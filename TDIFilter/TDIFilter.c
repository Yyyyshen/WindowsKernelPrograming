#include <ntddk.h>
#include <tdikrnl.h>

//TODO 近期有需求，先略过键盘、磁盘、文件过滤，主要看下网络过滤
/**
 * 网络过滤
 * TDI即将淘汰，被WFP取代
 * 但最好还是都学习一下，技术原理还是有参考价值的，还有一些兼容性问题，可能会用到TDI
 * 从测试上看，TDI支持到Win7，这之后（包括Win7）的版本都应该用WFP
 */

 /**
  * 应用层使用socket进行网络操作，Windows中实现TCP协议的驱动为tcpip.sys，是一个NDIS协议驱动
  * 而TDI接口就是连接着socket和协议驱动的中间层
  * 协议驱动生成了一个有名字的设备，能接收一组请求：生成、控制（包括bind、connect、listen、accept、send、recv等）
  * 根据绑定设备原理，我们可以生成一个过滤设备绑定协议驱动的设备，这样请求就会先被过滤设备截获
  *
  * PS: TDIFW——一个开源的TDI防火墙
  * https://sourceforge.net/projects/tdifw/files/latest/download
  */

  /**
   * TDI框架
   * 常用协议的TDI设备名
   * "\Device\Tcp"  "\Device\Udp"  "\Device\RawIp"(原始IP包)
   *
   * 官方文档介绍：
   * https://docs.microsoft.com/en-us/previous-versions/windows/hardware/network/ff565094(v=vs.85)
   */

   //创建及绑定设备
NTSTATUS
c_n_a_device(PDRIVER_OBJECT DriverObject, PDEVICE_OBJECT* fltobj, PDEVICE_OBJECT* oldobj, wchar_t* devname)
{
	NTSTATUS status;
	UNICODE_STRING str;

	//创建过滤设备
	status = IoCreateDevice(DriverObject,
		0,
		NULL,
		FILE_DEVICE_UNKNOWN,
		0,
		TRUE,
		fltobj);
	if (status != STATUS_SUCCESS) {
		KdPrint(("[tdi_fw] c_n_a_device: IoCreateDevice(%S): 0x%x\n", devname, status));
		return status;
	}

	(*fltobj)->Flags |= DO_DIRECT_IO;//设置IO方式

	RtlInitUnicodeString(&str, devname);
	//绑定设备
	status = IoAttachDevice(*fltobj, &str, oldobj);
	if (status != STATUS_SUCCESS) {
		KdPrint(("[tdi_fw] DriverEntry: IoAttachDevice(%S): 0x%x\n", devname, status));
		return status;
	}

	KdPrint(("[tdi_fw] DriverEntry: %S fileobj: %p\n", devname, *fltobj));

	return STATUS_SUCCESS;
}

//资源操作
#include "memtrack.h"

//ip端口转换
#include "sock.h"

//协议号
#define IPPROTO_IP              0
#define IPPROTO_ICMP            1
#define IPPROTO_TCP             6
#define IPPROTO_UDP             17

//保存过滤设备和真实设备为全局变量
PDEVICE_OBJECT
g_tcpfltobj = NULL,//保存tcp过滤设备对象指针，以下根据命名类推
g_udpfltobj = NULL,
g_ipfltobj = NULL,
g_tcpoldobj = NULL,
g_udpoldobj = NULL,
g_ipoldobj = NULL;

//各设备名
#define DEVICE_NAME_TCP L"\\Device\\Tcp"
#define DEVICE_NAME_UDP L"\\Device\\Udp"
#define DEVICE_NAME_IP L"\\Device\\RawIp"

//过滤结果类型
enum {
	FILTER_ALLOW = 1,
	FILTER_DENY,
	FILTER_PACKET_LOG,
	FILTER_PACKET_BAD,
	FILTER_DISCONNECT
};

//对应子功能号中各过程
enum {
	IRP_CREATE = 1,
	IRP_CONTROL,
	IRP_CLOSE
};

//保存文件对象的对应关系，阉割了部分代码，完整的见TDIFW项目
#include "obj_tbl.h"

//根据过滤设备对象获取真实设备对象
PDEVICE_OBJECT get_original_devobj(PDEVICE_OBJECT flt_devobj, int* proto)
{
	PDEVICE_OBJECT result;
	int ipproto;

	//根据保存的全局变量一一对应的返回
	if (flt_devobj == g_tcpfltobj)
	{
		result = g_tcpoldobj;
		ipproto = IPPROTO_TCP;
	}
	else if (flt_devobj == g_udpfltobj) {
		result = g_udpoldobj;
		ipproto = IPPROTO_UDP;
	}
	else if (flt_devobj == g_ipfltobj) {
		result = g_ipoldobj;
		ipproto = IPPROTO_IP;
	}
	else
	{
		KdPrint(("[tdi_fw] get_original_devobj: Unknown DeviceObject %p\n", flt_devobj));
		ipproto = IPPROTO_IP;
		result = NULL;
	}

	if (result != NULL && proto != NULL)
	{
		*proto = ipproto;
	}

	return result;
}

//卸载函数
VOID OnUnload(PDRIVER_OBJECT DriverObject)
{
	//解绑及删除保存的设备
	if (g_tcpoldobj != NULL) IoDetachDevice(g_tcpoldobj);
	if (g_tcpfltobj != NULL) IoDeleteDevice(g_tcpfltobj);
	if (g_udpoldobj != NULL) IoDetachDevice(g_udpoldobj);
	if (g_udpfltobj != NULL) IoDeleteDevice(g_udpfltobj);
	if (g_ipoldobj != NULL) IoDetachDevice(g_ipoldobj);
	if (g_ipfltobj != NULL) IoDeleteDevice(g_ipfltobj);
}

//处理生成请求
struct _completion {
	PIO_COMPLETION_ROUTINE	routine;
	PVOID					context;
};
typedef struct {
	TDI_ADDRESS_INFO* tai;
	PFILE_OBJECT		fileobj;
} TDI_CREATE_ADDROBJ2_CTX;
#define TDI_ADDRESS_MAX_LENGTH	TDI_ADDRESS_LENGTH_OSI_TSAP
#define TA_ADDRESS_MAX			(sizeof(TA_ADDRESS) - 1 + TDI_ADDRESS_MAX_LENGTH)
#define TDI_ADDRESS_INFO_MAX	(sizeof(TDI_ADDRESS_INFO) - 1 + TDI_ADDRESS_MAX_LENGTH)
NTSTATUS tdi_create_addrobj_complete2(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp, IN PVOID Context)
{
	//查询请求的完成函数
	NTSTATUS status = STATUS_SUCCESS;
	if (Irp->MdlAddress)
	{
		//得到mdl所指地址
		TDI_ADDRESS_INFO* tai = (TDI_ADDRESS_INFO*)MmGetSystemAddressForMdl(Irp->MdlAddress);
		//得到一个地址结构
		TA_ADDRESS* addr = tai->Address.Address;
		//打印信息
		KdPrint(("[tdi_fw] tdi_create_addrobj_complete2: Address: %x:%u\n",
			ntohl(((TDI_ADDRESS_IP*)(addr->Address))->in_addr),
			ntohs(((TDI_ADDRESS_IP*)(addr->Address))->sin_port)));
	}
	return status;
}
NTSTATUS tdi_create_addrobj_complete(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp, IN PVOID Context)
{
	//生成请求的完成函数
	NTSTATUS status = STATUS_SUCCESS;
	PIO_STACK_LOCATION irps = IoGetCurrentIrpStackLocation(Irp);
	PIRP query_irp = (PIRP)Context;
	PDEVICE_OBJECT devobj;
	devobj = get_original_devobj(DeviceObject, NULL);
	TDI_CREATE_ADDROBJ2_CTX* ctx = NULL;
	PMDL mdl = NULL;

	if (Irp->IoStatus.Status != STATUS_SUCCESS) {
		KdPrint(("[tdi_fw] tdi_create_addrobj_complete: status 0x%x\n", Irp->IoStatus.Status));
		status = Irp->IoStatus.Status;
		return status;
	}
	//分配上下文内存
	ctx = (TDI_CREATE_ADDROBJ2_CTX*)malloc_np(sizeof(TDI_CREATE_ADDROBJ2_CTX));
	if (ctx == NULL) {
		KdPrint(("[tdi_fw] tdi_create_addrobj_complete: malloc_np\n"));
		status = STATUS_INSUFFICIENT_RESOURCES;
		return status;
	}
	ctx->fileobj = irps->FileObject;

	ctx->tai = (TDI_ADDRESS_INFO*)malloc_np(TDI_ADDRESS_INFO_MAX);
	if (ctx->tai == NULL) {
		KdPrint(("[tdi_fw] tdi_create_addrobj_complete: malloc_np!\n"));
		status = STATUS_INSUFFICIENT_RESOURCES;
		return status;
	}
	//用IoAllocateMdl 函数实现大缓存分片的目的，通过一个独立的MDL来映射缓存的一小部分，或者映射驱动分配的内存
	//调用MmBuildMdlForNonPagedPool来设置MDL的内存，使得MDL描述驱动分配的缓存处于不可置换的内存中
	mdl = IoAllocateMdl(ctx->tai, TDI_ADDRESS_INFO_MAX, FALSE, FALSE, NULL);
	if (mdl == NULL) {
		KdPrint(("[tdi_fw] tdi_create_addrobj_complete: IoAllocateMdl!\n"));
		status = STATUS_INSUFFICIENT_RESOURCES;
		return status;
	}
	MmBuildMdlForNonPagedPool(mdl);

	//生成请求完成后，创建查询请求，之后再注册一个查询请求的完成函数tdi_create_addrobj_complete2
	//mdl是用户态和内核态共享的一块内存，就是通过MDL进行内存的重映射。将同一块物理内存同时映射到用户态空间和核心态空间
	TdiBuildQueryInformation(query_irp, devobj, irps->FileObject, tdi_create_addrobj_complete2, ctx, TDI_QUERY_ADDRESS_INFO, mdl);
	//发出查询请求
	status = IoCallDriver(devobj, query_irp);
	query_irp = NULL;
	mdl = NULL;
	ctx = NULL;

	if (status != STATUS_SUCCESS) {
		KdPrint(("[tdi_fw] tdi_create_addrobj_complete: IoCallDriver: 0x%x\n", status));
		return status;
	}

	//清理资源
	if (mdl != NULL)
		IoFreeMdl(mdl);
	if (ctx != NULL) {
		if (ctx->tai != NULL)
			free(ctx->tai);
		free(ctx);
	}

	if (query_irp != NULL)
		IoCompleteRequest(query_irp, IO_NO_INCREMENT);
	Irp->IoStatus.Status = status;

	return status;
}
int deal_tdi_create(PIRP irp, PIO_STACK_LOCATION irps, struct _completion* completion, PDEVICE_OBJECT devobj, int ipproto)
{
	NTSTATUS status;
	//可在此处获取当前进程
	ULONG pid = (ULONG)PsGetCurrentProcessId();
	//请求一般由ZwCreateFile调用引发，函数中EaBuffer指针存放了EA数据，可以在这个过程获取
	FILE_FULL_EA_INFORMATION* ea = (FILE_FULL_EA_INFORMATION*)irp->AssociatedIrp.SystemBuffer;
	//TDI具体操作指令存在于ea->EaName中
	//预定义结果：TdiTransportAddress 表示目前生成的时一个传输层地址（一般就是IP）
	//TdiConnectionContext 表示目前生成一个连接终端
	//二者都有一个对应的文件对象
	//TDI建立连接的方式：过程总是先生成一个传输层地址，再生成一个连接终端，接着用一个控制请求将二者联系起来
	if (ea != NULL)
	{
		if (ea->EaNameLength == TDI_TRANSPORT_ADDRESS_LENGTH && memcmp(ea->EaName, TdiTransportAddress, TDI_TRANSPORT_ADDRESS_LENGTH) == 0)
		{
			//这里捕获传输层地址生成
			//只有这个请求被发送到下层完成后，才能发送查询请求询问IP和端口
			//询问被打开文件对象来获得IP和端口，询问需要构建一个请求
			PIRP query_irp;
			query_irp = TdiBuildInternalDeviceControlIrp(TDI_QUERY_INFORMATION, devobj, irps->FileObject, NULL, NULL);
			//请求完成函数一般在DISPATCH中断级调用，而只有PASSIVE中断级才能调用TdiBuildInternalDeviceControlIrp，而分发函数一般就在PASSIVE中断级，满足条件
			if (query_irp == NULL)
			{
				return FILTER_DENY;
			}
			//设置完成函数，生成请求一完成，就调用这个函数，可以在其中访问IP和端口，此函数在后面被设置为IRP完成函数
			completion->routine = tdi_create_addrobj_complete;
			//记录已分配请求，方便使用
			completion->context = query_irp;

			//文件对象与生成地址也应该对应的保存下来
			status = ot_add_fileobj(irps->DeviceObject, irps->FileObject, FILEOBJ_ADDROBJ, ipproto, NULL);
			if (status != STATUS_SUCCESS) {
				KdPrint(("[tdi_fw] tdi_create: ot_add_fileobj: FILEOBJ_ADDROBJ 0x%x\n", status));
				return FILTER_DENY;
			}
		}
		else if (ea->EaNameLength == TDI_CONNECTION_CONTEXT_LENGTH && memcmp(ea->EaName, TdiConnectionContext, TDI_CONNECTION_CONTEXT_LENGTH) == 0)
		{
			//捕获连接终端生成
			CONNECTION_CONTEXT conn_ctx = *(CONNECTION_CONTEXT*)(ea->EaName + ea->EaNameLength + 1);//计算地址转换为指针再取值
			//一个终端生成后，一个文件对象生成

			//这之后所有截获到的DeviceIoControl截获到的都只是文件对象，所以应该在内存中维护一个哈希表把文件对象和连接上下文对应起来
			status = ot_add_fileobj(irps->DeviceObject, irps->FileObject, FILEOBJ_CONNOBJ, ipproto, conn_ctx);
			if (status != STATUS_SUCCESS) {
				KdPrint(("[tdi_fw] tdi_create: ot_add_fileobj: FILEOBJ_CONNOBJ 0x%x\n", status));
				return FILTER_DENY;
			}
		}
	}

	return FILTER_ALLOW;
}
//完成请求
NTSTATUS
tdi_dispatch_complete(PDEVICE_OBJECT devobj, PIRP irp, int filter, PIO_COMPLETION_ROUTINE cr, PVOID context, int irp_type)
{
	PIO_STACK_LOCATION irps = IoGetCurrentIrpStackLocation(irp);
	NTSTATUS status = STATUS_SUCCESS;

	if (filter == FILTER_DENY) {
		//前面发生错误或不符合条件
		KdPrint(("[tdi_fw] tdi_dispatch_complete: [DROP!]"
			" major 0x%x, minor 0x%x for devobj %p; fileobj %p\n",
			irps->MajorFunction,
			irps->MinorFunction,
			devobj,
			irps->FileObject));

		if (irp->IoStatus.Status == STATUS_SUCCESS) {
			status = irp->IoStatus.Status = STATUS_ACCESS_DENIED;
		}
		else {
			status = irp->IoStatus.Status;
		}

		IoCompleteRequest(irp, IO_NO_INCREMENT);
	}
	else if (filter == FILTER_ALLOW) {

		//各流程过滤操作
		if (irp_type == IRP_CREATE)
		{
			//设置请求完成后的事务，类似于注册回调函数
			IoSetCompletionRoutine(irp, cr, context, NULL, NULL, NULL);
		}
		else if (irp_type == IRP_CONTROL)
		{
		}
		else if (irp_type == IRP_CLOSE)
		{
		}

	}
	else {
		//未知结果
		status = irp->IoStatus.Status = STATUS_SUCCESS;
		IoCompleteRequest(irp, IO_NO_INCREMENT);
	}

	return status;
}
//分发函数
NTSTATUS DeviceDispatch(PDEVICE_OBJECT DeviceObject, PIRP irp)
{
	NTSTATUS status;
	int ipproto;
	PDEVICE_OBJECT old_devobj = get_original_devobj(DeviceObject, &ipproto);
	if (old_devobj != NULL)
	{
		//获取当前栈空间
		PIO_STACK_LOCATION irps;
		irps = IoGetCurrentIrpStackLocation(irp);
		//用一个结构体存放生成请求中的信息
		struct _completion completion = { 0 };
		int result = 0;
		//解析功能号
		switch (irps->MajorFunction)
		{
		case IRP_MJ_CREATE: //生成请求
		{
			//处理生成请求
			result = deal_tdi_create(irp, irps, &completion, old_devobj, ipproto);
			//请求将在下面函数完成，完成后completion.routine记录的完成函数被调用
			status = tdi_dispatch_complete(DeviceObject, irp, result, completion.routine, completion.context, IRP_CREATE);
			break;
		}
		case IRP_MJ_DEVICE_CONTROL: //设备控制
			status = tdi_dispatch_complete(DeviceObject, irp, result, completion.routine, completion.context, IRP_CONTROL);
			break;
		case IRP_MJ_INTERNAL_DEVICE_CONTROL: //内部设备控制
			break;
		case IRP_MJ_CLOSE: //关闭
			status = tdi_dispatch_complete(DeviceObject, irp, result, completion.routine, completion.context, IRP_CLOSE);
			break;
		case IRP_MJ_CLEANUP:
			break;
		default:
			break;
		}

		//转发到原设备
		IoSkipCurrentIrpStackLocation(irp);
		status = IoCallDriver(old_devobj, irp);
	}
	else
	{
		//找不到对应设备，返回失败
		status = irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
		IoCompleteRequest(irp, IO_NO_INCREMENT);
	}
	return status;
}
//驱动入口
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	NTSTATUS status = STATUS_SUCCESS;

	//设置分发函数
	for (int i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
	{
		DriverObject->MajorFunction[i] = DeviceDispatch;
	}

	//生成过滤设备并绑定
	status = c_n_a_device(DriverObject, &g_tcpfltobj, &g_tcpoldobj, DEVICE_NAME_TCP);
	if (status != STATUS_SUCCESS)
	{
		KdPrint(("[tdi_fw] DriverEntry: c_n_a_device: tcp: 0x%x\n", status));
		goto done;
	}
	status = c_n_a_device(DriverObject, &g_udpfltobj, &g_udpoldobj, DEVICE_NAME_UDP);
	if (status != STATUS_SUCCESS)
	{
		KdPrint(("[tdi_fw] DriverEntry: c_n_a_device: udp: 0x%x\n", status));
		goto done;
	}
	status = c_n_a_device(DriverObject, &g_ipfltobj, &g_ipoldobj, DEVICE_NAME_IP);
	if (status != STATUS_SUCCESS)
	{
		KdPrint(("[tdi_fw] DriverEntry: c_n_a_device: ip: 0x%x\n", status));
		goto done;
	}

done:
	if (status != STATUS_SUCCESS)
	{
		//失败则释放资源
		OnUnload(DriverObject);
	}
	return status;
}