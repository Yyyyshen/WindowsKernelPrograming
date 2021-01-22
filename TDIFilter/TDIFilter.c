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
  * 可将这个例子编译为静态库，留出一些必要回调接口，之后就可以在这个库基础上进行TDI防火墙开发了
  * 具体使用可以去找下《Windows内核编程》随书源码tdifw_smpl
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
	IRP_INTERNAL_CONTROL,
	IRP_CLEANUP,
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
//在连接进入事件中设置自定义回调回调函数
typedef struct {
	PFILE_OBJECT fileobj;
	PVOID old_handler;
	PVOID old_context; //就是回调函数的第一个参数
}TDI_EVENT_CONTEXT; //自定义上下文信息结构
NTSTATUS my_handler(PVOID TdiEventContext, LONG RemoteAddressLength, PVOID RemoteAddress, LONG UserDataLength, PVOID UserData,
	LONG OptionsLength, PVOID Options, CONNECTION_CONTEXT* ConnectionContext, PIRP* AcceptIrp)
{
	NTSTATUS status = STATUS_SUCCESS;
	//执行自己逻辑

	//调用原来的回调函数
	TDI_EVENT_CONTEXT* ctx = (TDI_EVENT_CONTEXT*)TdiEventContext;
	status = ((PTDI_IND_CONNECT)(ctx->old_handler))(ctx->old_context, //转为原函数指针后调用
		RemoteAddressLength, RemoteAddress, UserDataLength, UserData, OptionsLength, Options, ConnectionContext, AcceptIrp);
	return status;//若返回STATUS_CONNECTION_REFUSED，请求将不能建立
}
//进一步处理逻辑/次功能号，之后完成本次请求
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
			//内核中netbt设备发送TCP数据时，无法被TDI过滤驱动捕获TDI_SEND请求
			//netbt时基于TCP/IP的NetBIOS协议，用于计算机名字解析
			//netbt能直接获取TCP协议驱动中内部函数TCPSendData指针，用这个函数直接发送数据，就绕过了TDI_SEND
			//通过对tcpip.sys的研究，有一个功能号为IOCTL_TDI_QUERY_DIRECT_SEND_HANDLER
			BOOLEAN bRet = irps->Parameters.DeviceIoControl.IoControlCode == IOCTL_TDI_QUERY_DIRECT_SEND_HANDLER;
			//如果发送这个请求，tcpip.sys将把TCPSendData函数指针返回，可以用其发送数据
			//所以只要对此特殊处理，将返回的TCPSendData函数保存，取代为自己的过滤函数即可
			if (bRet)
			{
				VOID* buff = irps->Parameters.DeviceIoControl.Type3InputBuffer;
				if (buff != NULL)
				{
					//old_TCPSendData = *(TCPSendData_t**)buff;
					//*(TCPSendData_t**)buff = my_TCPSendData;
				}
			}
		}
		else if (irp_type == IRP_INTERNAL_CONTROL)
		{
			//处理各次功能号的请求

			if (irps->MinorFunction == TDI_ASSOCIATE_ADDRESS)
			{
				//TDI_ASSOCIATE_ADDRESS，用于把传输层对象和连接对象联系起来
				//在这样的请求中，IRP当前栈空间的FileObjcet域中保存的文件对象指针时连接终端的文件对象
				//我们之前保存过连接上下文指针，以文件对象指针为索引可以取到
				//把两组信息联系起来之后，当我们得到一个连接上下文对象时，就能知道所使用的本地地址
				//与之对应的，TDI_DISASSOCIATE_ADDRESS，删除地址的文件对象与连接上下文之间的关系
			}

			if (irps->MinorFunction == TDI_CONNECT)
			{
				//TDI_CONNECT
				//这个请求发生在本地试图连接外界时，当这个请求完成时，连接就已经建立了，这里也是监控网络安全很重要的地方
				//可在此处控制：进程使用本地什么地址、进程试图连接什么远程地址、是否允许访问发生、是否记录日志等

				//获取远程地址
				PTDI_REQUEST_KERNEL_CONNECT param = (PTDI_REQUEST_KERNEL_CONNECT)(&irps->Parameters);
				TA_ADDRESS* remote_addr = ((TRANSPORT_ADDRESS*)(param->RequestConnectionInformation->RemoteAddress))->Address;

				//根据得到的信息做相应处理
			}

			//还有一些功能号：TDI_SEND、TDI_RECEIVE、TDI_SEND_DATAGRAM、TDI_RECEIVE_DATAGRAM 处理传输过程
			//两种传输方式：流式传输（对应前两个功能号）和报式传输
			//流式传输不关心每次传输多少，只关心连接上发送的总大小，先发送的永远先到（TCP
			//报式传输没有连接，一次发送一个数据包，后发送的包不一定在先发送的包之后被接收（UDP
			//可以在传输过程做过滤处理：检查数据、检测病毒、加密数据、修改数据、拒绝发送、备份数据
			if (irps->MinorFunction == TDI_SEND)
			{
				//获取文件对象
				PFILE_OBJECT fileObj = irps->FileObject;
				//find方法获取之前保存的连接对象

				//获取数据，读取MDL中数据即可
				VOID* buff = MmGetSystemAddressForMdl(irp->MdlAddress);//获取实际缓冲区位置
				ULONG len = irp->IoStatus.Information;//获取长度

				//禁止发送或接收，把这个请求返回错误即可
			}

			//TDI_SET_EVENT_HANDLER
			//socket调用listen时，一个类型为TDI_EVENT_CONNECT设置事件请求将发送到下层协议，下层协议得到一个回调函数指针
			//TDI_SET_EVENT_HANDLER是一个设置事件回调的请求
			if (irps->MinorFunction == TDI_SET_EVENT_HANDLER)
			{
				//事件种类很多，先要获取类型
				PTDI_REQUEST_KERNEL_SET_EVENT r = (PTDI_REQUEST_KERNEL_SET_EVENT)&irps->Parameters;
				LONG type = r->EventType;//事件类型
				r->EventHandler;//回调函数，根据事件类型不同，回调函数也不同
				//前面提过TDI_CONNECT过滤只能针对本地连外部
				//对于外部连接本地，则通过TDI_EVENT_CONNECT类型事件，设置回调函数，我们可以用自己的回调函数取代它，并保存原回调函数指针
				//执行完自己的回调，再调用原本的函数，实现侦听
				if (type == TDI_EVENT_CONNECT && r->EventHandler != NULL)
				{
					TDI_EVENT_CONTEXT* ctx;//自定义上下文结构存储原来回调函数信息
					ctx->fileobj = irps->FileObject;
					ctx->old_handler = r->EventHandler;
					ctx->old_context = r->EventContext;
					//替换为自己的
					r->EventHandler = my_handler;
					r->EventContext = ctx;
				}
			}

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
			//这种请求与IRP_MJ_INTERNAL_DEVICE_CONTROL基本重复（除了netbt发送数据问题）
			status = TdiMapUserRequest(DeviceObject, irp, irps);//可以调用该函数将IRP_MJ_DEVICE_CONTROL转换为IRP_MJ_INTERNAL_DEVICE_CONTROL

			status = tdi_dispatch_complete(DeviceObject, irp, FILTER_ALLOW, completion.routine, completion.context, IRP_CONTROL);

			//break; //这里可以不break，直接作为内部控制请求继续处理
		case IRP_MJ_INTERNAL_DEVICE_CONTROL: //内部设备控制
			//上下两种功能号在TDI中功能基本相同
			status = tdi_dispatch_complete(DeviceObject, irp, FILTER_ALLOW, completion.routine, completion.context, IRP_INTERNAL_CONTROL);
			break;
		case IRP_MJ_CLEANUP://清理
			//此处一般用于删除保存的连接和地址信息
			//收到清理请求意为着一个文件对象的句柄降到0，但并不意味着文件对象的引用计数一定降为0，因为引用计数不止是打开句柄时增加
			//当引用计数减少为0时，文件对象会销毁，此时才会收到CLOSE请求
			status = tdi_dispatch_complete(DeviceObject, irp, FILTER_ALLOW, completion.routine, completion.context, IRP_CLEANUP);
			break;
		case IRP_MJ_CLOSE: //关闭
			status = tdi_dispatch_complete(DeviceObject, irp, FILTER_ALLOW, completion.routine, completion.context, IRP_CLOSE);
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