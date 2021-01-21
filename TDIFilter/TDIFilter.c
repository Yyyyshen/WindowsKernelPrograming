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

//分发函数
NTSTATUS DeviceDispatch(PDEVICE_OBJECT DeviceObject, PIRP irp)
{
	NTSTATUS status;
	PDEVICE_OBJECT old_devobj = get_original_devobj(DeviceObject, NULL);
	if (old_devobj != NULL)
	{
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