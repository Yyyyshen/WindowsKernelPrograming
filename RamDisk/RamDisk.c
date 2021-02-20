#include <ntddk.h>
#include <wdf.h> //需要配置包含目录及附加依赖项；或者新建项目时使用KMDF项目框架

/**
 * 磁盘虚拟技术
 *
 * 使用非分页内存做的磁盘存储空间，并将其以一个独立磁盘形式暴露给用户
 *
 * 使用了WDF，是对WDM的封装
 * 例如对电源管理和即插即用这样的常用、复杂的处理代码进行封装，可以更方便的进行开发
 */

NTSTATUS
RamDiskEvtDeviceAdd(
	IN WDFDRIVER Driver,
	IN PWDFDEVICE_INIT DeviceInit
)
{
	//该回调函数是用来在即插即用管理器发现新设备时对这个设备及逆行初始化操作的
	//任何支持PnP操作的驱动都应该有这样的函数（就是WDM驱动中AddDevice回调的翻版）
	//当DriverEntry执行完毕后，驱动基本就只依靠这个函数来与系统保持联系了
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObject, IN PUNICODE_STRING pRegistryPath)
{
	//驱动程序的可配置项，一般包括EvtDriverDeviceAdd和EvtDriverUnload回调函数的入口地址、驱动初始化时的标志和分配内存是使用的tag值
	WDF_DRIVER_CONFIG config;

	KdPrint(("Windows Ramdisk Driver - Driver Framework Edition.\n"));
	KdPrint(("Built %s %s\n", __DATE__, __TIME__));

	//初始化配置时，会将用户自定义的EvtDriverDeviceAdd回调函数存入其中，并初始化其他部分
	WDF_DRIVER_CONFIG_INIT(&config, RamDiskEvtDeviceAdd);

	//对原本驱动开发的一次包装，根据参数对环境进行初始化工作，并建立驱动对象
	return WdfDriverCreate(
		pDriverObject,	//入口函数的两个参数
		pRegistryPath,
		WDF_NO_OBJECT_ATTRIBUTES, //表示不需要特殊属性
		&config,
		WDF_NO_HANDLE	//作为函数的输出结果，即WDF驱动的驱动对象
	);//至此将config与驱动挂钩，运行过程中，PnP管理器就会根据需要调用回调函数
}