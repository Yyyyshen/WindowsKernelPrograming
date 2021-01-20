#include <ntddk.h>

/**
 * 过滤技术
 * 系统有很多过滤机制，包括键盘过滤、磁盘过滤、文件过滤、网络过滤等
 */

 /**
  * 先用一个串口过滤例子学习过滤驱动最基本的要素
  * 过滤最主要的方法是通过编程生成一个虚拟设备对象，并绑定到一个真实设备上
  * 绑定后，系统发送给真实设备的请求就会先从这个虚拟设备上走一遍
  * 使用IoAttachDevice绑定的设备对象需要有名字
  * 如果一个名字对应的设备被绑定了，那么他们在一起的一组设备被成为设备栈
  * IoAttachDevice总是会绑定设备栈上最顶层的那个设备
  * 还有一个API可以根据设备对象指针绑定：IoAttachDeviceToDeviceStack(Safe)
  */
VOID Test_Filter()
{
	//生成过滤设备并绑定
	//绑定设备前，应把设备对象多个子域设置成与目标对象一致
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	return STATUS_SUCCESS;
}