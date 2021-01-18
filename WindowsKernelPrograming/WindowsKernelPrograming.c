#include "ntddk.h"
#include "ntstrsafe.h"

/**
 * 《Windows内核编程》
 * 看目录的话，跟《Windows黑客编程技术详解》大部分内容重叠
 * 过一遍看看还有什么不同，另外也巩固一下之前的学习
 * 
 * PS:使用了下VS自带的git管理器连接远程库，直接生成的.gitignore非常方便，直接把该忽略的都写好了
 */

/**
 * 与黑客技术介绍的各技术的直接应用不同
 * 书的开头介绍了很多驱动层开发更基本的知识
 */

/**
 * CPU运行环概念:
 * x86计算机中，CPU有四个特权级别 ring0（特权最大）~ring3
 * 大多数内核都只使用0和3两个级别
 * 内核应用运行于ring0，用户应用运行于ring3
 */

/**
 * IRQL中断级别：
 * 高IRQL代码可以中断低IRQL代码执行过程
 * 驱动中常见级别为0~2
 */

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
	if (DriverObject != NULL)
	{
		DbgPrint("[%ws]Driver Upload,Driver Object Address:%p", __FUNCTIONW__, DriverObject);
	}
	//KeBugCheckEx(0x0, 0x0, 0x0, 0x0, 0x0); // 主动蓝屏
	return;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	//获取当前驱动所在的进程ID和IRQL级别，此处应该两个值都为0
	DbgPrint("[%ws]Hello Kernel World, CurrentProcessId = 0x%p , CurrentIRQL = 0x%u\n", __FUNCTIONW__, PsGetCurrentProcessId(), KeGetCurrentIrql());
	if (RegistryPath != NULL)
	{
		DbgPrint("[%ws]Driver RegistryPath:%wZ\n", __FUNCTIONW__, RegistryPath);
	}

	if (DriverObject != NULL)
	{
		DbgPrint("[%ws]Driver Object Address:%p\n", __FUNCTIONW__, DriverObject);
		DriverObject->DriverUnload = DriverUnload;
	}

	//内核层编程中，大部分情况使用Unicode
	WCHAR strBuf[128] = { 0 };
	//一般不直接使用WCHAR，而是UNICODE_STRING，结构体内buffer指针所指缓冲区结尾不一定包含'\0'
	//不依赖结束标志更为安全，可以有效防止缓冲区溢出覆盖掉\0导致的违法访问
	UNICODE_STRING uFirstString = { 0 };
	RtlInitEmptyUnicodeString(&uFirstString, strBuf, sizeof(strBuf));
	RtlUnicodeStringCopyString(&uFirstString, L"Hello,Kernel\n"); //只能在PASSIVE_LEVEL下使用
	DbgPrint("String:%wZ", &uFirstString);

	return STATUS_SUCCESS;
}