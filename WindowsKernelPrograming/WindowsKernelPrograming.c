#include "ntddk.h"
#include "ntstrsafe.h"

/**
 * 《Windows内核编程》
 * 看目录的话，跟《Windows黑客编程技术详解》大部分内容重叠
 * 过一遍看看还有什么不同，另外也巩固一下之前的学习
 * 
 * PS:使用了下VS自带的git管理器连接远程库，直接生成的.gitignore非常方便，直接把该忽略的都写好了
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

	WCHAR strBuf[128] = { 0 };

	UNICODE_STRING uFirstString = { 0 };
	RtlInitEmptyUnicodeString(&uFirstString, strBuf, sizeof(strBuf));
	RtlUnicodeStringCopyString(&uFirstString, L"Hello,Kernel\n"); //只能在PASSIVE_LEVEL下使用
	DbgPrint("String:%wZ", &uFirstString);

	return STATUS_SUCCESS;
}