#include <ntddk.h>

/**
 * WFP（Windows Filter Platform，Windows过滤平台）
 * 微软希望用WFP来代替之前的Winsock LSP、TDI以及NDIS等网络过滤驱动
 * 开发者可以在WFP划分的不同分层进行过滤、重定向、修改等
 * WFP本身包含用户态API和内核态API，在用户层也可以处理网络数据包，主要学习下内核层使用
 */

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	return STATUS_SUCCESS;
}