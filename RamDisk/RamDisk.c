#include <ntddk.h>

/**
 * 磁盘虚拟技术
 * 
 * 使用非分页内存做的磁盘存储空间，并将其以一个独立磁盘形式暴露给用户
 */

NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObject, IN PUNICODE_STRING pRegistryPath)
{
	return STATUS_SUCCESS;
}