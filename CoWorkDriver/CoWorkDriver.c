#include "ntddk.h"

/**
 * 应用层与内核层通信
 * 与用户层应用加载DLL模块调用导出函数不同
 * 想要与内核驱动通信，需要以设备对象为介质
 * 设备对象可以在内核中暴露给应用层，让应用层像操作文件一样操作它
 */

#define DEV_NAME L"\\Device\\CO_WORK_DRIVER"
#define SYM_NAME L"\\??\\MY_CO_WORK_DRIVER"
#define SDDL_SYM L"D:P(A;;GA;;;WD)" //安全描述符，D:P开头接多个类似括号中的符号，本例为允许任何用户访问该设备的安全字符串，方便测试


 // 从应用层给驱动发送一个字符串。
#define  CWK_DVC_SEND_STR \
	(ULONG)CTL_CODE( \
	FILE_DEVICE_UNKNOWN, \
	0x911,METHOD_BUFFERED, \
	FILE_WRITE_DATA)

// 从驱动读取一个字符串
#define  CWK_DVC_RECV_STR \
	(ULONG)CTL_CODE( \
	FILE_DEVICE_UNKNOWN, \
	0x912,METHOD_BUFFERED, \
	FILE_READ_DATA)

// 定义一个链表用来保存字符串
#define CWK_STR_LEN_MAX 512
typedef struct {
	LIST_ENTRY list_entry;
	char buf[CWK_STR_LEN_MAX];
} CWK_STR_NODE, * PCWK_STR_NODE;

// 还必须有一把自旋锁来保证链表操作的安全性
KSPIN_LOCK g_cwk_lock;
// 一个事件来标识是否有字符串可以取
KEVENT  g_cwk_event;
// 必须有个链表头
LIST_ENTRY g_cwk_str_list;

#define MEM_TAG 'cwkr'

// 分配内存并初始化一个链表节点
PCWK_STR_NODE cwkMallocStrNode()
{
	PCWK_STR_NODE ret = ExAllocatePoolWithTag(
		NonPagedPool, sizeof(CWK_STR_NODE), MEM_TAG);
	if (ret == NULL)
		return NULL;
	return ret;
}

NTSTATUS CoWorkDispatch(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	DbgPrint("Enter CoWorkDispatch\n");
	NTSTATUS status = STATUS_SUCCESS;
	//获取irp所在栈
	PIO_STACK_LOCATION  irpsp = IoGetCurrentIrpStackLocation(pIrp);
	ULONG ret_len = 0;

	while (pDevObj)
	{
		if (irpsp->MajorFunction == IRP_MJ_CREATE || irpsp->MajorFunction == IRP_MJ_CLOSE)
		{
			// 生成和关闭请求，这个一律简单地返回成功就可以
			// 了。就是无论何时打开和关闭都可以成功。
			break;
		}

		if (irpsp->MajorFunction == IRP_MJ_DEVICE_CONTROL)
		{
			// 处理DeviceIoControl。
			PVOID buffer = pIrp->AssociatedIrp.SystemBuffer;//获取缓冲区
			ULONG inlen = irpsp->Parameters.DeviceIoControl.InputBufferLength;//输入缓冲区长度
			ULONG outlen = irpsp->Parameters.DeviceIoControl.OutputBufferLength;//输出缓冲区长度
			ULONG len;
			PCWK_STR_NODE str_node;
			switch (irpsp->Parameters.DeviceIoControl.IoControlCode)
			{
			case CWK_DVC_SEND_STR:
				ASSERT(buffer != NULL);
				ASSERT(outlen == 0);

				// 安全的编程态度之一:检查输入缓冲的长度对于长度超出预期的，果
				// 断返回错误。
				if (inlen > CWK_STR_LEN_MAX)
				{
					status = STATUS_INVALID_PARAMETER;
					break;
				}

				// 安全的编程态度之二：检查字符串的长度，不要使用strlen!如果使
				// 用strlen,一旦攻击者故意输入没有结束符的字符串，会导致内核驱
				// 动访问非法内存空间而崩溃。
				DbgPrint("strnlen = %llu\r\n", strnlen((char*)buffer, inlen));
				if (strnlen((char*)buffer, inlen) == inlen)
				{
					// 字符串占满了缓冲区，且中间没有结束符。立刻返回错误。
					status = STATUS_INVALID_PARAMETER;
					break;
				}

				// 现在可以认为输入缓冲是安全而且不含恶意的。分配节点。
				str_node = cwkMallocStrNode();
				if (str_node == NULL)
				{
					// 如果分配不到空间了，返回资源不足的错误
					status = STATUS_INSUFFICIENT_RESOURCES;
					break;
				}

				// 前面已经检查了缓冲区中的字符串的确长度合适而且含有结束符
				// ，所以这里用什么函数来拷贝字符串对安全性而言并不非常重要。
				strncpy(str_node->buf, (char*)buffer, CWK_STR_LEN_MAX);
				// 插入到链表末尾。用锁来保证安全性。
				ExInterlockedInsertTailList(&g_cwk_str_list, (PLIST_ENTRY)str_node, &g_cwk_lock);
				// InsertTailList(&g_cwk_str_list, (PLIST_ENTRY)str_node);
				// 打印
				DbgPrint((char*)buffer);
				// 那么现在就可以认为这个请求已经成功。因为刚刚已经插入了一
				// 个，那么可以设置事件来表明队列中已经有元素了。
				KeSetEvent(&g_cwk_event, 0, TRUE);
				break;
			case CWK_DVC_RECV_STR:
				ASSERT(buffer != NULL);
				ASSERT(inlen == 0);
				// 应用要求接收字符串。对此，安全上要求是输出缓冲要足够长。
				if (outlen < CWK_STR_LEN_MAX)
				{
					status = STATUS_INVALID_PARAMETER;
					break;
				}
				while (1)
				{
					// 插入到链表末尾。用锁来保证安全性。
					str_node = (CWK_STR_NODE*)ExInterlockedRemoveHeadList(&g_cwk_str_list, &g_cwk_lock);
					// str_node = RemoveHeadList(&g_cwk_str_list);
					if (str_node != NULL)
					{
						// 这种情况下，取得了字符串。那就拷贝到输出缓冲中。然后
						// 整个请求就返回了成功。
						strncpy((char*)buffer, str_node->buf, CWK_STR_LEN_MAX);
						ret_len = strnlen(str_node->buf, CWK_STR_LEN_MAX) + 1;
						ExFreePool(str_node);
						break;
					}
					else
					{
						// 对于合法的要求，在缓冲链表为空的情况下，等待事件进行
						// 阻塞。也就是说，如果缓冲区中没有字符串，就停下来等待
						// 。这样应用程序也会被阻塞住，DeviceIoControl是不会返回
						// 的。但是一旦有就会返回。等于驱动“主动”通知了应用。
						KeWaitForSingleObject(&g_cwk_event, Executive, KernelMode, 0, 0);
					}
				}
				break;
			default:
				// 到这里的请求都是不接受的请求。未知的请求一律返回非法参数错误。
				status = STATUS_INVALID_PARAMETER;
				break;
			}
		}
		break;
	}

	//分发中返回请求
	pIrp->IoStatus.Status = status;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	DbgPrint("Leave CoWorkDispatch\n");
}

VOID DriverUnload(PDRIVER_OBJECT pDriverObject)
{
	DbgPrint("Enter DriverUnload\n");
	//删除设备和符号
	UNICODE_STRING ustrSymName;
	RtlInitUnicodeString(&ustrSymName, SYM_NAME);
	IoDeleteSymbolicLink(&ustrSymName);
	if (pDriverObject->DeviceObject)
	{
		IoDeleteDevice(pDriverObject->DeviceObject);
	}
	// 释放分配过的所有内核内存。
	PCWK_STR_NODE str_node;
	while (TRUE)
	{
		str_node = ExInterlockedRemoveHeadList(
			&g_cwk_str_list, &g_cwk_lock);
		// str_node = RemoveHeadList(&g_cwk_str_list);
		if (str_node != NULL)
			ExFreePool(str_node);
		else
			break;
	};

	DbgPrint("Leave DriverUnload\n");
}

NTSTATUS CreateDevice(PDRIVER_OBJECT pDriverObject)
{
	NTSTATUS status = STATUS_SUCCESS;
	PDEVICE_OBJECT pDevObj = NULL;
	UNICODE_STRING ustrDevName, ustrSymName;

	RtlInitUnicodeString(&ustrDevName, DEV_NAME);
	RtlInitUnicodeString(&ustrSymName, SYM_NAME);
	status = IoCreateDevice(pDriverObject, 0, &ustrDevName, FILE_DEVICE_UNKNOWN, 0, FALSE, &pDevObj);
	if (!NT_SUCCESS(status))
	{
		return status;
	}
	status = IoCreateSymbolicLink(&ustrSymName, &ustrDevName);
	if (!NT_SUCCESS(status))
	{
		IoDeleteDevice(pDevObj);
		return status;
	}

	return status;
}

VOID Init()
{
	// 初始化事件、锁、链表头。
	KeInitializeEvent(&g_cwk_event, SynchronizationEvent, TRUE);
	KeInitializeSpinLock(&g_cwk_lock);
	InitializeListHead(&g_cwk_str_list);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING RegistryPath)
{
	DbgPrint("Enter DriverEntry\n");
	NTSTATUS status = STATUS_SUCCESS;

	pDriverObject->DriverUnload = DriverUnload;
	for (ULONG i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
	{
		//注册分发函数
		pDriverObject->MajorFunction[i] = CoWorkDispatch;
	}

	//初始化链表、锁等
	Init();
	//创建设备对象
	status = CreateDevice(pDriverObject);

	DbgPrint("Leave DriverEntry\n");
	return status;
}