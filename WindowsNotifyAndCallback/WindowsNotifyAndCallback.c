#include <ntddk.h>

/**
 * Windows通知及回调
 *
 * 系统内核提供了一系列事件通知机制以及回调机制
 * 事件通知主要用于监控系统内某一事件操作
 * 回调机制更多被用来反应系统内某一个部件状态，还可以被用来实现内核模块之间的通信
 *
 * 事件通知可以理解成开发者写的一些函数，通过内核API把函数和具体事件操作绑定（注册），当事件发生，这些函数就会被系统调用
 * 常见的有创建进程通知、创建线程通知、加载模块通知、注册表操作通知等
 */

 /*函数原型声明*/
void  DriverUnload(__in struct _DRIVER_OBJECT* DriverObject);

/**
 * 创建进程事件回调相关（其他的基本一样，文件放在项目里，没有引入）
 */
VOID CreateProcessNotifyEx(__inout PEPROCESS  Process,
	__in HANDLE  ProcessId,
	__in_opt PPS_CREATE_NOTIFY_INFO  CreateInfo);


typedef NTSTATUS(_stdcall* PPsSetCreateProcessNotifyRoutineEx)(
	IN PCREATE_PROCESS_NOTIFY_ROUTINE_EX  NotifyRoutine,
	IN BOOLEAN  Remove
	);

/*全局变量定义*/
PPsSetCreateProcessNotifyRoutineEx	g_pPsSetCreateProcessNotifyRoutineEx = NULL;
BOOLEAN g_bSuccRegister = FALSE;

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	NTSTATUS nStatus = STATUS_UNSUCCESSFUL;
	//_asm int 3;
	do
	{
		UNICODE_STRING uFuncName = { 0 };
		DriverObject->DriverUnload = DriverUnload;
		RtlInitUnicodeString(&uFuncName, L"PsSetCreateProcessNotifyRoutineEx");
		//动态获取函数地址
		g_pPsSetCreateProcessNotifyRoutineEx = (PPsSetCreateProcessNotifyRoutineEx)MmGetSystemRoutineAddress(&uFuncName);
		if (g_pPsSetCreateProcessNotifyRoutineEx == NULL)
		{
			break;
		}
		if (STATUS_SUCCESS != g_pPsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyEx, FALSE))
		{
			//可能返回STATUS_ACCESS_DENIED，时因为通知例程所在模块PE头没有被设置IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY标志
			//解决办法时加入衔接选项/inegritycheck
			break;
		}
		g_bSuccRegister = TRUE;
		nStatus = STATUS_SUCCESS;
	} while (FALSE);

	return nStatus;
	return STATUS_SUCCESS;
}

void  DriverUnload(__in struct _DRIVER_OBJECT* DriverObject)
{
	if (g_bSuccRegister && g_pPsSetCreateProcessNotifyRoutineEx)
	{
		//在不使用时，必须相应的移除通知
		g_pPsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyEx, TRUE);
		g_bSuccRegister = FALSE;
	}
	return;
}

VOID CreateProcessNotifyEx(
	__inout PEPROCESS  Process,
	__in HANDLE  ProcessId,
	__in_opt PPS_CREATE_NOTIFY_INFO  CreateInfo
)
{
	HANDLE hParentProcessID = NULL;/*父进程ID*/
	HANDLE hPareentThreadID = NULL;/*父进程的线程ID*/
	HANDLE hCurrentThreadID = NULL;/*回调例程CreateProcessNotifyEx当前线程ID*/
	hCurrentThreadID = PsGetCurrentThreadId();
	if (CreateInfo == NULL)
	{
		/*进程退出*/
		DbgPrint("CreateProcessNotifyEx [Destroy][CurrentThreadId: %p][ProcessId = %p]\n", hCurrentThreadID, ProcessId);
		return;
	}
	/*进程启动*/
	hParentProcessID = CreateInfo->CreatingThreadId.UniqueProcess;
	hPareentThreadID = CreateInfo->CreatingThreadId.UniqueThread;

	DbgPrint("CreateProcessNotifyEx [Create][CurrentThreadId: %p][ParentID %p:%p][ProcessId = %p,ProcessName=%wZ]\n",
		hCurrentThreadID, hParentProcessID, hPareentThreadID, ProcessId, CreateInfo->ImageFileName);
	return;
}