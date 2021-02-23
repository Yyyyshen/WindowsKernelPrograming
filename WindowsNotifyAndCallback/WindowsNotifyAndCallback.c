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
 * 
 * 回调机制为驱动提供了一种通用方法来发送和接收某类通告
 * 这些通告可以时系统某部件状态发生变化而产生的通告，也可以时开发者自定义某条件成立而产生
 * 系统内置了一些回调有电源状态变化回调、系统时间变化回调
 * 主要理解下基于CALLBACK_OBJECT回调对象的回调机制
 * 回调对象就是实现发送和接收通告的关键，用来唯一的描述一个回调
 * 它是一种命名的内核对象（感觉像是可以用来做通信的设备对象）
 * 比如系统中电源状态回调的对象名为：\Callback\PowerState
 * 需要接收该回调时，可以调用ExCreateCallback函数打开对象，会返回一个回调对象指针
 * 之后调用ExRegisterCallback将一个回调例程注册到该对象上
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

/**
 * 一些中了驱动级病毒的电脑，通过杀软删除后，重启电脑又会出现
 * 一般来说，这类病毒也是sys文件形式存在，也保存在注册表中，但只删除这两个信息是不够的
 * 驱动病毒很多都会注册系统关机事件通知，或电源状态变化回调
 * 在通知或回调例程中，把自身重新注册到系统中，即生成一份sys文件，并将服务信息写入注册表
 * 这也只是一些简单的应用，实际情况可能更复杂
 */