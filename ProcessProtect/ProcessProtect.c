#include <ntifs.h>
#include <ntddk.h>

/**
 * 保护进程
 *
 * 安全软件还有一个重要责任就是保护自身的正确性和完整性
 * 对内核对象的保护，主要是进程保护、线程和互斥量保护等
 *
 * 内核对象是内核态的一块内存，由系统分配及维护，描述了对象的相关信息
 * 比如进程对象属于内核对象，描述了和进程相关的信息：可执行文件名、进程页表指针、进程分配的虚拟内存等
 * 内核对象分为命名和匿名内核对象，一般跨进程访问的对象可以用命名对象
 * 对象是由类型的，例如互斥量对象和事件对象
 *
 * 内核对象在内存上的数据结构没有具体公开，但可以通过WinDbg结合.pdb符号表来查看
 * 书中主要介绍32位下win7系统的内核对象结构
 *
 * 内核对象结构主要由两部分组成：对象头、对象体
 * WinDbg上可以使用dt命令显示结构定义
 *
 * 要操作一个内核对象，首先要打开，所以最简单的保护就是防止此对象被恶意程序打开
 * 可以挂钩打开内核对象的相关函数，在处理函数中判断当前需要打开的内核对象名是否是需要保护的对象
 * 如果是，再判断进程是否受信任，如果是恶意程序，则阻止这个操作
 * 对于不同的内核对象要挂钩不同函数，比如事件对象使用NtOpenEvent函数、内存映射对象使用NtOpenSection
 */

#define PROTECT_NAME L"Global\\ProtectEvent" //需要保护的内核对象名

typedef NTSTATUS(_stdcall* PHOOK_NtOpenEvent) (PHANDLE EventHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);

PHOOK_NtOpenEvent g_pOrgin_NtOpenEvent = NULL;//hook时记录原函数地址

UNICODE_STRING g_strProtectEventName = { //保护的对象名
	sizeof(PROTECT_NAME) - 2,
	sizeof(PROTECT_NAME),
	PROTECT_NAME
};

BOOLEAN IsSafeProcess(HANDLE processId)
{
	//自定义判断是否为安全进程，一些系统进程要包含进去
	return TRUE;
}

//钩子处理函数
NTSTATUS _stdcall HOOK_NtOpenEvent(
	PHANDLE EventHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes
)
{
	NTSTATUS status = STATUS_SUCCESS;
	HANDLE hCurrentProcessId = 0;
	do
	{
		if (ExGetPreviousMode() != UserMode)
		{
			break;//只过滤UserMode
		}
		if (ObjectAttributes == NULL ||
			ObjectAttributes->ObjectName == NULL ||
			ObjectAttributes->ObjectName->Buffer == NULL ||
			ObjectAttributes->ObjectName->Length == 0)
		{
			break;//检查对象名
		}
		if (RtlCompareUnicodeString(ObjectAttributes->ObjectName, &g_strProtectEventName, TRUE) != 0)
		{
			break;//名字不匹配跳过
		}
		hCurrentProcessId = PsGetCurrentProcessId();
		//检查当前进程是否是安全进程（规则自定义）
		if (IsSafeProcess(hCurrentProcessId) == FALSE)
		{
			status = STATUS_ACCESS_DENIED;//不是安全进程，拒绝操作
		}
		break;
	} while (FALSE);
	if (status != STATUS_ACCESS_DENIED)
	{
		//提交给原函数
		status = g_pOrgin_NtOpenEvent(EventHandle, DesiredAccess, ObjectAttributes);
	}
	return status;
}

/**
 * 防止受保护对象被非法打开仅仅是第一步
 *
 * 还有其他操作可以获得内核对象句柄
 * Windows提供了一种句柄复制操作，可以把一个进程句柄表中的句柄复制到另一个进程的句柄表
 * 函数为DuplicateHandle，要求当前进程必须拥有源进程和目标进程的PROCESS_DUP_HANDLE权限
 * 所以，不通过打开操作，也能获取对象句柄
 *
 * 解决思路有：
 * 挂钩内核对象的操作函数，例如事件对象，挂钩NtSetEvent等函数，判断是否是安全进程在操作内核对象
 * 挂钩句柄复制函数（NtDuplicateObject），判断是否是复制到安全进程中，如果不是则拦截
 * 由于复制句柄需要权限，可以挂钩NtOpenProcess函数，阻止非安全进程获取该权限
 */

NTSTATUS ProtectCopyOp()
{
	return STATUS_SUCCESS;
}

/**
 * 除了打开和复制操作，还可以通过继承来获取句柄
 *
 * 从Vista系统开始引入了属性列表（AttributeList），允许在创建子进程过程中指定某个进程继承句柄
 * 恶意程序可以通过属性列表方式，在创建子进程时，指定从安全进程中继承句柄，而这个操作发生在创建子进程过程中，没有公开函数来操作句柄的继承
 * 虽然没有挂钩目标，但是继承过程中，也涉及了进程句柄权限，可以通过限制PROCESS_DUP_HANDLE权限解决
 * 还有一个办法是：
 * 通过之前了解的内核对象结构，对象头中有成员表示对象类型TypeIndex，同时他也是ObTypeIndexTable数组的下标
 * 数组中每个元素也是也给内核对象，系统是使用内核对象来表示一个对象类型的
 * 在对象结构中有一个TypeInfo，类型是_OBJECT_TYPE_INITIALIZER结构体，有一个成员是OpenProcedure
 * 此成员是一个函数指针，表示当一个内核对象被“获取”句柄是，系统就会调用这个内核对象相应“Type对象”的OpenProcedure函数
 * 并且，这里的获取指的是上述所有方式获取时都会发生，所以，hook该函数，可以解决大部分问题
 * 但由于是未公开函数，所以不同环境下可能不同
 *
 */

#define PROTECT_NAME_2 L"\\Global\\ProtectEvent" //需要保护的内核对象名
#define PROTECT_NAME_2_BASE L"、、BaseNamedObjectsProtectEvent" //NT格式，需要保护的内核对象名
#define OPENPROCEDURE_OFFSET (0x5c)	//OpenProcedure偏移

UNICODE_STRING g_strProtectEventName_2 = { //保护的对象名
	sizeof(PROTECT_NAME_2) - 2,
	sizeof(PROTECT_NAME_2),
	PROTECT_NAME_2
};
UNICODE_STRING g_strProtectEventName_2_Base = { //保护的对象名
	sizeof(PROTECT_NAME_2_BASE) - 2,
	sizeof(PROTECT_NAME_2_BASE),
	PROTECT_NAME_2_BASE
};

typedef enum _OB_OPEN_REASON
{
	//以各种方式获取到句柄
	ObCreateHandle,
	ObOpenHandle,
	ObDuplicateHandle,
	ObInheritHandle,
	ObMaxOpenReason
}OB_OPEN_REASON;

//函数类型声明以及全局变量记录原函数
typedef NTSTATUS(_stdcall* PHOOK_OpenProcedure)(
	IN OB_OPEN_REASON OpenReason,
	IN KPROCESSOR_MODE AccessMode,
	IN PEPROCESS Proccess OPTIONAL,
	IN PVOID Object,
	IN PACCESS_MASK GrandedAccess,
	IN ULONG HandleCount
	);
PHOOK_OpenProcedure g_pOrigin_OpenProcedure = NULL;

BOOLEAN ObjectHookOpenEvent(PVOID pHookFunc, PVOID* pOldFunc)
{
	BOOLEAN bSucc = FALSE;
	do
	{
		PVOID pEventTypeObj = NULL;
		PVOID* pHookAddress = NULL;
		if (ExEventObjectType == NULL)
		{
			break;
		}
		pEventTypeObj = (PVOID)*ExEventObjectType;
		//从Object_Type中通过硬编码定位到OpenProcedure地址
		pHookAddress = (PVOID*)((UCHAR*)pEventTypeObj + OPENPROCEDURE_OFFSET);
		if (pHookAddress == NULL)
		{
			break;
		}
		//保存原函数
		if (pOldFunc != NULL)
		{
			*pOldFunc = *pHookAddress;
		}
		//Hook操作
		InterlockedExchangePointer(pHookAddress, pHookFunc);
		bSucc = TRUE;
	} while (FALSE);
	return bSucc;
}

NTSTATUS _stdcall HOOK_OpenProcedure_Event(
	IN OB_OPEN_REASON OpenReason,
	IN KPROCESSOR_MODE AccessMode,
	IN PEPROCESS Proccess OPTIONAL,
	IN PVOID Object,
	IN PACCESS_MASK GrandedAccess,
	IN ULONG HandleCount
)
{
	NTSTATUS status = STATUS_SUCCESS;
	POBJECT_NAME_INFORMATION pObjNameInfo = NULL;
	do
	{
		ULONG uReturnLen = 0;
		NTSTATUS nRet = STATUS_UNSUCCESSFUL;
		HANDLE hCurrentProcessId = NULL;
		//检查参数
		if (OpenReason != ObInheritHandle && AccessMode != UserMode)
		{
			break;//对于继承操作，不关心模式，其他操作只过滤UserMode
		}
		if (GrandedAccess == NULL)
		{
			break;
		}
		if (Object == NULL)
		{
			break;
		}
		ObQueryNameString(Object, NULL, 0, &uReturnLen);
		if (uReturnLen == 0)
		{
			break;
		}
		pObjNameInfo = (POBJECT_NAME_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, uReturnLen, '1');
		if (pObjNameInfo == NULL)
		{
			break;
		}
		memset(pObjNameInfo, 0, uReturnLen);
		nRet = ObQueryNameString(Object, pObjNameInfo, uReturnLen, &uReturnLen);
		if (!NT_SUCCESS(nRet))
		{
			break;
		}
		if (pObjNameInfo->Name.Buffer == NULL || pObjNameInfo->Name.Length == 0)
		{
			break;
		}
		if (RtlCompareUnicodeString(&pObjNameInfo->Name, &g_strProtectEventName_2, TRUE) &&
			RtlCompareUnicodeString(&pObjNameInfo->Name, &g_strProtectEventName_2_Base, TRUE))
		{
			break;
		}
		hCurrentProcessId = PsGetCurrentProcessId();
		if (IsSafeProcess(hCurrentProcessId) == TRUE)
		{
			break;
		}
		status = STATUS_ACCESS_DENIED; //走到这里表示是非安全进程在获取句柄
		break;
	} while (FALSE);
	if (pObjNameInfo != NULL)
	{
		ExFreePoolWithTag(pObjNameInfo, '1');
		pObjNameInfo = NULL;
	}
	if (status != STATUS_ACCESS_DENIED && g_pOrigin_OpenProcedure != NULL)
	{
		//提交给原函数
		status = g_pOrigin_OpenProcedure(OpenReason, AccessMode, Proccess, Object, GrandedAccess, HandleCount);
	}
	return status;
}

VOID HOOK_GET_HANDLE()
{
	ObjectHookOpenEvent((PVOID)HOOK_OpenProcedure_Event, (PVOID*)&g_pOrigin_OpenProcedure);
}

/**
 * 继续研究，如何从内核对象角度保护进程
 *
 * 在安全软件中，进程和内核模块相互配合，任何一方破坏都会引起一定的异常
 * 由于攻击内核模块难度较大，所以更偏向于攻击安全软件上层进程
 *
 * 保护原理：
 * 进程对象也是一种内核对象，所以通过上面的方式拦截进程句柄获取可以一定程度上保护进程对象
 * 另外，相对于其他内核对象，进程对象保护有特殊性
 * 从操作内核对象角度，对进程操作比其他对象要多，比如获取进程的命令行、枚举进程内线程、等待一个进程退出等
 * 如果一味禁止非安全进程（不一定全是恶意进程）打开进程句柄，可能会导致一些软件间的兼容问题
 * 所以，对于进程，应当允许非恶意操作；恶意操作主要指的是通过进程句柄恶意修改、写入进程数据或恶意终止进程
 *
 * 对内核对象不同操作需要不同的权限，方案设计上可以用如下思路：
 * 进程权限主要分为制度权限和修改权限，对于非安全进程，给与只读权限，能够做一些查询操作，但无法破坏进程
 * 控制权限可以通过上面说的Hook函数NtOpenProcess中的DesiredAccess参数，或者修改OpenProcedure函数的GrandedAcess参数
 *
 * 由于OpenProcedure函数未公开，在不同环境收集所有偏移情况需要消耗大量时间和人力
 * 从Vista系统开始，系统新增了ObRegisterCallbacks函数，这个函数可以监控获取进程和线程句柄，并能阻止句柄获取和修改权限
 */
//能做到与挂钩OpenProcedure相同的功能
NTSTATUS ObRegisterCallbacks(_In_ POB_CALLBACK_REGISTRATION CallbackRegistration, _Outptr_ PVOID* RegistrationHandle);

/**
 * 除了通过进程句柄破坏进程，还有很多方式
 * 例如：
 * 攻击进程内的线程（终之、挂起线程，向线程中插入APC等
 * 攻击进程所创建的内核对象
 * 攻击进程的Windows窗口
 * 攻击进程需要加载的文件和注册表
 * 向进程发送欺骗消息（如系统关机），欺骗进程退出
 * 通过DLL注入机制
 * 利用系统提供的Exe劫持或重定向机制控制或禁止进程启动，如IFEO机制
 * 攻击或利用0day漏洞
 */

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
	return STATUS_SUCCESS;
}