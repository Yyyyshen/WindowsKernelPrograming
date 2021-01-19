#include "ntifs.h"
#include "ntddk.h"
#include "ntstrsafe.h"

/**
 * 驱动编程常用基础点
 */

 /**
  * 内存分配
  * 对于应用层，有malloc以及new操作符在堆上分配内存
  * 堆是基于虚拟内存上更小粒度的分割，有堆管理器管理，根据需要去申请一页或多页虚拟内存，再分割管理
  * 与之类似，内核中有池（Pool）的概念，可以从中申请内存，WDK提供一些列函数来操作
  */
VOID Test_Pool()
{
	//第一个参数PoolType表示申请何种内存，常用的有NonPagedPool与PagedPool
	//非分页内存一般用于高IRQL（大于等于DISPATCH_LEVEL）的代码中，所以需要根据代码的IRQL来选择合适的内存类型
	//类型还有很多，比较需要关注的还有NonPagedPoolExecute和NonPagedPoolNx
	//非分页类型内存属性为可执行，意味着可以写入二进制指令后执行，对存在漏洞的代码，可以使用缓冲区溢出攻击执行指令
	//NonPagedPoolNx类型则可以代替不需要可执行属性的非分页内存，Execute则是有可执行属性的类型，于普通非分页类型等价
	//第二个参数为申请大小
	//第三个Tag一般用于排查问题，对内存泄漏，可以通过查看系统各Tag标志对应内存大小，找到持续增长的内存块
	PVOID address;//执行成功返回分配内存的首地址，失败返回NULL
	address = ExAllocatePoolWithTag(PagedPool, 128, 0);//不需要Tag可以使用ExAllocatePool函数
	if (address == NULL)
	{
		DbgPrint("AllocatePool Failed.");
		return;
	}
	//内存使用后释放
	ExFreePoolWithTag(address, 0);
}
/**
 * 某些场景中，需要高频率的申请固定大小的内存
 * 使用ExAllocatePool效率并不高，而且容易造成内存碎片
 * 为提高性能，有一种 旁视列表 的内存分配方法
 * 首先，初始化一个旁视列表对象，设置内存块大小
 * 对象内部会维护内存使用状态，通过类似缓存或者说另一个自定义池的方式对内存进行二次管理
 */
BOOLEAN Test_Lookaside()
{
	//非分页内存示例
	PNPAGED_LOOKASIDE_LIST pLookAsideList = NULL;
	BOOLEAN bSucc = FALSE;
	BOOLEAN bInit = FALSE;
	PVOID pFirstMemory = NULL;
	PVOID pSecondMemory = NULL;

	do
	{
		//申请内存
		pLookAsideList = ExAllocatePoolWithTag(NonPagedPool, sizeof(NPAGED_LOOKASIDE_LIST), 'test');
		if (pLookAsideList == NULL)
		{
			break;
		}
		memset(pLookAsideList, 0, sizeof(NPAGED_LOOKASIDE_LIST));
		//初始化旁视列表对象 第二、三个函数分别是分配和释放内存的函数指针，可以自定义，传递NULL为使用系统默认函数
		ExInitializeNPagedLookasideList(pLookAsideList, NULL, NULL, 0, 128, 'test', 0);
		bInit = TRUE;
		//分配内存
		pFirstMemory = ExAllocateFromNPagedLookasideList(pLookAsideList);
		if (pFirstMemory == NULL)
		{
			break;
		}
		pSecondMemory = ExAllocateFromNPagedLookasideList(pLookAsideList);
		if (pSecondMemory == NULL)
		{
			break;
		}
		DbgPrint("First: %p , Second: %p\n", pFirstMemory, pSecondMemory);
		//释放第一块内存
		ExFreeToNPagedLookasideList(pLookAsideList, pFirstMemory);
		pFirstMemory = NULL;
		//再次分配
		pFirstMemory = ExAllocateFromNPagedLookasideList(pLookAsideList);
		if (pFirstMemory == NULL)
		{
			break;
		}
		DbgPrint("ReAllocate First: %p \n", pFirstMemory);
		bSucc = TRUE;

	} while (FALSE);

	if (pFirstMemory != NULL)
	{
		ExFreeToNPagedLookasideList(pLookAsideList, pFirstMemory);
		pFirstMemory = NULL;
	}
	if (pSecondMemory != NULL)
	{
		ExFreeToNPagedLookasideList(pLookAsideList, pSecondMemory);
		pSecondMemory = NULL;
	}
	if (bInit == TRUE)
	{
		ExDeleteNPagedLookasideList(pLookAsideList);
		bInit = FALSE;
	}
	if (pLookAsideList != NULL)
	{
		ExFreePoolWithTag(pLookAsideList, 'test');
		pLookAsideList = NULL;
	}
	return bSucc;
}

/**
 * Windows把一切都作为对象来管理，进程、线程、驱动等都是对象
 * 如果用户态进程需要创建一个内核对象，对象内存地址属于内核态地址空间，而用户态进程无法访问
 * 就需要句柄(HANDLE),句柄就如同内核对象凭证，用户态程序可以间接操作内核对象
 * 句柄只在当前进程中有意义，因为不同进程有各自的句柄表，内核态中，有一个系统的句柄表，存在于SYSTEM进程，只有一个，所有内核驱动都能使用该表
 * 根据上下文概念，如果有一个函数F1在进程P1中执行，打开一个句柄H1，另一个函数F2需要在进程P2使用H1句柄，就会出现错误
 * 可以在创建H1句柄时，指定句柄类型为内核句柄，这样就可以跨进程使用了
 */
BOOLEAN Test_Handle()
{
	BOOLEAN bSucc = FALSE;
	HANDLE hCreateEvent = NULL;
	PVOID pCreateEventObject = NULL;
	HANDLE hOpenEvent = NULL;
	PVOID pOpenEventObject = NULL;

	do
	{
		OBJECT_ATTRIBUTES obj_attr = { 0 };
		UNICODE_STRING uNameString = { 0 };
		RtlInitUnicodeString(&uNameString, L"\\BaswNamedObjects\\TestEvent");
		InitializeObjectAttributes(&obj_attr, &uNameString, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
		ZwCreateEvent(&hCreateEvent, EVENT_ALL_ACCESS, &obj_attr, SynchronizationEvent, FALSE);
		if (hCreateEvent == NULL)
		{
			break;
		}
		ObReferenceObjectByHandle(hCreateEvent, EVENT_ALL_ACCESS, *ExEventObjectType, KernelMode, &pCreateEventObject, NULL);
		if (pCreateEventObject == NULL)
		{
			break;
		}
		ZwOpenEvent(&hOpenEvent, EVENT_ALL_ACCESS, *ExEventObjectType, KernelMode, &pCreateEventObject, NULL);
		if (hOpenEvent == NULL)
		{
			break;
		}
		ObReferenceObjectByHandle(hOpenEvent, EVENT_ALL_ACCESS, *ExEventObjectType, KernelMode, &pOpenEventObject, NULL);
		if (pOpenEventObject == NULL)
		{
			break;
		}
		DbgPrint("Create Handle: %p, Create Pointer = %p \n", hCreateEvent, pCreateEventObject);
		DbgPrint("Open Handle: %p, Open Pointer = %p \n", hOpenEvent, pOpenEventObject);
		bSucc = TRUE;

	} while (FALSE);

	//释放
	if (pCreateEventObject != NULL)
	{
		ObDereferenceObject(pCreateEventObject);
		pCreateEventObject = NULL;
	}
	if (hCreateEvent != NULL)
	{
		ZwClose(hCreateEvent);
		hCreateEvent = NULL;
	}
	if (pOpenEventObject != NULL)
	{
		ObDereferenceObject(pOpenEventObject);
		pOpenEventObject = NULL;
	}
	if (hOpenEvent != NULL)
	{
		ZwClose(hOpenEvent);
		hOpenEvent = NULL;
	}

	return bSucc;
}

/**
 * 注册表是一种文件，Windows\System32\config下的文件被以内存映射的方式映射到内核空间，然后以一种HIVE的方式组织起来
 * 之前项目中都用过，简单过一下
 */
VOID Test_Reg_Create(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	//创建新的注册表键，只能在IRQL为PASSIVE_LEVEL下运行（Zw开头函数一般都是）
	OBJECT_ATTRIBUTES objAttr = { 0 };
	HANDLE hkey = NULL;
	ULONG ulDisposition = 0;
	UNREFERENCED_PARAMETER(DriverObject);//告诉编译器，已经使用了该变量，不必检测警告
	InitializeObjectAttributes(&objAttr, RegistryPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
	ZwCreateKey(&hkey, KEY_WRITE, &objAttr, 0, NULL, REG_OPTION_NON_VOLATILE, &ulDisposition);
	if (hkey != NULL)
	{
		//修改键
		UNICODE_STRING usValueName = { 0 };
		ULONG ulNewStartValue = 2;
		RtlInitUnicodeString(&usValueName, L"Start");
		ZwSetValueKey(hkey, &usValueName, 0, REG_DWORD, (PVOID)&ulNewStartValue, sizeof(ulNewStartValue));

		//查询
		ULONG ulRetSize = 0;
		NTSTATUS nStatus = ZwQueryValueKey(hkey, &usValueName, KeyValuePartialInformation, NULL, 0, &ulRetSize);
		if (nStatus == STATUS_BUFFER_TOO_SMALL && ulRetSize != 0)//空间不足
		{
			//ulRetSize保存的是所需大小，确定所需大小后，申请内存并再次查询
			ULONG ulStartValue = 0;
			PKEY_VALUE_PARTIAL_INFORMATION pData = ExAllocatePoolWithTag(PagedPool, ulRetSize, 'DriF');
			if (pData != NULL)
			{
				memset(pData, 0, ulRetSize);
				nStatus = ZwQueryValueKey(hkey, &usValueName, KeyValuePartialInformation, (PVOID)pData, ulRetSize, &ulRetSize);
			}
			//释放内存
			ExFreePoolWithTag(pData, 'Drif');
			pData = NULL;
		}

		//关闭和释放
		ZwClose(hkey);
		hkey = NULL;
	}
}

/**
 * 文件操作
 * 路径前加“\\??\\”，因为操作时使用的时对象路径，而“C:”是一个符号链接对象，这类对象都在“\\??\\”路径下
 * 解释了之前在应用层写程序时，从资源管理器中复制出来的路径到VS里，前面有两个问号但代码中不可见，导致一直获取不到文件
 */
VOID Test_File(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	HANDLE file_handle = NULL;
	IO_STATUS_BLOCK io_status;
	//先初始化含有文件路径的OBJECT_ATTRIBUTES
	OBJECT_ATTRIBUTES objAttr;
	UNICODE_STRING ufile_name = RTL_CONSTANT_STRING(L"\\??\\C:\\Test.txt");
	InitializeObjectAttributes(&objAttr, &ufile_name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	//打开文件
	ZwCreateFile(&file_handle, GENERIC_READ | GENERIC_WRITE, &objAttr, &io_status, NULL,
		FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN_IF, FILE_NON_DIRECTORY_FILE | FILE_RANDOM_ACCESS | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
	//关闭文件
	ZwClose(file_handle);
}
//拷贝操作示例
NTSTATUS MyCopyFile(PUNICODE_STRING target_path, PUNICODE_STRING source_path)
{
	//文件句柄
	HANDLE target = NULL;
	HANDLE source = NULL;

	//拷贝缓冲区
	PVOID buffer = NULL;
	LARGE_INTEGER offset = { 0 };
	IO_STATUS_BLOCK io_status = { 0 };

	NTSTATUS status;
	do
	{
		//打开文件句柄
		OBJECT_ATTRIBUTES objAttr_target;
		OBJECT_ATTRIBUTES objAttr_source;
		UNICODE_STRING u_target = *target_path;
		UNICODE_STRING u_source = *source_path;
		InitializeObjectAttributes(&objAttr_target, &u_target, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
		InitializeObjectAttributes(&objAttr_source, &u_source, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
		ZwCreateFile(&target, GENERIC_READ | GENERIC_WRITE, &objAttr_target, &io_status, NULL,
			FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN_IF, FILE_NON_DIRECTORY_FILE | FILE_RANDOM_ACCESS | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
		ZwCreateFile(&source, GENERIC_READ | GENERIC_WRITE, &objAttr_source, &io_status, NULL,
			FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN_IF, FILE_NON_DIRECTORY_FILE | FILE_RANDOM_ACCESS | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
		if (target == NULL || source == NULL)
		{
			break;
		}

		//给buffer分配内存
		int length = 4 * 1024;
		buffer = ExAllocatePool(PagedPool, length);
		if (buffer == NULL)
		{
			break;
		}
		memset(buffer, 0, length);

		//循环读写
		while (1)
		{
			length = 4 * 1024;//每次想要读的长度
			status = ZwReadFile(source, NULL, NULL, NULL, &io_status, buffer, length, &offset, NULL);
			if (!NT_SUCCESS(status))
			{
				//判断是否读完
				if (status == STATUS_END_OF_FILE)
				{
					status = STATUS_SUCCESS;
					break;
				}
			}
			length = io_status.Information;//实际读到的长度
			//写入文件
			status = ZwWriteFile(target, NULL, NULL, NULL, &io_status, buffer, length, &offset, NULL);
			if (!NT_SUCCESS(status))
			{
				break;
			}
			//移动偏移量，继续循环，直到读完
			offset.QuadPart += length;
		}

	} while (0);

	//回收资源
	if (target != NULL)
	{
		ZwClose(target);
	}
	if (source != NULL)
	{
		ZwClose(source);
	}
	if (buffer != NULL)
	{
		ExFreePool(buffer);
	}

	return STATUS_SUCCESS;

}

/**
 * 驱动中等待或停顿会使整个系统卡住，应启动另一个线程来做一些长期、耗时的操作
 * 驱动中生成的线程一般是系统线程，所在进程为System
 */
VOID MyThreadProc(PVOID context)
{
	PUNICODE_STRING str = (PUNICODE_STRING)context;
	DbgPrint("Print something in my thread.");
	PsTerminateSystemThread(STATUS_SUCCESS);//结束自己
}
VOID Test_Thread()
{
	UNICODE_STRING str = { 0 };
	RtlInitUnicodeString(&str, L"Hello!");
	HANDLE thread = NULL;
	NTSTATUS status = STATUS_SUCCESS;
	status = PsCreateSystemThread(&thread, 0, NULL, NULL, NULL, MyThreadProc, (PVOID)&str);
	//上面写法这里有个问题，当MyThreadProc执行时，本方法可能执行完毕了，堆栈中str可能已经释放，会导致蓝屏，所以要将str放在全局空间
	//或者在后面加上等待线程结束的语句
	if (!NT_SUCCESS(status))
	{
		//错误处理
	}
	//关闭句柄
	ZwClose(thread);
}
//同步事件


NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	NTSTATUS status = TRUE;

	//旁视列表
	Test_Lookaside();


	return status;
}