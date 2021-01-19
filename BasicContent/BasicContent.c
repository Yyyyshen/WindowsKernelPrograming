#include "ntddk.h"

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

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	NTSTATUS status = TRUE;

	//旁视列表
	Test_Lookaside();


	return status;
}