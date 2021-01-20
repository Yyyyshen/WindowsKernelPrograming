#include <ntddk.h>

/**
 * 一些常用技巧和知识
 */

 /**
  * 关于x64和x86
  * 当32位程序运行在64位系统时
  * 有一个WOW64子系统发挥作用，可以理解为一个轻量级兼容层，工作在应用层
  * 当32位发起系统调用，会被这个子系统拦截，使用指针时，WOW64就会把指针长度转换为合适的长度再交给内核，这一过程称为“thunking”
  *
  * 系统目录中
  * System32放64位二进制文件，SysWOW64放32位文件
  * 当32位程序访问到System32目录文件，会被子系统重定向到SysWOW64（并非所有）
  * 如果确实需要访问System32目录，需要调用API：Wow64DisableWow64FsRedirection
  * 注册表也有相应的重定向机制
  */
VOID Test_Redirection() // 用户层使用
{
	//用于保留重定向状态
	//PVOID pOldValue = NULL;
	//BOOL bRet = Wow64DisableWow64FsRedirection(&pOldValue);//取消重定向
	//if (bRet == TRUE)
	//{
	//	HANDLE hFile = CreateFile("C:\\Windows\\system32\\test.txt", GENERIC_READ, 0, NULL, CREATE_ALWAYS, 0, NULL);
	//	if (hFile != INVALID_HANDLE_VALUE)
	//	{
	//		CloseHandle(hFile);
	//		hFile = INVALID_HANDLE_VALUE;
	//	}
	//	Wow64RevertWow64FsRedirection(pOldValue);//恢复重定向机制
	//}
}

/**
 * PatchGuard机制
 * 定时检查系统关键位置，如SSDT（系统服务描述表）、GDT（全局描述表）、IDT（中断描述表）、系统模块（ntoskrnl.exe）等
 * 发现篡改时，触发蓝屏保护，所以一些常见HOOK技术在64位不适用
 */

 /**
  * 汇编嵌入
  * 编译器只支持32位下嵌入汇编代码
  * 所以常用的 __asm int 3; （软中断）在64位下并不适用，但可以用现成的API：KdBreakPoint();
  * 通过反汇编，两个语句效果是一样的
  */

  /**
   * 需要注意的一些点
   * 初始化赋值，判空，释放等
   */
VOID Test_Init()
{
	WCHAR strNameBuf[256] = { 0 }; //初始化最好赋值
	PVOID pData = NULL;
	pData = ExAllocatePool(PagedPool, 1024);
	if (pData == NULL)
	{
		//资源不足时，申请时可能失败的，所以有效性判断很重要
		return;
	}//如果没有上面的判断，memset访问了空指针会蓝屏
	memset(pData, 0, 1024);
	//申请内存后使用，最后释放
	ExFreePool(pData);
	pData = NULL; //释放后最好是把指针也赋值为空，如果内存释放后正好被其他驱动申请，而指针还指向这块内存，会导致POOL数据破坏，类似应用层的堆破坏
	//不只在申请内存时，使用其他资源，如句柄、对象指针等，释放后也应当把变量置空
	//有效性判断应该包括使用入口函数参数，可以认定为一切资源都是不可信的
}

/**
 * 从Win10 14393开始，驱动需要打EV签名，为了减少成本，可以这样做
 * 开发一个空壳驱动打EV签名，驱动本身没有任何业务，只负责加载其他没签名的驱动
 */

/**
 * 一次性申请
 * 假如函数创建了很多线程，在卸载时，是需要停止这些线程的
 * 如果在unload函数中使用KeWaitForMultipleObjects函数等待线程退出，而这个函数本身需要一个非分页内存块
 * 当这个函数内存分配失败时，就没有能够等待线程退出导致蓝屏
 * 所以最好是在DriverEntry中把所需资源申请好
 */

/**
 * 微软提供的验证工具——Verifier
 * 驱动应包含自我判断、自我检测、自我修复过程，针对不同场景制定不同策略，防止升级驱动模块出问题后一直蓝屏
 */

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	return STATUS_SUCCESS;
}