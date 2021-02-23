#include <ntddk.h>
#include <wdm.h>
/**
 * 代码注入与防注入
 *
 * 代码注入一般以进程为目标，编写好Dll模块或者一串SHELLCODE，然后通过某种手段，放入目标进程，让目标进程执行这段代码
 * 一般的目的有：
 * 提权
 * 免杀
 * 行为监控
 * 敏感信息截取
 * 常见注入方式：
 * 主动注入，指被注入进程调用某些系统API时，会在这些API内部加载一些第三方代码或DLL，如SHELL扩展注入、输入法注入、消息钩子注入、SPI注入
 * 被动注入，指被注入进程即使不执行任何操作，也会被强制注入代码或DLL，常见的有远线程注入、APC注入
 */
int g_int_0 = 0;
/**
 * 主动注入时利用系统机制，系统为一部分功能预留了扩展接口，为系统定制或补充额外能力，开发者可以编写DLL遵守系统相关约定
 * 当发生相应操作时，如果有扩展，则会调用到这个DLL
 * （实用工具：PCHunter）
 *
 * AppInit注入：
 * 在注册表Windows键值下，有一个AppInit_DLLs项，可以在该项里填充需要注入的DLL全路径名，同键值下LoadAppInit_DLLs为1表示开启功能
 * AppInit注入针对User32.dll，当进程加载User32.dll时，就会加载上面指定的DLL到进程（只能针对GUI应用）
 *
 * SPI注入：
 * 服务提供者接口，是系统为拓展网络功能引入的一套接口
 * 开发者可以编写一个遵循规范的DLL，导出一个名字固定的函数，同时也要将DLL信息写入注册表相应位置（WinSock2）
 *
 * 消息时间注入：
 * 系统提供两套基于消息事件的注入方式，消息钩子和事件钩子
 * 消息钩子是常见的使用SetWindowsHookEx函数，对应的，事件钩子使用SetWinEventHook，使用方法类似
 * 限制是只能监控统一桌面下的进程
 */
int g_int_1 = 1;
/**
 * 被动注入目标性较强，一般针对一个或一类进程
 *
 * 远线程注入：
 * 应用开发中，往往需要创建线程，系统有一套机制，允许开发者创建一个运行在其他进程当中的线程，即远线程
 * 使用函数CreateRemoteThread创建远程线程
 * 由于远线程并非在自身进程空间中，每个进程均有自身独立的进程空间，所以IpStartAddress函数所指的线程函数地址，也必须指向目标进程的地址空间
 *
 * APC注入：
 * APC是异步方法调用，是系统为了异步完成一些请求或事件而提供的与线程上下文强相关的机制
 * 开发者准备好一个函数，然后通过系统提供的APC机制，让指定线程在合适时机执行该函数
 * APC分为内核和用户态，内核态APC又分为特殊APC与普通APC
 * 特殊内核APC主要被用于IO完成的请求；普通内核APC常见场景是线程挂起
 * 用户态APC相关函数只有一个——QueueUserAPC
 * 
 * 父子进程注入：
 * 微软Detours所使用的就是父子进程注入方式，一般原理为
 * 父进程调用CreateProcess函数，传入CREATE_SUSPENDED标记，挂起方式创建子进程，该子进程就是需要被注入的进程
 * 子进程创建后，受标记控制，子进程中的主进程没有运行，并且PE加载器没有对进程进行初始化，整个子进程处于暂停状态
 * 父进程可以修改子进程内存信息，如，为子进程导入表增加DLL依赖、对子进程写入ShellCode，然后修改EIP指向该段代码、对子进程某关键API进行Hook，API被调用时加载注入的代码
 * 调用ResumeThread，恢复子进程执行
 * 常见于劫持
 */
 //APC注入函数原型
 //DWORD WINAPI QueueUserAPC(_In_ PAPCFUNC pfnAPC, _In_ HANDLE hThread, _In_ ULONG_PTR dwData);
int g_int_2 = 2;
/**
 * 防注入
 * 
 * 防止主动注入
 * 对于诸如信息处于内存
 *	检查内存，修改对应信息，删除注入信息
 * 
 * 对于注入信息处于注册表
 * 下面代码例子为防止AppInit注入
 * 
 * 对于注入信息处于磁盘
 * 常见DLL加载顺序漏洞、特洛伊木马等
 * 初级防护为对ntdll！LdrLoadDll函数进行挂钩
 * 对于安全软件，通常是通过文件过滤驱动，禁止第三方程序在自身程序文件夹修改或新增文件
 * 
 * 防止被动注入
 * 可以参考保护进程方式
 */

NTSTATUS RegistryCallback(PVOID CallbackContext, PVOID Argument1, PVOID Argument2);

VOID DriverUnload(PDRIVER_OBJECT pDrObj);


LARGE_INTEGER	g_CmCookies = { 0 };

UNICODE_STRING	g_AppInitValueName = { 0 };

NTSTATUS DriverEntry(PDRIVER_OBJECT pDrvObj, PUNICODE_STRING pRegistryPath)
{
	NTSTATUS nStatus = STATUS_UNSUCCESSFUL;
	do
	{
		UNREFERENCED_PARAMETER(pRegistryPath);
		//KdBreakPoint();
		RtlInitUnicodeString(&g_AppInitValueName, L"AppInit_DLLs");
		if (STATUS_SUCCESS != CmRegisterCallback(RegistryCallback, NULL, &g_CmCookies))
		{
			break;
		}
		pDrvObj->DriverUnload = DriverUnload;
		nStatus = TRUE;

	} while (FALSE);
	return nStatus;
}

VOID DriverUnload(PDRIVER_OBJECT pDrObj)
{
	UNREFERENCED_PARAMETER(pDrObj);
	CmUnRegisterCallback(g_CmCookies);
}

NTSTATUS RegistryCallback(PVOID CallbackContext, PVOID Argument1, PVOID Argument2)
{
	NTSTATUS nStatus = STATUS_SUCCESS;
	do
	{
		UNREFERENCED_PARAMETER(CallbackContext);
		if (ExGetPreviousMode() == KernelMode)
		{
			break;
		}
		switch ((REG_NOTIFY_CLASS)(ULONGLONG)Argument1)
		{
		case RegNtPreQueryValueKey:
		{
			//TODO，在这里可以添加对进程名字的过滤
			REG_QUERY_VALUE_KEY_INFORMATION* pInfo = (REG_QUERY_VALUE_KEY_INFORMATION*)Argument2;
			if (pInfo == NULL)
			{
				break;
			}
			if (pInfo->ValueName == NULL || pInfo->ValueName->Buffer == NULL)
			{
				break;
			}
			if (0 != RtlCompareUnicodeString(pInfo->ValueName, &g_AppInitValueName, TRUE))
			{
				break;
			}
			//命中Value名字,实际上，开发者应该通过pInfo->Object,结合ObQueryNameString反查全路径
			//这样更为严格
			__try
			{
				*pInfo->ResultLength = 0;
			}
			except(EXCEPTION_EXECUTE_HANDLER)
			{

			}
			nStatus = STATUS_CALLBACK_BYPASS;
			break;
		}
		default:
		{
			break;
		}
		}
	} while (FALSE);
	return nStatus;
}
