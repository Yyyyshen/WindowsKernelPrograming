// ServicesOperate.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

/**
 * 对服务的操作
 * 可将驱动文件作为服务创建（注册）、启动、暂停、停止、删除（卸载）
 * 其中，内核驱动类型服务不支持暂停
 * 
 * 命令 sc create/start/stop/delete 实际上就是调用这些API
 */

#include <stdio.h>
#include "windows.h"
#define SER_NAME TEXT("MyDriver")
int main()
{
	SC_HANDLE hSCM = NULL;
	SC_HANDLE hSer = NULL;

	do
	{
		//服务管理器，开发者可通过系统API操作服务，API内部首先通过一个LPC（本地方法调用)方式，把请求发送给服务管理器
		hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);//以拥有注册服务的权限打开管理器
		if (hSCM == NULL)
		{
			break;
		}
		//                              服务名             有用所有权限          内核类型驱动          手动启动            忽略错误
		hSer = CreateService(hSCM, SER_NAME, SER_NAME, SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE
			, TEXT("C:\\DriverTest\\Drivers\\MyDriver.sys"), NULL, NULL, NULL, NULL, NULL);
		if (hSer == NULL)
		{
			DWORD dwErrorCode = GetLastError();
			if (dwErrorCode == ERROR_SERVICE_EXISTS)
			{
				hSer = OpenService(hSCM, SER_NAME, SERVICE_ALL_ACCESS);
				if (hSer == NULL)
				{
					break;
				}
			}
			else
			{
				break;
			}
		}
		printf("CreateService or OpenService succ \n");
		getchar();
		//启动服务
		BOOL bSucc = StartService(hSer, NULL, NULL);
		printf("StartService:%u\n", bSucc);
		getchar();
		//启动服务后可通过ControlService函数暂停、恢复、停止服务
		SERVICE_STATUS SerStatus = { 0 };
		bSucc = ControlService(hSer, SERVICE_CONTROL_STOP, &SerStatus);
		printf("ControlService-stop:%u\n", bSucc);
		//删除服务
		DeleteService(hSer);
	} while (FALSE);

	if (hSCM != NULL)
	{
		CloseServiceHandle(hSCM);
		hSCM = NULL;
	}
	if (hSer != NULL)
	{
		CloseServiceHandle(hSer);
		hSer = NULL;
	}
	return 0;
}