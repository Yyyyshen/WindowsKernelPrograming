#include <wdm.h>
#include <ntddkbd.h>

/**
 * 键盘输入监控
 *
 * 基于ctrl2cap
 */


extern POBJECT_TYPE* IoDriverObjectType;//全局变量，头文件中不存在，声明后可用。注意需要声明为*，书中是错误的

#define KBD_DRIVER_NAME L"\\Driver\\Kbdclass" //驱动名

ULONG gC2pKeyCount = 0;//键盘按键事件计数

NTSTATUS
ObReferenceObjectByName(	//未公开函数，声明后可以使用
	PUNICODE_STRING OjbectName,
	ULONG Attributes,
	PACCESS_STATE AccessState,
	ACCESS_MASK DesiredAccess,
	POBJECT_TYPE ObjectType,
	KPROCESSOR_MODE AccessMode,
	PVOID ParseContext,
	PVOID* Object
);

//转换扫描码为实际键位
unsigned char asciiTbl[] = {
	0x00, 0x1B, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x2D, 0x3D, 0x08, 0x09,	//normal
		0x71, 0x77, 0x65, 0x72, 0x74, 0x79, 0x75, 0x69, 0x6F, 0x70, 0x5B, 0x5D, 0x0D, 0x00, 0x61, 0x73,
		0x64, 0x66, 0x67, 0x68, 0x6A, 0x6B, 0x6C, 0x3B, 0x27, 0x60, 0x00, 0x5C, 0x7A, 0x78, 0x63, 0x76,
		0x62, 0x6E, 0x6D, 0x2C, 0x2E, 0x2F, 0x00, 0x2A, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x37, 0x38, 0x39, 0x2D, 0x34, 0x35, 0x36, 0x2B, 0x31,
		0x32, 0x33, 0x30, 0x2E,
		0x00, 0x1B, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x2D, 0x3D, 0x08, 0x09,	//caps
		0x51, 0x57, 0x45, 0x52, 0x54, 0x59, 0x55, 0x49, 0x4F, 0x50, 0x5B, 0x5D, 0x0D, 0x00, 0x41, 0x53,
		0x44, 0x46, 0x47, 0x48, 0x4A, 0x4B, 0x4C, 0x3B, 0x27, 0x60, 0x00, 0x5C, 0x5A, 0x58, 0x43, 0x56,
		0x42, 0x4E, 0x4D, 0x2C, 0x2E, 0x2F, 0x00, 0x2A, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x37, 0x38, 0x39, 0x2D, 0x34, 0x35, 0x36, 0x2B, 0x31,
		0x32, 0x33, 0x30, 0x2E,
		0x00, 0x1B, 0x21, 0x40, 0x23, 0x24, 0x25, 0x5E, 0x26, 0x2A, 0x28, 0x29, 0x5F, 0x2B, 0x08, 0x09,	//shift
		0x51, 0x57, 0x45, 0x52, 0x54, 0x59, 0x55, 0x49, 0x4F, 0x50, 0x7B, 0x7D, 0x0D, 0x00, 0x41, 0x53,
		0x44, 0x46, 0x47, 0x48, 0x4A, 0x4B, 0x4C, 0x3A, 0x22, 0x7E, 0x00, 0x7C, 0x5A, 0x58, 0x43, 0x56,
		0x42, 0x4E, 0x4D, 0x3C, 0x3E, 0x3F, 0x00, 0x2A, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x37, 0x38, 0x39, 0x2D, 0x34, 0x35, 0x36, 0x2B, 0x31,
		0x32, 0x33, 0x30, 0x2E,
		0x00, 0x1B, 0x21, 0x40, 0x23, 0x24, 0x25, 0x5E, 0x26, 0x2A, 0x28, 0x29, 0x5F, 0x2B, 0x08, 0x09,	//caps + shift
		0x71, 0x77, 0x65, 0x72, 0x74, 0x79, 0x75, 0x69, 0x6F, 0x70, 0x7B, 0x7D, 0x0D, 0x00, 0x61, 0x73,
		0x64, 0x66, 0x67, 0x68, 0x6A, 0x6B, 0x6C, 0x3A, 0x22, 0x7E, 0x00, 0x7C, 0x7A, 0x78, 0x63, 0x76,
		0x62, 0x6E, 0x6D, 0x3C, 0x3E, 0x3F, 0x00, 0x2A, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x37, 0x38, 0x39, 0x2D, 0x34, 0x35, 0x36, 0x2B, 0x31,
		0x32, 0x33, 0x30, 0x2E
};
// flags for keyboard status
#define	S_SHIFT				1
#define	S_CAPS				2
#define	S_NUM				4
static int kb_status = S_NUM;
void __stdcall print_keystroke(UCHAR sch)
{
	UCHAR	ch = 0;
	int		off = 0;

	if ((sch & 0x80) == 0)	//make
	{
		if ((sch < 0x47) ||
			((sch >= 0x47 && sch < 0x54) && (kb_status & S_NUM))) // Num Lock
		{
			ch = asciiTbl[off + sch];
		}

		switch (sch)
		{
		case 0x3A:
			kb_status ^= S_CAPS;
			break;

		case 0x2A:
		case 0x36:
			kb_status |= S_SHIFT;
			break;

		case 0x45:
			kb_status ^= S_NUM;
		}
	}
	else		//break
	{
		if (sch == 0xAA || sch == 0xB6)
			kb_status &= ~S_SHIFT;
	}

	if (ch >= 0x20 && ch < 0x7F)
	{
		DbgPrint("%C \n", ch);
	}
}


/**
 * 在串口过滤例子中，使用了两个数组，一个保存所有过滤设备，另一个保存真实设备
 * 两个数组起到了映射表的作用，拿到过滤设备指针时就可以找到真实设备指针
 * 但实际上没有必要，生成过滤设备时，可以给设备指定任意长度的设备扩展
 * 所以，这里定义一个结构体作为设备扩展，通过向扩展中填写内容，就保存了各指针信息
 */
typedef struct _C2P_DEV_EXT
{
	// 这个结构的大小
	ULONG NodeSize;
	// 过滤设备对象
	PDEVICE_OBJECT pFilterDeviceObject;
	// 同时调用时的保护锁
	KSPIN_LOCK IoRequestsSpinLock;
	// 进程间同步处理  
	KEVENT IoInProgressEvent;
	// 绑定的设备对象
	PDEVICE_OBJECT TargetDeviceObject;
	// 绑定前底层设备对象
	PDEVICE_OBJECT LowerDeviceObject;
} C2P_DEV_EXT, * PC2P_DEV_EXT;

NTSTATUS
c2pDevExtInit(
	IN PC2P_DEV_EXT devExt,
	IN PDEVICE_OBJECT pFilterDeviceObject,
	IN PDEVICE_OBJECT pTargetDeviceObject,
	IN PDEVICE_OBJECT pLowerDeviceObject)
{
	//向设备扩展域中记录所需信息
	memset(devExt, 0, sizeof(C2P_DEV_EXT));
	devExt->NodeSize = sizeof(C2P_DEV_EXT);
	devExt->pFilterDeviceObject = pFilterDeviceObject;
	KeInitializeSpinLock(&(devExt->IoRequestsSpinLock));
	KeInitializeEvent(&(devExt->IoInProgressEvent), NotificationEvent, FALSE);
	devExt->TargetDeviceObject = pTargetDeviceObject;
	devExt->LowerDeviceObject = pLowerDeviceObject;
	return(STATUS_SUCCESS);
}

//打开驱动对象KbdClass，然后绑定下面所有设备
NTSTATUS
c2pAttachDevices(
	IN PDRIVER_OBJECT DriverObject,
	IN PUNICODE_STRING RegistryPath
)
{
	NTSTATUS status = 0;

	UNICODE_STRING uniNtNameString;
	PC2P_DEV_EXT devExt;
	PDEVICE_OBJECT pFilterDeviceObject = NULL;
	PDEVICE_OBJECT pTargetDeviceObject = NULL;
	PDEVICE_OBJECT pLowerDeviceObject = NULL;

	PDRIVER_OBJECT KbdDriverObject = NULL;

	RtlInitUnicodeString(&uniNtNameString, KBD_DRIVER_NAME);//初始化驱动名字符串
	//通过驱动名打开对象
	status = ObReferenceObjectByName(
		&uniNtNameString,
		OBJ_CASE_INSENSITIVE,
		NULL,
		0,
		*IoDriverObjectType,
		KernelMode,
		NULL,
		&KbdDriverObject
	);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("Attach: open driver object by name failed."));
		return status;
	}

	ObDereferenceObject(KbdDriverObject);//调用ObReferenceObjectByName会使驱动对象引用增加，需要解引用

	//设备链中第一个设备
	pTargetDeviceObject = KbdDriverObject->DeviceObject;
	//遍历设备链
	while (pTargetDeviceObject)
	{
		//生成过滤设备
		status = IoCreateDevice(
			DriverObject,
			sizeof(C2P_DEV_EXT), //填写设备扩展所需要的大小
			NULL,
			pTargetDeviceObject->DeviceType,
			pTargetDeviceObject->Characteristics,
			FALSE,
			&pFilterDeviceObject
		);
		if (!NT_SUCCESS(status))
		{
			KdPrint(("Attach: create filter device failed."));
			return status;
		}
		//绑定过滤设备与真实设备对象，用pLowerDeviceObjcet接收绑定后得到的下一个真实设备对象
		pLowerDeviceObject = IoAttachDeviceToDeviceStack(pFilterDeviceObject, pTargetDeviceObject);
		//失败则放弃之前操作后退出
		if (!pLowerDeviceObject)
		{
			KdPrint(("Attach: attach device failed."));
			IoDeleteDevice(pFilterDeviceObject);
			pFilterDeviceObject = NULL;
			return status;
		}

		//设备扩展																				
		devExt = (PC2P_DEV_EXT)(pFilterDeviceObject->DeviceExtension);						 //关于为绑定的过滤设备对象StackSize赋值
		c2pDevExtInit(																		 //msdn对于设备对象的StackSize字段解释中，明确指出了
			devExt,																			 //当使用IoAttachDevice或IoAttachDeviceToDeviceStack绑定一个设备对象时
			pFilterDeviceObject,															 //IO管理器会自动绑定的设备对象设置合适的StackSize值
			pTargetDeviceObject,															 //只有当前面是使用IoGetDeviceObjectPointer获取的设备对象
			pLowerDeviceObject																 //才需要显示声明它的设备对象StackSize+1
		);																					 //所以可以不需要写
																							 //（参考 https://blog.csdn.net/cssxn/article/details/103165667）
		//准备绑定下一个设备
		pFilterDeviceObject->DeviceType = pLowerDeviceObject->DeviceType;								   //  ↑
		pFilterDeviceObject->Characteristics = pLowerDeviceObject->Characteristics;
		//pFilterDeviceObject->StackSize = pLowerDeviceObject->StackSize + 1; //这句话可以不需要，具体解释 见上面空白
		pFilterDeviceObject->Flags |= pLowerDeviceObject->Flags & (DO_BUFFERED_IO | DO_DIRECT_IO | DO_POWER_PAGABLE);
		pTargetDeviceObject = pTargetDeviceObject->NextDevice; //移动到下一个设备
	}

	return status;
}

//解绑设备
VOID
c2pDetach(IN PDEVICE_OBJECT pDeviceObject)
{
	PC2P_DEV_EXT devExt;
	BOOLEAN NoRequestsOutstanding = FALSE;
	devExt = (PC2P_DEV_EXT)pDeviceObject->DeviceExtension;
	__try
	{
		__try
		{
			IoDetachDevice(devExt->TargetDeviceObject);
			devExt->TargetDeviceObject = NULL;
			IoDeleteDevice(pDeviceObject);
			devExt->pFilterDeviceObject = NULL;
			DbgPrint(("Detach Finished\n"));
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {}
	}
	__finally {}
	return;
}

/**
 * 各分发函数
 */
NTSTATUS
c2pDispatchGeneral(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
)
{
	//没用到的分发函数，直接skip然后用IoCallDriver把IRP发送到真实设备对象 
	IoSkipCurrentIrpStackLocation(Irp);
	return IoCallDriver(((PC2P_DEV_EXT)DeviceObject->DeviceExtension)->LowerDeviceObject, Irp);//使用预先保留的设备扩展中的指针
}

#define LCONTROL ((USHORT)0x1D) 
#define CAPS_LOCK ((USHORT)0x3A) 
NTSTATUS // 这是一个IRP完成回调函数的原型
c2pReadComplete(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp,
	IN PVOID Context
)
{
	PIO_STACK_LOCATION IrpSp;
	ULONG buf_len = 0;
	PUCHAR buf = NULL;
	size_t i,numKeys;

	//结构体中获取输入信息
	PKEYBOARD_INPUT_DATA KeyData;

	IrpSp = IoGetCurrentIrpStackLocation(Irp);

	// 如果请求失败了，这么获取进一步的信息是没意义的。
	if (NT_SUCCESS(Irp->IoStatus.Status))
	{
		// 获得读请求完成后输出的缓冲区
		buf = Irp->AssociatedIrp.SystemBuffer;
		KeyData = (PKEYBOARD_INPUT_DATA)buf;
		// 获得这个缓冲区的长度。一般的说返回值有多长都保存在
		// Information中。
		buf_len = Irp->IoStatus.Information;
		numKeys = buf_len / sizeof(KEYBOARD_INPUT_DATA);
		for (i = 0; i < numKeys; ++i)
		{
			//DbgPrint("ctrl2cap: %2x\r\n", buf[i]);
			DbgPrint("\n");
			DbgPrint("ScanCode: %x ", KeyData->MakeCode);
			DbgPrint("%s\n", KeyData->Flags ? "Up" : "Down");
			print_keystroke((UCHAR)KeyData->MakeCode);

			if (KeyData->MakeCode == CAPS_LOCK)
			{
				KeyData->MakeCode = LCONTROL;
			}
		}

	}
	//按键请求计数-1
	gC2pKeyCount--;

	if (Irp->PendingReturned)
	{
		IoMarkIrpPending(Irp);
	}
	return Irp->IoStatus.Status;
}

NTSTATUS
c2pRead(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
)
{
	NTSTATUS status = STATUS_SUCCESS;
	PC2P_DEV_EXT devExt;
	PIO_STACK_LOCATION currentIrpStack;
	KEVENT waitEvent;
	KeInitializeEvent(&waitEvent, NotificationEvent, FALSE);

	if (Irp->CurrentLocation == 1)
	{
		ULONG ReturnedInformation = 0;
		KdPrint(("Dispatch encountered bogus current location\n"));
		status = STATUS_INVALID_DEVICE_REQUEST;
		Irp->IoStatus.Status = status;
		Irp->IoStatus.Information = ReturnedInformation;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return(status);
	}

	// 全局变量键计数器加1
	gC2pKeyCount++;

	// 得到设备扩展。目的是之后为了获得下一个设备的指针。
	devExt = (PC2P_DEV_EXT)DeviceObject->DeviceExtension;

	// 设置回调函数并把IRP传递下去。 之后读的处理也就结束了。
	// 剩下的任务是要等待读请求完成。
	currentIrpStack = IoGetCurrentIrpStackLocation(Irp);
	IoCopyCurrentIrpStackLocationToNext(Irp);//复制当前栈空间
	IoSetCompletionRoutine(Irp, c2pReadComplete, DeviceObject, TRUE, TRUE, TRUE);//设置完成回调
	return  IoCallDriver(devExt->LowerDeviceObject, Irp);
}

NTSTATUS
c2pPower(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
)
{
	//电源相关IRP处理
	PC2P_DEV_EXT devExt;
	devExt = (PC2P_DEV_EXT)DeviceObject->DeviceExtension;
	//与普通分发中skip处理类似，但先调用PoStartNextPowerIrp，之后使用PoCallDriver代替IoCallDriver
	PoStartNextPowerIrp(Irp);
	IoSkipCurrentIrpStackLocation(Irp);
	return PoCallDriver(devExt->LowerDeviceObject, Irp);
}

NTSTATUS
c2pPnP(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
)
{
	//设备插拔时的分发特殊处理
	PC2P_DEV_EXT devExt;
	PIO_STACK_LOCATION irpStack;
	NTSTATUS status = STATUS_SUCCESS;
	KIRQL oldIrql;
	KEVENT event;

	// 获得真实设备。
	devExt = (PC2P_DEV_EXT)(DeviceObject->DeviceExtension);
	irpStack = IoGetCurrentIrpStackLocation(Irp);

	switch (irpStack->MinorFunction)
	{
	case IRP_MN_REMOVE_DEVICE:
		KdPrint(("IRP_MN_REMOVE_DEVICE\n"));

		// 首先把请求发下去
		IoSkipCurrentIrpStackLocation(Irp);
		IoCallDriver(devExt->LowerDeviceObject, Irp);
		// 然后解除绑定。
		IoDetachDevice(devExt->LowerDeviceObject);
		// 删除我们自己生成的虚拟设备。
		IoDeleteDevice(DeviceObject);
		status = STATUS_SUCCESS;
		break;

	default:
		// 对于其他类型的IRP，全部都直接下发即可。 
		IoSkipCurrentIrpStackLocation(Irp);
		status = IoCallDriver(devExt->LowerDeviceObject, Irp);
	}
	//没必要担心还有未完成IRP，Windows系统要求卸载设备时系统自身应该已经处理掉了所有未决IRP
	return status;
}

/**
 * 键盘总是处于有一个读请求没完成的状态
 * 所以类似串口驱动一样等待5秒，也并不一定能完成这个请求（因为并未按键)
 * 防止未决请求没完成的方法就是使用gC2pKeyCount，是一个全局计数变量
 * 有一个读请求来时，计数+1，完成时-1，只有所有请求完成，才会结束等待
 * 最终结果是，只有一个按键被按下，卸载过程才结束
 */
#define  DELAY_ONE_MICROSECOND  (-10) //关于时间为负数 https://blog.csdn.net/lqk1985/article/details/2541867
#define  DELAY_ONE_MILLISECOND (DELAY_ONE_MICROSECOND*1000)
#define  DELAY_ONE_SECOND (DELAY_ONE_MILLISECOND*1000)
VOID
c2pUnload(PDRIVER_OBJECT DriverObject)
{
	PDEVICE_OBJECT DeviceObject;
	PDEVICE_OBJECT OldDeviceObject;
	PC2P_DEV_EXT devExt;

	LARGE_INTEGER lDelay;
	PRKTHREAD CurrentThread;
	lDelay = RtlConvertLongToLargeInteger(100 * DELAY_ONE_MILLISECOND);
	CurrentThread = KeGetCurrentThread();
	//当前线程设置为低实时模式，减少对其他程序的影响
	KeSetPriorityThread(CurrentThread, LOW_REALTIME_PRIORITY);

	UNREFERENCED_PARAMETER(DriverObject);
	KdPrint(("Driver Unloading..."));

	//遍历所有设备，解除绑定
	DeviceObject = DriverObject->DeviceObject;
	while (DeviceObject)
	{
		c2pDetach(DeviceObject);
		DeviceObject = DeviceObject->NextDevice;
	}
	ASSERT(NULL == DriverObject->DeviceObject);

	while (gC2pKeyCount)
	{
		//内核中sleep
		KeDelayExecutionThread(KernelMode, FALSE, &lDelay);
	}
	KdPrint(("Driver Unload OK!"));
	return;
}

PDRIVER_OBJECT gDriverObject = NULL;

NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObject, IN PUNICODE_STRING pRegistryPath)
{
	NTSTATUS status = STATUS_SUCCESS;

	//指定普通分发函数
	for (ULONG i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
	{
		pDriverObject->MajorFunction[i] = c2pDispatchGeneral;
	}

	//指定需要使用的特殊分发函数
	pDriverObject->MajorFunction[IRP_MJ_READ] = c2pRead;//读取按键信息
	pDriverObject->MajorFunction[IRP_MJ_POWER] = c2pPower;//
	pDriverObject->MajorFunction[IRP_MJ_PNP] = c2pPnP;//即插即用分发函数，比如设备插拔时做特殊处理

	//卸载函数
	pDriverObject->DriverUnload = c2pUnload;
	gDriverObject = pDriverObject;//记录为全局变量

	//绑定所有设备
	status = c2pAttachDevices(pDriverObject, pRegistryPath);

	return status;
}