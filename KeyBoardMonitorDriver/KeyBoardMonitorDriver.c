#include <ntddk.h>
#include <wdm.h>
#include <ntddkbd.h>
#include <windef.h>

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
	size_t i, numKeys;

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


/**
 * HOOK分发函数
 *
 * 恶意程序很少会通过上面这种直接绑定虚拟设备的方式，因为很容易被发现
 * 会采用修改驱动对象的分发函数指针来过滤请求，截获后再调用旧的函数，使后续流程正常运作
 */
NTSTATUS
MyDispatch(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
)
{
	//做一些截获操作
}
NTSTATUS
HookKbdclassDispatch(
	IN PDRIVER_OBJECT DriverObject,
	IN PUNICODE_STRING RegistryPath
)
{
	NTSTATUS status = STATUS_SUCCESS;

	UNICODE_STRING uniNtNameString;
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

	//保存原有分发函数指针
	ULONG i;
	PDRIVER_DISPATCH OldDispatchFunctions[IRP_MJ_MAXIMUM_FUNCTION + 1];

	for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; ++i)
	{
		OldDispatchFunctions[i] = KbdDriverObject->MajorFunction[i];
		//进行原子交换操作，替换为自己的分发函数
		InterlockedExchangePointer(&KbdDriverObject->MajorFunction[i], MyDispatch);
	}

	return status;
}

/**
 * 类驱动下的端口驱动
 *
 * 替换分发函数指针的方法依然很明显
 * 还有一个手段，是直接寻找一个用于端口驱动中读取输入缓冲区的函数（实际上是类驱动提供）
 * 通过Hook该函数实现过滤
 *
 * KbdClass被称为键盘类驱动
 * 类驱动通常指统管一类设备的驱动程序，在类驱动下和实际硬件交互的驱动被称为端口驱动
 *
 * 当键盘上一个键被按下时，产生一个MakeCode，引发键盘中断；松开时，产生一个BreakCode，引发中断
 * 键盘中断导致键盘中断服务例程被执行，最终导致i8042prt的I8042KeyboardInterruptService被执行
 * 从端口读出按键的扫描码，放在KEYBOARD_INPUT_DATA中，将此结构放入i8042prt的输入数据队列中，一个中断放一个数据
 * 最终调用KeInsertQueueDpc，进行更多处理的延迟过程调用
 *
 * 如果找到了I8042KeyboardInterruptService中调用的类驱动的回调函数，就可以获取键盘输入了
 * 关键在于定位函数指针：
 *		函数指针应该保存在i8042prt生成的设备的自定义设备扩展中
 *		函数开始地址应该在内核模块KbdClass中
 *		内核模块KbdClass生成的一个设备对象指针也保存在设备扩展中，并且在要找的函数指针之前
 */
 //ps2的端口驱动
#define PS2_DRIVER_NAME  L"\\Driver\\i8042prt"
 //usb的端口驱动
#define USB_DRIVER_NAME  L"\\Driver\\Kbdhid"
//要搜索的回调函数类型定义
typedef VOID(_stdcall* KEYBOARDCLASSSERVIECALLBACK)(
	IN PDEVICE_OBJECT DeviceObject,
	IN PKEYBOARD_INPUT_DATA InputDataStart,
	IN PKEYBOARD_INPUT_DATA InputDataEnd,
	IN OUT PULONG InputDataConsumed
	);
//定义一个结构体以及全局变量接收搜索到的回调函数
typedef struct _KBD_CALLBACK
{
	PDEVICE_OBJECT classDeviceObject;
	KEYBOARDCLASSSERVIECALLBACK serviceCallBack;
}KBD_CALLBACK, * PKBD_CALLBACK;
KBD_CALLBACK gKbdCallBack = { 0 };
//替换的函数
VOID
MyCallBackFunction(
	PDEVICE_OBJECT DeviceObject,  //驱动对象
	PKEYBOARD_INPUT_DATA InputDataStart,  //
	PKEYBOARD_INPUT_DATA InputDataEnd,
	PULONG InputDataConsumed
)
{
	DbgPrint("keyup %d", InputDataStart->MakeCode);
	DbgPrint("keydown %d", InputDataEnd->MakeCode);
}
//搜索回调函数
NTSTATUS
SearchServiceCallBack(IN PDRIVER_OBJECT DriverObject)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	int i = 0;
	UNICODE_STRING uniNtNameString;
	PDEVICE_OBJECT pTargetDeviceObject = NULL;
	PDRIVER_OBJECT KbdDriverObject = NULL;
	PDRIVER_OBJECT KbdhidDriverObject = NULL;
	PDRIVER_OBJECT Kbd8042DriverObject = NULL;
	PDRIVER_OBJECT UsingDriverObject = NULL;
	PDEVICE_OBJECT UsingDeviceObject = NULL;
	PVOID KbdDriverStart = NULL;
	ULONG KbdDriverSize = 0;
	PVOID UsingDeviceExt = NULL;
	PVOID* AddrServiceCallBack = 0;

	//打开USB类型键盘
	RtlInitUnicodeString(&uniNtNameString, USB_DRIVER_NAME);
	status = ObReferenceObjectByName(
		&uniNtNameString,
		OBJ_CASE_INSENSITIVE,
		NULL,
		0,
		IoDriverObjectType,
		KernelMode,
		NULL,
		&KbdhidDriverObject
	);
	if (!NT_SUCCESS(status))
	{
		DbgPrint(("Search: open usb keyboard failed."));
	}
	else
	{
		ObDereferenceObject(KbdhidDriverObject);
	}
	//打开PS/2类型键盘
	RtlInitUnicodeString(&uniNtNameString, PS2_DRIVER_NAME);
	status = ObReferenceObjectByName(
		&uniNtNameString,
		OBJ_CASE_INSENSITIVE,
		NULL,
		0,
		IoDriverObjectType,
		KernelMode,
		NULL,
		&Kbd8042DriverObject
	);
	if (!NT_SUCCESS(status))
	{
		DbgPrint(("Search: open ps/2 keyboard failed."));
	}
	else
	{
		ObDereferenceObject(Kbd8042DriverObject);
	}
	//同时存在或者都没找到，返回失败
	if (Kbd8042DriverObject && KbdhidDriverObject)
	{
		return STATUS_UNSUCCESSFUL;
	}
	if (!KbdhidDriverObject && !Kbd8042DriverObject)
	{
		return STATUS_UNSUCCESSFUL;
	}
	//使用存在的对象
	UsingDriverObject = Kbd8042DriverObject ? Kbd8042DriverObject : KbdhidDriverObject;
	//找到该驱动对象下第一个设备对象
	UsingDeviceObject = UsingDriverObject->DeviceObject;
	//获取该设备对象的设备扩展，至此，该扩展中应该包含了要找的函数指针
	UsingDeviceExt = UsingDeviceObject->DeviceExtension;
	//则该地址就是在此扩展中保存的一个在类驱动KbdClass中的地址

	//打开驱动KbdClass
	RtlInitUnicodeString(&uniNtNameString, KBD_DRIVER_NAME);
	status = ObReferenceObjectByName(
		&uniNtNameString,
		OBJ_CASE_INSENSITIVE,
		NULL,
		0,
		IoDriverObjectType,
		KernelMode,
		NULL,
		&KbdDriverObject
	);
	if (!NT_SUCCESS(status))
	{
		DbgPrint(("Search: open kbd driver failed."));
		return STATUS_UNSUCCESSFUL;
	}
	else
	{
		ObDereferenceObject(KbdDriverObject);
		//获得开始地址和大小
		KbdDriverStart = KbdDriverObject->DriverStart;
		KbdDriverSize = KbdDriverObject->DriverSize;
	}
	//遍历kbdclass下所有设备，在这些设备中，有一个会保存在端口驱动的设备扩展中
	pTargetDeviceObject = KbdDriverObject->DeviceObject;
	PBYTE DeviceExt;
	while (pTargetDeviceObject)
	{
		DeviceExt = (PBYTE)UsingDeviceExt;
		//遍历设备扩展下的每一个指针
		for (; i < 4096; i++, DeviceExt += sizeof(PBYTE))
		{
			PVOID tmp;
			if (!MmIsAddressValid(DeviceExt)) //ntddk.h在最前面声明，否则找不到
			{
				break;
			}
			//找到后会填写到全局变量中，所以这里检查是否已找到，找到直接跳出
			if (gKbdCallBack.classDeviceObject && gKbdCallBack.serviceCallBack)
			{
				status = STATUS_SUCCESS;
				break;
			}
			//端口驱动的设备扩展中，找到了类驱动的设备对象，记录下类驱动设备对象
			tmp = *(PVOID*)DeviceExt;
			if (tmp == pTargetDeviceObject)
			{
				gKbdCallBack.classDeviceObject = (PDEVICE_OBJECT)tmp;
				DbgPrint(("classDeviceObject %8x\n", tmp));
				continue;
			}
			//如果设备扩展中找到一个地址位于KbdClass驱动中，基本可以认为就是我们要找的回调函数地址
			if (
				(tmp > KbdDriverStart) &&
				(tmp < (PBYTE)KbdDriverStart + KbdDriverSize) &&
				MmIsAddressValid(tmp)
				)
			{
				//记录下来
				gKbdCallBack.serviceCallBack = (KEYBOARDCLASSSERVIECALLBACK)tmp;
				AddrServiceCallBack = (PVOID*)DeviceExt;
				DbgPrint(("serviceCallBack:%8x AddrServiceCallBack: %8x\n", tmp, AddrServiceCallBack));
			}

		}
		pTargetDeviceObject = pTargetDeviceObject->NextDevice;//继续遍历下一个设备
	}

	//成功找到，替换为自己的回调函数，至此成功截获
	if (AddrServiceCallBack && gKbdCallBack.serviceCallBack)
	{
		DbgPrint(("Hook KeyboardClassServiceCallback\n"));
		*AddrServiceCallBack = MyCallBackFunction;
	}

	return status;
}

/**
 * 通过键盘中断反过滤
 *
 * 再往端口驱动更底层走
 * 针对PS/2键盘（32位系统下）
 * 早期方案：当输入焦点移到密码框时，注册一个中断服务接管键盘中断，比如0x93
 * 之后按键就不通过键盘驱动，而是完全由这个中断服务来处理扫描码并交给输入框
 *
 * 之前知道_asm int 3是一条中断指令（int n，其中n为中断号，可以触发软件中断，软件中断又叫异常）
 * 触发的本质是使CPU暂停执行，并跳转到中断处理函数中，中断处理函数首地址保存在叫做IDT的表中
 *
 * 真正的硬件中断一般称为IRQ，某个IRQ来自什么硬件通常有明确规定，比如IRQ1就是PS/2键盘
 * 一个IRQ一般需要一个中断处理函数处理，所以需要一个IRQ号到中断号的对应关系
 * 在IOAIPC出现后，对应关系变得可以修改，在Windows上，PS/2键盘事件发生一般都是int 0x93
 * 所以，修改int 0x93在IDT中保存的函数地址，修改为自己的函数，那么就能够先截获到这个中断
 *
 * 修改IDT
 * 在内核程序中，可以修改IDT，IDT内存地址不定，但可以通过指令sidt获取
 * 需要注意的是，在多核CPU上，每个核心都有自己的IDT，所以需要对每个核获取IDT，保证代码覆盖每个核
 *
 */
 //必须明确一个域有多少位，所以预先定义几个明确知道长度的变量
typedef unsigned char P2C_U8;
typedef unsigned short P2C_U16;
typedef unsigned long P2C_U32;
//通过sidt指令会得到如下结构体，注意1字节对齐
#pragma pack(push,1)
typedef struct P2C_IDTR_
{
	P2C_U16 limit;//范围
	P2C_U32 base;//基地址
}P2C_IDTR, * PP2C_IDTR;
#pragma  pack(pop)
//用指令读出结构体，并返回IDT地址
void* p2cGetIdt()
{
	P2C_IDTR idtr;
	_asm sidt idtr //汇编指令获取IDT位置
	return (void*)idtr.base;
}
//获取IDT地址后，该内存空间是一个数组，每个元素为如下结构
#pragma pack(push,1)
typedef struct P2C_IDT_ENTRY_
{
	P2C_U16 offset_low;
	P2C_U16 selector;
	P2C_U8 reserved;
	P2C_U8 type : 4;			   //带冒号的域为位域
	P2C_U8 always0 : 1;			   //表示成员宽度少于1字节，冒号后数字表示具体位数
	P2C_U8 dpl : 2;				   //这里四个成员各占4/1/2/1位
	P2C_U8 present : 1;			   //实际占空间位1字节
	P2C_U16 offset_high;
}P2C_IDT_ENTRY, * PP2C_IDT_ENTRY;
#pragma  pack(pop)
//写一个函数替换中断服务地址，并在执行后跳转回原有中断函数
void* g_p2c_old;//记录原中断服务函数
__declspec(naked)/*修饰一个裸函数，MS的C编译器不会再生成函数框架指令*/ p2cInterruptProc()
{
	__asm
	{
		pushad					//保存所有寄存器状态
		pushfd					//
		call p2cUserFilter		//调用自己的函数

		popfd					//恢复所有寄存器
		popad					//
		jmp g_p2c_old			//跳转回原来的中断服务程序
	}
}
//宏处理，便于取数据高低字节部分，或者从高低字节部分组合数据
#define P2C_MAKELONG(low,high) \
((P2C_U32)(((P2C_U16)((P2C_U32)(low) & 0xffff)) | \
((P2C_U32)((P2C_U16)((P2C_U32)(high) & 0xffff))) << 16))
#define P2C_LOW16_OF_32(data) \
((P2C_U16)(((P2C_U32)data) & 0xffff))
#define P2C_HIGH16_OF_32(data) \
((P2C_U16)(((P2C_U32)data) >> 16))
//修改IDT表中第0x93项，修改为p2cInterruptProc
void p2cHookInt93(BOOLEAN hook_or_unhook)
{
	PP2C_IDT_ENTRY idt_addr = (PP2C_IDT_ENTRY)p2cGetIdt();
	idt_addr += 0x93;
	if (hook_or_unhook)
	{
		//记录原中断函数地址
		g_p2c_old = (void*)P2C_MAKELONG(idt_addr->offset_low, idt_addr->offset_high);
		//替换为p2cInterruptProc
		idt_addr->offset_low = P2C_LOW16_OF_32(p2cInterruptProc);
		idt_addr->offset_high = P2C_HIGH16_OF_32(p2cInterruptProc);
	}
	else
	{
		//取消hook
		idt_addr->offset_low = P2C_LOW16_OF_32(g_p2c_old);
		idt_addr->offset_high = P2C_HIGH16_OF_32(g_p2c_old);
	}
}

/**
 * 上面方法设置的是0x93中断号
 * 实际上由于这个中断号对应关系可以被设置，应使用HalGetInterruptVector来获取这个中断号，然后及逆行替换
 * （就是早期QQ的PS/2反过滤措施）
 *
 * 还可以更加底层，直接用端口操作键盘
 * PS/2键盘数据端口为0x60，直接读取端口就能读到数据（前提是键盘必须处于可读状态)
 * 驱动中没有对端口读取进行限制，直接用汇编就可以读取，一次读取一字节
 */
#define OBUFFER_FULL 0x02
#define IBUFFER_FULL 0x01
 //等待到键盘可读
ULONG p2cWaitForKbRead()
{
	int i = 100;
	P2C_U8 mychar;//一个字节等待读取
	do
	{
		_asm in al, 0x64	//读取键盘命令端口
		_asm mov mychar, al
		KeStallExecutionProcessor(50);
		if (!(mychar & OBUFFER_FULL)) break; //验证是否有对应标志
	} while (i--);
	if (i)	return TRUE;
	return FALSE;
}
//等待到键盘可写
ULONG p2cWaitForKbWrite()
{
	int i = 100;
	P2C_U8 mychar;//一个字节等待读取
	do
	{
		_asm in al, 0x64
		_asm mov mychar, al
		KeStallExecutionProcessor(50);
		if (!(mychar & IBUFFER_FULL)) break;
	} while (i--);
	if (i)	return TRUE;
	return FALSE;
}
//从端口操作键盘
void p2cUserFilter()
{
	static P2C_U8 sch_pre = 0;
	P2C_U8 sch;
	//可读时获取端口中的扫描码
	p2cWaitForKbRead();
	_asm in al, 0x60 //读取键盘端口
	_asm mov sch, al
	//把读到的数据写回端口，以便其他程序正常读取（如果不想被读取，可以随便写一个数据）
	if (sch_pre != sch)
	{
		sch_pre = sch;
		_asm mov al, 0xd2
		_asm out 0x64, al
		p2cWaitForKbWrite();
		_asm mov al, sch
		_asm out 0x60, al
	}
	//扫描码读出后，键盘数据端口中就没有这个值了， 调用旧的中断处理也就没了意义，所以又写回了端口中
	//但写回键盘时同样是触发中断，再次进入中断处理函数，引起死循环
	//解决方法就是使用一个静态变量sch_pre记录前一次的值，如果是这个值，就跳过
}


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