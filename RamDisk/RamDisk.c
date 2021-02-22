#include <ntddk.h>
#include <ntdddisk.h>
#include <wdf.h> //需要配置包含目录及附加依赖项；或者新建项目时使用KMDF项目框架
#include <ntstrsafe.h>

/**
 * 磁盘虚拟技术
 *
 * 使用非分页内存做的磁盘存储空间，并将其以一个独立磁盘形式暴露给用户
 *
 * 使用了WDF，是对WDM的封装
 * 例如对电源管理和即插即用这样的常用、复杂的处理代码进行封装，可以更方便的进行开发
 */

#define NT_DEVICE_NAME                  L"\\Device\\Ramdisk"
#define DOS_DEVICE_NAME                 L"\\DosDevices\\"

#define RAMDISK_TAG                     'DmaR'  // "RamD"
#define DOS_DEVNAME_LENGTH              (sizeof(DOS_DEVICE_NAME)+sizeof(WCHAR)*10)
#define DRIVE_LETTER_LENGTH             (sizeof(WCHAR)*10)

#define DRIVE_LETTER_BUFFER_SIZE        10
#define DOS_DEVNAME_BUFFER_SIZE         (sizeof(DOS_DEVICE_NAME) / 2) + 10

#define RAMDISK_MEDIA_TYPE              0xF8
#define DIR_ENTRIES_PER_SECTOR          16

#define DEFAULT_DISK_SIZE               (1024*1024)     // 1 MB
#define DEFAULT_ROOT_DIR_ENTRIES        512
#define DEFAULT_SECTORS_PER_CLUSTER     2
#define DEFAULT_DRIVE_LETTER            L"Z:"

typedef struct _DISK_INFO {
	ULONG   DiskSize;           //磁盘大小，字节计算（ULONG最大只有4GB）
	ULONG   RootDirEntries;     //磁盘上根文件系统进入节点
	ULONG   SectorsPerCluster;  //磁盘每个簇由多少扇区组成
	UNICODE_STRING DriveLetter; //磁盘盘符
} DISK_INFO, * PDISK_INFO;

typedef struct _DEVICE_EXTENSION {
	PUCHAR              DiskImage;                  //指向一块内存，作为内存盘实际数据存储空间
	DISK_GEOMETRY       DiskGeometry;               // Drive parameters built by Ramdisk
	DISK_INFO           DiskRegInfo;                //自定义磁盘信息
	UNICODE_STRING      SymbolicLink;               //磁盘符号链接名
	WCHAR               DriveLetterBuffer[DRIVE_LETTER_BUFFER_SIZE];//DiskRegInfo中DriverLetter的存储空间，是用户在注册表中指定的盘符
	WCHAR               DosDeviceNameBuffer[DOS_DEVNAME_BUFFER_SIZE];//SymbolicLink的存储空间
} DEVICE_EXTENSION, * PDEVICE_EXTENSION;
WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(DEVICE_EXTENSION, DeviceGetExtension)

typedef struct _QUEUE_EXTENSION {
	PDEVICE_EXTENSION DeviceExtension;
} QUEUE_EXTENSION, * PQUEUE_EXTENSION;
WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(QUEUE_EXTENSION, QueueGetExtension)


#pragma pack(1)

typedef struct  _BOOT_SECTOR
{
	UCHAR       bsJump[3];          // x86 jmp instruction, checked by FS
	CCHAR       bsOemName[8];       // OEM name of formatter
	USHORT      bsBytesPerSec;      // Bytes per Sector
	UCHAR       bsSecPerClus;       // Sectors per Cluster
	USHORT      bsResSectors;       // Reserved Sectors
	UCHAR       bsFATs;             // Number of FATs - we always use 1
	USHORT      bsRootDirEnts;      // Number of Root Dir Entries
	USHORT      bsSectors;          // Number of Sectors
	UCHAR       bsMedia;            // Media type - we use RAMDISK_MEDIA_TYPE
	USHORT      bsFATsecs;          // Number of FAT sectors
	USHORT      bsSecPerTrack;      // Sectors per Track - we use 32
	USHORT      bsHeads;            // Number of Heads - we use 2
	ULONG       bsHiddenSecs;       // Hidden Sectors - we set to 0
	ULONG       bsHugeSectors;      // Number of Sectors if > 32 MB size
	UCHAR       bsDriveNumber;      // Drive Number - not used
	UCHAR       bsReserved1;        // Reserved
	UCHAR       bsBootSignature;    // New Format Boot Signature - 0x29
	ULONG       bsVolumeID;         // VolumeID - set to 0x12345678
	CCHAR       bsLabel[11];        // Label - set to RamDisk
	CCHAR       bsFileSystemType[8];// File System Type - FAT12 or FAT16
	CCHAR       bsReserved2[448];   // Reserved
	UCHAR       bsSig2[2];          // Originial Boot Signature - 0x55, 0xAA
}   BOOT_SECTOR, * PBOOT_SECTOR;

typedef struct  _DIR_ENTRY
{
	UCHAR       deName[8];          // File Name
	UCHAR       deExtension[3];     // File Extension
	UCHAR       deAttributes;       // File Attributes
	UCHAR       deReserved;         // Reserved
	USHORT      deTime;             // File Time
	USHORT      deDate;             // File Date
	USHORT      deStartCluster;     // First Cluster of file
	ULONG       deFileSize;         // File Length
}   DIR_ENTRY, * PDIR_ENTRY;

#pragma pack()

#define DIR_ATTR_READONLY   0x01
#define DIR_ATTR_HIDDEN     0x02
#define DIR_ATTR_SYSTEM     0x04
#define DIR_ATTR_VOLUME     0x08
#define DIR_ATTR_DIRECTORY  0x10
#define DIR_ATTR_ARCHIVE    0x20

VOID
RamDiskEvtDeviceContextCleanup(
	IN WDFDEVICE Device
)
/*++

Routine Description:

   EvtDeviceContextCleanup event callback cleans up anything done in
   EvtDeviceAdd, except those things that are automatically cleaned
   up by the Framework.

   In the case of this sample, everything is automatically handled.  In a
   driver derived from this sample, it's quite likely that this function could
   be deleted.

Arguments:

	Device - Handle to a framework device object.

Return Value:

	VOID

--*/
{
	PDEVICE_EXTENSION pDeviceExtension = DeviceGetExtension(Device);

	PAGED_CODE();

	if (pDeviceExtension->DiskImage) {
		ExFreePool(pDeviceExtension->DiskImage);
	}
}

BOOLEAN
RamDiskCheckParameters(
	IN PDEVICE_EXTENSION devExt,
	IN LARGE_INTEGER ByteOffset,
	IN size_t Length
)

{
	//
	// Check for invalid parameters.  It is an error for the starting offset
	// + length to go past the end of the buffer, or for the length to
	// not be a proper multiple of the sector size.
	//
	// Others are possible, but we don't check them since we trust the
	// file system.
	//

	if (devExt->DiskRegInfo.DiskSize < Length ||
		ByteOffset.QuadPart < 0 || // QuadPart is signed so check for negative values
		((ULONGLONG)ByteOffset.QuadPart > (devExt->DiskRegInfo.DiskSize - Length)) ||
		(Length & (devExt->DiskGeometry.BytesPerSector - 1))) {

		//
		// Do not give an I/O boost for parameter errors.
		//

		KdPrint((
			"Error invalid parameter\n"
			"ByteOffset: %x\n"
			"Length: %d\n",
			ByteOffset,
			Length
			));

		return FALSE;
	}

	return TRUE;
}

/**
 * 对关注的请求进行自定义回调
 * 回调函数中需要做以下操作的一种：
 * 重新排队，可以将请求放入另一个队列
 * 完成请求，对请求做一些处理后完成它
 * 撤销请求，回调函数可以要求撤销该请求
 * 转发请求，可以转发给其他设备
 * 不能忽略该请求
 *
 * 这个例子中大多是对请求做处理后完成请求
 * 由RamDiskEvtDeviceAdd函数中做的处理，可以很方便的通过队列对象获取到设备扩展，进而获取所有相关参数
 * 缓冲区由系统提供，负责存放读出的数据或者要写入的数据
 * 获取相应参数后，只需要在内存镜像中适当地点和长度读取或写入即可
 */
VOID
RamDiskEvtIoDeviceControl(
	IN WDFQUEUE Queue,
	IN WDFREQUEST Request,
	IN size_t OutputBufferLength,
	IN size_t InputBufferLength,
	IN ULONG IoControlCode
)
/*++

Routine Description:
	处理一些必要的控制请求
	This event is called when the framework receives IRP_MJ_DEVICE_CONTROL
	requests from the system.

Arguments:

	Queue - Handle to the framework queue object that is associated
			with the I/O request.
	Request - Handle to a framework request object.

	OutputBufferLength - length of the request's output buffer,
						if an output buffer is available.
	InputBufferLength - length of the request's input buffer,
						if an input buffer is available.

	IoControlCode - the driver-defined or system-defined I/O control code
					(IOCTL) that is associated with the request.


Return Value:

	VOID

--*/
{

	NTSTATUS          Status = STATUS_INVALID_DEVICE_REQUEST;
	ULONG_PTR         information = 0;//存放返回的DeviceIoControl所需要的数据长度
	size_t            bufSize;
	PDEVICE_EXTENSION devExt = QueueGetExtension(Queue)->DeviceExtension;//通过队列对象获取设备扩展
	//由于是标准的Windows请求，所以可以不担心长度问题
	UNREFERENCED_PARAMETER(OutputBufferLength);
	UNREFERENCED_PARAMETER(InputBufferLength);
	//判断请求类型，一般磁盘卷都需要支持大量控制请求，这个例子的作者根据经验总结了一些必要的处理
	switch (IoControlCode) {
		//获取当前分区信息的请求
	case IOCTL_DISK_GET_PARTITION_INFO:
	{
		//声明一个输出缓冲区指针
		PPARTITION_INFORMATION outputBuffer;
		PBOOT_SECTOR bootSector = (PBOOT_SECTOR)devExt->DiskImage;//所需信息大部分由DBR中获取，所以需要个DBR指针
		//返回信息的长度，会被上层发出请求的设备收到
		information = sizeof(PARTITION_INFORMATION);
		//通过框架函数获取这个请求携带的输出缓冲区
		Status = WdfRequestRetrieveOutputBuffer(Request, sizeof(PARTITION_INFORMATION), &outputBuffer, &bufSize);
		if (NT_SUCCESS(Status)) {
			//获取缓冲区成功，将相关信息填入
			outputBuffer->PartitionType = (bootSector->bsFileSystemType[4] == '6') ? PARTITION_FAT_16 : PARTITION_FAT_12;
			outputBuffer->BootIndicator = FALSE;
			outputBuffer->RecognizedPartition = TRUE;
			outputBuffer->RewritePartition = FALSE;
			outputBuffer->StartingOffset.QuadPart = 0;
			outputBuffer->PartitionLength.QuadPart = devExt->DiskRegInfo.DiskSize;
			outputBuffer->HiddenSectors = (ULONG)(1L);
			outputBuffer->PartitionNumber = (ULONG)(-1L);

			Status = STATUS_SUCCESS;
		}
		break;
	}

	//向缓冲区填写磁盘信息
	case IOCTL_DISK_GET_DRIVE_GEOMETRY:
	{

		PDISK_GEOMETRY outputBuffer;

		information = sizeof(DISK_GEOMETRY);

		Status = WdfRequestRetrieveOutputBuffer(Request, sizeof(DISK_GEOMETRY), &outputBuffer, &bufSize);
		if (NT_SUCCESS(Status)) {

			RtlCopyMemory(outputBuffer, &(devExt->DiskGeometry), sizeof(DISK_GEOMETRY));
			Status = STATUS_SUCCESS;
		}

		break;
	}
	//验证可用和可写，直接返回成功，不需要其他信息
	case IOCTL_DISK_CHECK_VERIFY:
	case IOCTL_DISK_IS_WRITABLE:
		Status = STATUS_SUCCESS;
		break;
	}
	//完成请求
	WdfRequestCompleteWithInformation(Request, Status, information);
}

VOID
RamDiskEvtIoRead(
	IN WDFQUEUE Queue,
	IN WDFREQUEST Request,
	IN size_t Length
)
{
	//通过队列获取设备扩展
	PDEVICE_EXTENSION      devExt = QueueGetExtension(Queue)->DeviceExtension;
	NTSTATUS               Status = STATUS_INVALID_PARAMETER;
	WDF_REQUEST_PARAMETERS Parameters;//用于获取请求参数的变量
	LARGE_INTEGER          ByteOffset;//用于获取起始地址变量
	WDFMEMORY              hMemory;//缓冲区内存句柄
	//初始化参数变量
	WDF_REQUEST_PARAMETERS_INIT(&Parameters);
	//从请求参数中获取信息
	WdfRequestGetParameters(Request, &Parameters);
	//从请求参数中读出起始位置
	ByteOffset.QuadPart = Parameters.Parameters.Read.DeviceOffset;
	//检查参数；由于读取范围不能超过磁盘镜像大小，且必须扇区对齐，所以需要检查，若失败则将请求以错误参数结果返回
	if (RamDiskCheckParameters(devExt, ByteOffset, Length)) {
		//从请求参数中读取缓冲区的内存句柄
		Status = WdfRequestRetrieveOutputMemory(Request, &hMemory);
		if (NT_SUCCESS(Status)) {
			//根据之前获取到的参数进行内存拷贝，填写读请求的缓冲区
			Status = WdfMemoryCopyFromBuffer(hMemory, // Destination
				0, // Offset into the destination
				devExt->DiskImage + ByteOffset.LowPart, // source
				Length);
		}
	}
	//完成这个请求，需要将读取长度作为返回信息
	WdfRequestCompleteWithInformation(Request, Status, (ULONG_PTR)Length);
}

VOID
RamDiskEvtIoWrite(
	IN WDFQUEUE Queue,
	IN WDFREQUEST Request,
	IN size_t Length
)
{
	//写和读基本一样
	PDEVICE_EXTENSION      devExt = QueueGetExtension(Queue)->DeviceExtension;
	NTSTATUS               Status = STATUS_INVALID_PARAMETER;
	WDF_REQUEST_PARAMETERS Parameters;
	LARGE_INTEGER          ByteOffset;
	WDFMEMORY              hMemory;

	WDF_REQUEST_PARAMETERS_INIT(&Parameters);

	WdfRequestGetParameters(Request, &Parameters);

	ByteOffset.QuadPart = Parameters.Parameters.Write.DeviceOffset;

	if (RamDiskCheckParameters(devExt, ByteOffset, Length)) {

		Status = WdfRequestRetrieveInputMemory(Request, &hMemory);
		if (NT_SUCCESS(Status)) {

			Status = WdfMemoryCopyToBuffer(hMemory, // Source
				0, // offset in Source memory where the copy has to start
				devExt->DiskImage + ByteOffset.LowPart, // destination
				Length);
		}

	}

	WdfRequestCompleteWithInformation(Request, Status, (ULONG_PTR)Length);
}

VOID
RamDiskQueryDiskRegParameters(
	__in PWSTR RegistryPath,
	__in PDISK_INFO DiskRegInfo
)

/*++

Routine Description:

	This routine is called from the DriverEntry to get the debug
	parameters from the registry. If the registry query fails, then
	default values are used.

Arguments:

	RegistryPath    - Points the service path to get the registry parameters

Return Value:

	None

--*/

{

	RTL_QUERY_REGISTRY_TABLE rtlQueryRegTbl[5 + 1];  // Need 1 for NULL
	NTSTATUS                 Status;
	DISK_INFO                defDiskRegInfo;

	PAGED_CODE();

	ASSERT(RegistryPath != NULL);

	// Set the default values

	defDiskRegInfo.DiskSize = DEFAULT_DISK_SIZE;
	defDiskRegInfo.RootDirEntries = DEFAULT_ROOT_DIR_ENTRIES;
	defDiskRegInfo.SectorsPerCluster = DEFAULT_SECTORS_PER_CLUSTER;

	RtlInitUnicodeString(&defDiskRegInfo.DriveLetter, DEFAULT_DRIVE_LETTER);

	RtlZeroMemory(rtlQueryRegTbl, sizeof(rtlQueryRegTbl));

	//
	// Setup the query table
	//

	rtlQueryRegTbl[0].Flags = RTL_QUERY_REGISTRY_SUBKEY;
	rtlQueryRegTbl[0].Name = L"Parameters";
	rtlQueryRegTbl[0].EntryContext = NULL;
	rtlQueryRegTbl[0].DefaultType = (ULONG_PTR)NULL;
	rtlQueryRegTbl[0].DefaultData = NULL;
	rtlQueryRegTbl[0].DefaultLength = (ULONG_PTR)NULL;

	//
	// Disk paramters
	//

	rtlQueryRegTbl[1].Flags = RTL_QUERY_REGISTRY_DIRECT;
	rtlQueryRegTbl[1].Name = L"DiskSize";
	rtlQueryRegTbl[1].EntryContext = &DiskRegInfo->DiskSize;
	rtlQueryRegTbl[1].DefaultType = REG_DWORD;
	rtlQueryRegTbl[1].DefaultData = &defDiskRegInfo.DiskSize;
	rtlQueryRegTbl[1].DefaultLength = sizeof(ULONG);

	rtlQueryRegTbl[2].Flags = RTL_QUERY_REGISTRY_DIRECT;
	rtlQueryRegTbl[2].Name = L"RootDirEntries";
	rtlQueryRegTbl[2].EntryContext = &DiskRegInfo->RootDirEntries;
	rtlQueryRegTbl[2].DefaultType = REG_DWORD;
	rtlQueryRegTbl[2].DefaultData = &defDiskRegInfo.RootDirEntries;
	rtlQueryRegTbl[2].DefaultLength = sizeof(ULONG);

	rtlQueryRegTbl[3].Flags = RTL_QUERY_REGISTRY_DIRECT;
	rtlQueryRegTbl[3].Name = L"SectorsPerCluster";
	rtlQueryRegTbl[3].EntryContext = &DiskRegInfo->SectorsPerCluster;
	rtlQueryRegTbl[3].DefaultType = REG_DWORD;
	rtlQueryRegTbl[3].DefaultData = &defDiskRegInfo.SectorsPerCluster;
	rtlQueryRegTbl[3].DefaultLength = sizeof(ULONG);

	rtlQueryRegTbl[4].Flags = RTL_QUERY_REGISTRY_DIRECT;
	rtlQueryRegTbl[4].Name = L"DriveLetter";
	rtlQueryRegTbl[4].EntryContext = &DiskRegInfo->DriveLetter;
	rtlQueryRegTbl[4].DefaultType = REG_SZ;
	rtlQueryRegTbl[4].DefaultData = defDiskRegInfo.DriveLetter.Buffer;
	rtlQueryRegTbl[4].DefaultLength = 0;


	Status = RtlQueryRegistryValues(
		RTL_REGISTRY_ABSOLUTE | RTL_REGISTRY_OPTIONAL,
		RegistryPath,
		rtlQueryRegTbl,
		NULL,
		NULL
	);

	if (NT_SUCCESS(Status) == FALSE) {

		DiskRegInfo->DiskSize = defDiskRegInfo.DiskSize;
		DiskRegInfo->RootDirEntries = defDiskRegInfo.RootDirEntries;
		DiskRegInfo->SectorsPerCluster = defDiskRegInfo.SectorsPerCluster;
		RtlCopyUnicodeString(&DiskRegInfo->DriveLetter, &defDiskRegInfo.DriveLetter);
	}

	KdPrint(("DiskSize          = 0x%lx\n", DiskRegInfo->DiskSize));
	KdPrint(("RootDirEntries    = 0x%lx\n", DiskRegInfo->RootDirEntries));
	KdPrint(("SectorsPerCluster = 0x%lx\n", DiskRegInfo->SectorsPerCluster));
	KdPrint(("DriveLetter       = %wZ\n", &(DiskRegInfo->DriveLetter)));

	return;
}


NTSTATUS
RamDiskFormatDisk(
	IN PDEVICE_EXTENSION devExt
)
/**
 * 格式化磁盘为FAT12/16
 *
 * 磁盘特性相关：
 * 扇区是读写的基本单位，硬盘物理设计上，一次最少读写一个扇区（一般为512字节）
 * 盘面上被分为多个同心圆，即多个磁道，每个磁道被划分为同样数目的扇区
 * 多个盘面相同位置的磁道组成了一个柱面，柱面越多磁道越细
 * 这些都属于物理结构
 *
 * 操作系统对磁盘管理是一种逻辑上的结构，通过文件系统来实现
 * 微软的文件系统包括：FAT12、FAT16、FAT32、NTFS等
 *
 * 在FAT12/16系统中：
 * MBR（主引导记录）位于整个磁盘的第一个扇区，大小为一个扇区大小
 * 起始处为一段程序，在BIOS代码执行到最后时，会将这段程序加载到内存中执行
 * 程序后面时一个硬盘分区表，记录分区信息
 * 本驱动例子只建立一个可用磁盘卷，并不要求引导，所以不存在MBR部分
 * DBR（操作系统引导记录）存在于MBR分区表中记录的起始位置指向的第一个扇区
 * 包含了有效的引导程序、厂商标志、描述数据区等
 * 最开始是一个跳转指令，跳转位置为引导程序处；厂商标志位OEM串；数据描述区称为BPB数据块，记录了分区的信息
 * 在文件系统驱动操作任何一个磁盘卷时，DBR信息将被读取
 * FAT（文件分配表）位于DBR之后，一式两份形式连续保存，是一个链表，每个表项编号都是一个簇
 * 第0和第1项时保留的，从第2项开始用来记录某个文件所在位置
 * FAT是多个链表集合体，其中每个链代表一个文件，链的起始点如何确定
 * 要用到根目录入口点，多个根目录入口点形成一个表，表紧跟FAT表存储，表的每一项代表根目录下的一个文件或目录，记录了很多信息
 */
{

	PBOOT_SECTOR bootSector = (PBOOT_SECTOR)devExt->DiskImage; //指向磁盘启动扇区的指针
	PUCHAR       firstFatSector;//指向第一个FAT表指针
	ULONG        rootDirEntries;//记录根目录入口点数量
	ULONG        sectorsPerCluster;//记录每个簇有多少扇区
	USHORT       fatType;        //FAT文件系统类型
	USHORT       fatEntries;     //记录FAT表里有多少表项
	USHORT       fatSectorCnt;   //也给FAT表需要占用多少扇区
	PDIR_ENTRY   rootDir;        //指向第一个根目录入口点

	PAGED_CODE();//确认可以存取分页内存
	ASSERT(sizeof(BOOT_SECTOR) == 512);//确认盘引导扇区大小为512
	ASSERT(devExt->DiskImage != NULL);//确认操作的磁盘镜像可用
	//用0填充磁盘，即清空
	RtlZeroMemory(devExt->DiskImage, devExt->DiskRegInfo.DiskSize);
	//定义磁盘属性
	devExt->DiskGeometry.BytesPerSector = 512;
	devExt->DiskGeometry.SectorsPerTrack = 32;     // Using Ramdisk value
	devExt->DiskGeometry.TracksPerCylinder = 2;    // Using Ramdisk value
	//计算柱面数
	devExt->DiskGeometry.Cylinders.QuadPart = devExt->DiskRegInfo.DiskSize / 512 / 32 / 2;
	//磁盘介质类型
	devExt->DiskGeometry.MediaType = RAMDISK_MEDIA_TYPE;

	KdPrint((
		"Cylinders: %ld\n TracksPerCylinder: %ld\n SectorsPerTrack: %ld\n BytesPerSector: %ld\n",
		devExt->DiskGeometry.Cylinders.QuadPart, devExt->DiskGeometry.TracksPerCylinder,
		devExt->DiskGeometry.SectorsPerTrack, devExt->DiskGeometry.BytesPerSector
		));
	//根据用户指定的值对根目录项的数目进行初始化
	rootDirEntries = devExt->DiskRegInfo.RootDirEntries;
	//根据用户指定的值对每个簇有多少个扇区进行初始化
	sectorsPerCluster = devExt->DiskRegInfo.SectorsPerCluster;
	//根目录入口点只是用32各字节，但最少占用一个扇区
	if (rootDirEntries & (DIR_ENTRIES_PER_SECTOR - 1)) {
		//用户指定数目不合适时修正，使扇区空间充分利用
		rootDirEntries =
			(rootDirEntries + (DIR_ENTRIES_PER_SECTOR - 1)) &
			~(DIR_ENTRIES_PER_SECTOR - 1);
	}

	KdPrint((
		"Root dir entries: %ld\n Sectors/cluster: %ld\n",
		rootDirEntries, sectorsPerCluster
		));
	//对开始的跳转指令成员填入硬编码指令
	bootSector->bsJump[0] = 0xeb;
	bootSector->bsJump[1] = 0x3c;
	bootSector->bsJump[2] = 0x90;
	//OEM成员名称
	bootSector->bsOemName[0] = 'R';
	bootSector->bsOemName[1] = 'a';
	bootSector->bsOemName[2] = 'j';
	bootSector->bsOemName[3] = 'u';
	bootSector->bsOemName[4] = 'R';
	bootSector->bsOemName[5] = 'a';
	bootSector->bsOemName[6] = 'm';
	bootSector->bsOemName[7] = ' ';
	//每个扇区多少个字节，取自初始化的磁盘信息数据结构
	bootSector->bsBytesPerSec = (SHORT)devExt->DiskGeometry.BytesPerSector;
	bootSector->bsResSectors = 1;//只有一个保留扇区，即DBR本身
	bootSector->bsFATs = 1;//只存放一份FAT表
	bootSector->bsRootDirEnts = (USHORT)rootDirEntries;//程序入口点，由之前的计算得出
	//磁盘总扇区数由磁盘大小和每个扇区大小计算得到
	bootSector->bsSectors = (USHORT)(devExt->DiskRegInfo.DiskSize /
		devExt->DiskGeometry.BytesPerSector);
	bootSector->bsMedia = (UCHAR)devExt->DiskGeometry.MediaType;//介质类型由初始化信息得到
	bootSector->bsSecPerClus = (UCHAR)sectorsPerCluster;//每个簇的扇区数，由之前计算得到
	//FAT表的表项数目使总扇区减去保留扇区数，再减去根目录入口点所占用的扇区数，之后除以每簇扇区数，最终结果+2是由于第0和第1项保留
	fatEntries =
		(bootSector->bsSectors - bootSector->bsResSectors -
			bootSector->bsRootDirEnts / DIR_ENTRIES_PER_SECTOR) /
		bootSector->bsSecPerClus + 2;
	//表项数目决定了文件系统类型
	if (fatEntries > 4087) {
		fatType = 16;
		//修正
		fatSectorCnt = (fatEntries * 2 + 511) / 512;
		fatEntries = fatEntries + fatSectorCnt;
		fatSectorCnt = (fatEntries * 2 + 511) / 512;
	}
	else {
		fatType = 12;
		fatSectorCnt = (((fatEntries * 3 + 1) / 2) + 511) / 512;
		fatEntries = fatEntries + fatSectorCnt;
		fatSectorCnt = (((fatEntries * 3 + 1) / 2) + 511) / 512;
	}
	//初始化FAT表所占分区数
	bootSector->bsFATsecs = fatSectorCnt;
	bootSector->bsSecPerTrack = (USHORT)devExt->DiskGeometry.SectorsPerTrack;//初始化DBR中每个磁道扇区数
	bootSector->bsHeads = (USHORT)devExt->DiskGeometry.TracksPerCylinder;//初始化磁头数
	bootSector->bsBootSignature = 0x29;//初始化启动签名
	bootSector->bsVolumeID = 0x12345678;//随便写一个卷ID
	//设置卷标
	bootSector->bsLabel[0] = 'R';
	bootSector->bsLabel[1] = 'a';
	bootSector->bsLabel[2] = 'm';
	bootSector->bsLabel[3] = 'D';
	bootSector->bsLabel[4] = 'i';
	bootSector->bsLabel[5] = 's';
	bootSector->bsLabel[6] = 'k';
	bootSector->bsLabel[7] = ' ';
	bootSector->bsLabel[8] = ' ';
	bootSector->bsLabel[9] = ' ';
	bootSector->bsLabel[10] = ' ';
	//根据之前计算结果填写文件系统类型
	bootSector->bsFileSystemType[0] = 'F';
	bootSector->bsFileSystemType[1] = 'A';
	bootSector->bsFileSystemType[2] = 'T';
	bootSector->bsFileSystemType[3] = '1';
	bootSector->bsFileSystemType[4] = '?';
	bootSector->bsFileSystemType[5] = ' ';
	bootSector->bsFileSystemType[6] = ' ';
	bootSector->bsFileSystemType[7] = ' ';
	bootSector->bsFileSystemType[4] = (fatType == 16) ? '6' : '2';
	//签署DBR最后标志位0x55AA
	bootSector->bsSig2[0] = 0x55;
	bootSector->bsSig2[1] = 0xAA;
	//定位到FAT表起始点，定位方式利用了DBR只有一个扇区这一条件
	firstFatSector = (PUCHAR)(bootSector + 1);
	//填写介质标识
	firstFatSector[0] = (UCHAR)devExt->DiskGeometry.MediaType;
	firstFatSector[1] = 0xFF;
	firstFatSector[2] = 0xFF;
	//如果是FAT16，每个表项为4字节
	if (fatType == 16) {
		firstFatSector[3] = 0xFF;
	}
	//入口点紧跟FAT表，所以容易定位
	rootDir = (PDIR_ENTRY)(bootSector + 1 + fatSectorCnt);
	//填入卷标
	rootDir->deName[0] = 'M';
	rootDir->deName[1] = 'S';
	rootDir->deName[2] = '-';
	rootDir->deName[3] = 'R';
	rootDir->deName[4] = 'A';
	rootDir->deName[5] = 'M';
	rootDir->deName[6] = 'D';
	rootDir->deName[7] = 'R';

	rootDir->deExtension[0] = 'I';
	rootDir->deExtension[1] = 'V';
	rootDir->deExtension[2] = 'E';
	//入口点属性设置为卷标属性
	rootDir->deAttributes = DIR_ATTR_VOLUME;
	//格式化完毕
	return STATUS_SUCCESS;
}

NTSTATUS
RamDiskEvtDeviceAdd(
	IN WDFDRIVER Driver, //WDF驱动对象
	IN PWDFDEVICE_INIT DeviceInit //WDF驱动模型自动分配的一个数据结构，专门传递给EvtDriverDeviceAdd函数用来建立新设备
)
{
	//该回调函数是用来在即插即用管理器发现新设备时对这个设备及逆行初始化操作的
	//任何支持PnP操作的驱动都应该有这样的函数（就是WDM驱动中AddDevice回调的翻版）
	//当DriverEntry执行完毕后，驱动基本就只依靠这个函数来与系统保持联系了

	//分解看下本例中此函数的工作

	//声明一些变量
	NTSTATUS status = STATUS_SUCCESS;
	WDF_OBJECT_ATTRIBUTES   deviceAttributes;//将要建立的设备对象的属性描述
	WDFDEVICE               device;//将要建立的设备
	WDF_OBJECT_ATTRIBUTES   queueAttributes;//队列属性描述变量
	WDF_IO_QUEUE_CONFIG     ioQueueConfig;//队列配置变量
	PDEVICE_EXTENSION       pDeviceExtension;//设备扩展域指针
	PQUEUE_EXTENSION        pQueueContext = NULL;//队列扩展域
	WDFQUEUE                queue;//将要建立的队列
	DECLARE_CONST_UNICODE_STRING(ntDeviceName, NT_DEVICE_NAME);//声明一个UNICODE_STRING变量并初始化
	//保证这个函数可以操作paged内存
	PAGED_CODE();	//#define PAGED_CODE() PAGED_ASSERT(KeGetCurrentIrql() <= APC_LEVEL);
	UNREFERENCED_PARAMETER(Driver);//对不使用的参数进行声明，避免编译警告

	//磁盘设备创建
	status = WdfDeviceInitAssignName(DeviceInit, &ntDeviceName);//为设备指定名称
	if (!NT_SUCCESS(status)) {
		return status;
	}
	//设置基本属性
	WdfDeviceInitSetDeviceType(DeviceInit, FILE_DEVICE_DISK);//磁盘设备类型
	WdfDeviceInitSetIoType(DeviceInit, WdfDeviceIoDirect);//在将读写和DeviceIoControl的IRP请求发送到这个设备时，IRP所携带的缓冲区可以被直接使用
	WdfDeviceInitSetExclusive(DeviceInit, FALSE);//表示设备可以多次打开
	//指定设备对象扩展
	WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&deviceAttributes, DEVICE_EXTENSION);
	//指定设备清楚回调函数
	deviceAttributes.EvtCleanupCallback = RamDiskEvtDeviceContextCleanup;
	//准备工作完成，创建设备，建立的设备通过第三个参数保存在变量中
	status = WdfDeviceCreate(&DeviceInit, &deviceAttributes, &device);
	if (!NT_SUCCESS(status)) {
		return status;
	}
	//保存新建立设备的设备扩展指针
	pDeviceExtension = DeviceGetExtension(device);

	//处理发往设备的请求
	//常用的方式是：将自己实现的回调函数，作为设备的功能分发函数；例如将读写请求都实现为读写内存，就是最简单的内存盘，一般需要建立队列
	//WDF框架中直接提供了这样的处理队列
	WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(
		&ioQueueConfig,
		WdfIoQueueDispatchSequential
	);//将队列配置变量初始化为默认值
	//将关心的三个请求改为自定义处理函数，其余使用默认值
	ioQueueConfig.EvtIoDeviceControl = RamDiskEvtIoDeviceControl;
	ioQueueConfig.EvtIoRead = RamDiskEvtIoRead;
	ioQueueConfig.EvtIoWrite = RamDiskEvtIoWrite;
	//指定队列对象扩展
	WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&queueAttributes, QUEUE_EXTENSION);
	//准备工作结束，创建队列对象，将之前创建的设备作为队列的父对象，设备销毁时队列也就销毁了
	status = WdfIoQueueCreate(device,
		&ioQueueConfig,
		&queueAttributes,
		&queue);
	if (!NT_SUCCESS(status)) {
		return status;
	}
	//保存刚生成的队列扩展
	pQueueContext = QueueGetExtension(queue);
	//初始化队列扩展中的DeviceExtension项为刚建立的设备的扩展，这样后续可以轻松获取队列对应的设备的设备扩展
	pQueueContext->DeviceExtension = pDeviceExtension;

	//用户配置初始化
	//设备和用来处理设备的队列都建立好了，接下来初始化与内存盘相关的数据结构
	//将生成设备的设备扩展中相应的UNICODE_STRING初始化
	pDeviceExtension->DiskRegInfo.DriveLetter.Buffer =
		(PWSTR)&pDeviceExtension->DriveLetterBuffer;
	pDeviceExtension->DiskRegInfo.DriveLetter.MaximumLength =
		sizeof(pDeviceExtension->DriveLetterBuffer);
	//从系统为本驱动提供的注册表键中获取我们需要的信息
	RamDiskQueryDiskRegParameters(
		WdfDriverGetRegistryPath(WdfDeviceGetDriver(device)), //获取驱动对象并获取注册表路径
		&pDeviceExtension->DiskRegInfo	//向该变量中填写需要的值
	);
	//获取参数后，分配一定大小的内存来作为模拟磁盘，大小由注册表中的磁盘大小参数指定，这块空间被称为磁盘镜像
	pDeviceExtension->DiskImage = ExAllocatePoolWithTag(
		NonPagedPool, //非分页内存，永远在内存中，不会被换到磁盘上，所以可分配的较少
		pDeviceExtension->DiskRegInfo.DiskSize,
		RAMDISK_TAG
	);
	//分配内存成功之后，磁盘就有了空间，但还没有分区、格式化等操作
	if (pDeviceExtension->DiskImage) {

		UNICODE_STRING deviceName;
		UNICODE_STRING win32Name;
		//将内存介质的磁盘格式化
		RamDiskFormatDisk(pDeviceExtension);
		//接下来需要将磁盘暴露给应用层以供使用
		status = STATUS_SUCCESS;
		//初始化一些所需的字符变量
		RtlInitUnicodeString(&win32Name, DOS_DEVICE_NAME);
		RtlInitUnicodeString(&deviceName, NT_DEVICE_NAME);
		//准备好用来存储符号链接名的变量
		pDeviceExtension->SymbolicLink.Buffer = (PWSTR)
			&pDeviceExtension->DosDeviceNameBuffer;
		pDeviceExtension->SymbolicLink.MaximumLength =
			sizeof(pDeviceExtension->DosDeviceNameBuffer);
		pDeviceExtension->SymbolicLink.Length = win32Name.Length;
		//将符号链接名开头设置为“\\DosDevices\\”，这是所有符号链接共有的前缀
		RtlCopyUnicodeString(&pDeviceExtension->SymbolicLink, &win32Name);
		RtlAppendUnicodeStringToString(&pDeviceExtension->SymbolicLink,
			&pDeviceExtension->DiskRegInfo.DriveLetter);//拼接从用户配置中读出来的指定盘符
		//调用WDF模型提供的函数来为之前生成的设备建立符号链接
		status = WdfDeviceCreateSymbolicLink(device,
			&pDeviceExtension->SymbolicLink);
	}
	//至此，磁盘设备已经建立，并链接到了应用层
	return status;
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObject, IN PUNICODE_STRING pRegistryPath)
{
	//驱动程序的可配置项，一般包括EvtDriverDeviceAdd和EvtDriverUnload回调函数的入口地址、驱动初始化时的标志和分配内存是使用的tag值
	WDF_DRIVER_CONFIG config;

	KdPrint(("Windows Ramdisk Driver - Driver Framework Edition.\n"));
	KdPrint(("Built %s %s\n", __DATE__, __TIME__));

	//初始化配置时，会将用户自定义的EvtDriverDeviceAdd回调函数存入其中，并初始化其他部分
	WDF_DRIVER_CONFIG_INIT(&config, RamDiskEvtDeviceAdd);

	//对原本驱动开发的一次包装，根据参数对环境进行初始化工作，并建立驱动对象
	return WdfDriverCreate(
		pDriverObject,	//入口函数的两个参数
		pRegistryPath,
		WDF_NO_OBJECT_ATTRIBUTES, //表示不需要特殊属性
		&config,
		WDF_NO_HANDLE	//作为函数的输出结果，即WDF驱动的驱动对象
	);//至此将config与驱动挂钩，运行过程中，PnP管理器就会根据需要调用回调函数
}

/**
 * 编译后安装：
 * 需要生成产物sys文件以及inf文件，还有WDK安装目录/redist/wdf下面的WdfCoInstaller01007.dll
 * 控制面板中找到添加硬件，手动从磁盘安装，选择inf文件，重启后会出现一个盘
 *
 * 安装向导读取inf文件后，sys文件会被拷贝到System32/drivers目录下
 * 并且会在注册表中新建一些项
 * （1）“\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\Root\UNKNOWN”。
 * 这是在安装之后新增加的一个键，在这之下还有一个叫作0000的子键，
 * 可以在管理员用户下用regedit命令查看这个键的内容。
 * 在Windows系统启动时，PnP管理器会枚举“\HKEY_ LOCAL_MACHINE\SYSTEM\CurrentControlSet\ Enum\Root\”下的所有键，
 * 并会根据键中的信息为每个设备创建一个PDO（物理设备对象）。
 * 在“\HKEY_LOCAL_MACHINE\SYSTEM\ CurrentControlSet\Enum\ Root\”下的所有键代表了在系统安装时记录的或者通过添加硬件向导添加的一个硬件信息，
 * Windows虚拟了一条根总线并且把这些硬件挂接在上面。PnP管理器完成PDO的建立之后会进行标准的PnP操作，
 * 与PDO相对应的驱动将会被加载。在“\HKEY_LOCAL_ MACHINE\SYSTEM\CurrentControlSet\Enum\Root\ UNKNOWN\0000”键下可以看到和Ramdisk相关的信息，
 * 其中有一个值是Service，系统将会寻找这个值指明的驱动，进行加载和调用。另外，在这个键下面还有一个值是ClassGUID，
 * 这个值的内容将作为这一类驱动的索引。
 * （2）“\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Ramdisk”。
 * 系统会去加载Service所指明的驱动，
 * 而在“\HKEY_LOCAL_MACHINE\SYSTEM\ CurrentControlSet\Enum\Root\UNKNOWN\0000”中的Service值的内容正是Ramdisk，
 * 于是系统就会在“\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\”下面寻找这个叫作Ramdisk的服务，
 * 并根据它的内容去最终加载驱动程序本身。
 * “\HKEY_LOCAL_MACHINE\ SYSTEM\CurrentControlSet\Services\Ramdisk”是一个标准的服务描述键，
 * 这个键最重要的一点就是指明了ramdisk.sys文件的位置。
 * （3）“\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\ClassGUID”。
 * 注意这个键最后的ClassGUID实际上是一长串数字，数字的内容在“\HKEY_LOCAL_ MACHINE\SYSTEM\CurrentControlSet\Enum\Root\UNKNOWN\0000”键的ClassGUID值中。
 * 这个键说明了具有同样Class的驱动所通用的一些信息，在Ramdisk驱动中这个键没有太大的用处，
 * 但是在其他的驱动如类过滤驱动等驱动程序中，这个键却起着非常重要的作用。
 */