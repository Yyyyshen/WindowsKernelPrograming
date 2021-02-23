
#include <fltKernel.h>
#include <dontuse.h>

/**
 * 文件系统微过滤驱动
 *
 * 以sfilter为代表的传统文件过滤驱动十分复杂，接口不够清晰
 * 微软为此开发了新的框架，过滤管理器（fltmgr），但目前市场上的安全技术需求越来越底层，封装更好的上层使用方便但可能无法满足需要
 *
 * 优点是基本的IRP处理都交给了管理器，开发者可以专心功能的实现，提高效率，降低错误，兼容性也更好
 * 不足是只使用Minifilter推荐接口，开发者看不到设备对象、IRP这些内核结构
 *
 * 在另一个repo中已经学习过，再过一下概念，不编写具体代码了
 */

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")


PFLT_FILTER gFilterHandle;
ULONG_PTR OperationStatusCtx = 1;

#define PTDBG_TRACE_ROUTINES            0x00000001
#define PTDBG_TRACE_OPERATION_STATUS    0x00000002

ULONG gTraceFlags = 0;


#define PT_DBG_PRINT( _dbgLevel, _string )          \
    (FlagOn(gTraceFlags,(_dbgLevel)) ?              \
        DbgPrint _string :                          \
        ((int)0))

/*************************************************************************
	Prototypes
*************************************************************************/

EXTERN_C_START

DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
);

NTSTATUS
MiniFilterDriverInstanceSetup(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_SETUP_FLAGS Flags,
	_In_ DEVICE_TYPE VolumeDeviceType,
	_In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
);

VOID
MiniFilterDriverInstanceTeardownStart(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
);

VOID
MiniFilterDriverInstanceTeardownComplete(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
);

NTSTATUS
MiniFilterDriverUnload(
	_In_ FLT_FILTER_UNLOAD_FLAGS Flags
);

NTSTATUS
MiniFilterDriverInstanceQueryTeardown(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
);

FLT_PREOP_CALLBACK_STATUS
MiniFilterDriverPreOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
);

VOID
MiniFilterDriverOperationStatusCallback(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
	_In_ NTSTATUS OperationStatus,
	_In_ PVOID RequesterContext
);

FLT_POSTOP_CALLBACK_STATUS
MiniFilterDriverPostOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
);

FLT_PREOP_CALLBACK_STATUS
MiniFilterDriverPreOperationNoPostOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
);

BOOLEAN
MiniFilterDriverDoRequestOperationStatus(
	_In_ PFLT_CALLBACK_DATA Data
);

EXTERN_C_END

//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, MiniFilterDriverUnload)
#pragma alloc_text(PAGE, MiniFilterDriverInstanceQueryTeardown)
#pragma alloc_text(PAGE, MiniFilterDriverInstanceSetup)
#pragma alloc_text(PAGE, MiniFilterDriverInstanceTeardownStart)
#pragma alloc_text(PAGE, MiniFilterDriverInstanceTeardownComplete)
#endif

//
//  operation registration
//

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {

#if 0 // TODO - List all of the requests to filter.
	{ IRP_MJ_CREATE,
	  0,
	  MiniFilterDriverPreOperation,
	  MiniFilterDriverPostOperation },

	{ IRP_MJ_CREATE_NAMED_PIPE,
	  0,
	  MiniFilterDriverPreOperation,
	  MiniFilterDriverPostOperation },

	{ IRP_MJ_CLOSE,
	  0,
	  MiniFilterDriverPreOperation,
	  MiniFilterDriverPostOperation },

	{ IRP_MJ_READ,
	  0,
	  MiniFilterDriverPreOperation,
	  MiniFilterDriverPostOperation },

	{ IRP_MJ_WRITE,
	  0,
	  MiniFilterDriverPreOperation,
	  MiniFilterDriverPostOperation },

	{ IRP_MJ_QUERY_INFORMATION,
	  0,
	  MiniFilterDriverPreOperation,
	  MiniFilterDriverPostOperation },

	{ IRP_MJ_SET_INFORMATION,
	  0,
	  MiniFilterDriverPreOperation,
	  MiniFilterDriverPostOperation },

	{ IRP_MJ_QUERY_EA,
	  0,
	  MiniFilterDriverPreOperation,
	  MiniFilterDriverPostOperation },

	{ IRP_MJ_SET_EA,
	  0,
	  MiniFilterDriverPreOperation,
	  MiniFilterDriverPostOperation },

	{ IRP_MJ_FLUSH_BUFFERS,
	  0,
	  MiniFilterDriverPreOperation,
	  MiniFilterDriverPostOperation },

	{ IRP_MJ_QUERY_VOLUME_INFORMATION,
	  0,
	  MiniFilterDriverPreOperation,
	  MiniFilterDriverPostOperation },

	{ IRP_MJ_SET_VOLUME_INFORMATION,
	  0,
	  MiniFilterDriverPreOperation,
	  MiniFilterDriverPostOperation },

	{ IRP_MJ_DIRECTORY_CONTROL,
	  0,
	  MiniFilterDriverPreOperation,
	  MiniFilterDriverPostOperation },

	{ IRP_MJ_FILE_SYSTEM_CONTROL,
	  0,
	  MiniFilterDriverPreOperation,
	  MiniFilterDriverPostOperation },

	{ IRP_MJ_DEVICE_CONTROL,
	  0,
	  MiniFilterDriverPreOperation,
	  MiniFilterDriverPostOperation },

	{ IRP_MJ_INTERNAL_DEVICE_CONTROL,
	  0,
	  MiniFilterDriverPreOperation,
	  MiniFilterDriverPostOperation },

	{ IRP_MJ_SHUTDOWN,
	  0,
	  MiniFilterDriverPreOperationNoPostOperation,
	  NULL },                               //post operations not supported

	{ IRP_MJ_LOCK_CONTROL,
	  0,
	  MiniFilterDriverPreOperation,
	  MiniFilterDriverPostOperation },

	{ IRP_MJ_CLEANUP,
	  0,
	  MiniFilterDriverPreOperation,
	  MiniFilterDriverPostOperation },

	{ IRP_MJ_CREATE_MAILSLOT,
	  0,
	  MiniFilterDriverPreOperation,
	  MiniFilterDriverPostOperation },

	{ IRP_MJ_QUERY_SECURITY,
	  0,
	  MiniFilterDriverPreOperation,
	  MiniFilterDriverPostOperation },

	{ IRP_MJ_SET_SECURITY,
	  0,
	  MiniFilterDriverPreOperation,
	  MiniFilterDriverPostOperation },

	{ IRP_MJ_QUERY_QUOTA,
	  0,
	  MiniFilterDriverPreOperation,
	  MiniFilterDriverPostOperation },

	{ IRP_MJ_SET_QUOTA,
	  0,
	  MiniFilterDriverPreOperation,
	  MiniFilterDriverPostOperation },

	{ IRP_MJ_PNP,
	  0,
	  MiniFilterDriverPreOperation,
	  MiniFilterDriverPostOperation },

	{ IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION,
	  0,
	  MiniFilterDriverPreOperation,
	  MiniFilterDriverPostOperation },

	{ IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION,
	  0,
	  MiniFilterDriverPreOperation,
	  MiniFilterDriverPostOperation },

	{ IRP_MJ_ACQUIRE_FOR_MOD_WRITE,
	  0,
	  MiniFilterDriverPreOperation,
	  MiniFilterDriverPostOperation },

	{ IRP_MJ_RELEASE_FOR_MOD_WRITE,
	  0,
	  MiniFilterDriverPreOperation,
	  MiniFilterDriverPostOperation },

	{ IRP_MJ_ACQUIRE_FOR_CC_FLUSH,
	  0,
	  MiniFilterDriverPreOperation,
	  MiniFilterDriverPostOperation },

	{ IRP_MJ_RELEASE_FOR_CC_FLUSH,
	  0,
	  MiniFilterDriverPreOperation,
	  MiniFilterDriverPostOperation },

	{ IRP_MJ_FAST_IO_CHECK_IF_POSSIBLE,
	  0,
	  MiniFilterDriverPreOperation,
	  MiniFilterDriverPostOperation },

	{ IRP_MJ_NETWORK_QUERY_OPEN,
	  0,
	  MiniFilterDriverPreOperation,
	  MiniFilterDriverPostOperation },

	{ IRP_MJ_MDL_READ,
	  0,
	  MiniFilterDriverPreOperation,
	  MiniFilterDriverPostOperation },

	{ IRP_MJ_MDL_READ_COMPLETE,
	  0,
	  MiniFilterDriverPreOperation,
	  MiniFilterDriverPostOperation },

	{ IRP_MJ_PREPARE_MDL_WRITE,
	  0,
	  MiniFilterDriverPreOperation,
	  MiniFilterDriverPostOperation },

	{ IRP_MJ_MDL_WRITE_COMPLETE,
	  0,
	  MiniFilterDriverPreOperation,
	  MiniFilterDriverPostOperation },

	{ IRP_MJ_VOLUME_MOUNT,
	  0,
	  MiniFilterDriverPreOperation,
	  MiniFilterDriverPostOperation },

	{ IRP_MJ_VOLUME_DISMOUNT,
	  0,
	  MiniFilterDriverPreOperation,
	  MiniFilterDriverPostOperation },

#endif // TODO

	{ IRP_MJ_OPERATION_END }
};

//注册的过滤管理器
CONST FLT_REGISTRATION FilterRegistration = {

	sizeof(FLT_REGISTRATION),         //  Size
	FLT_REGISTRATION_VERSION,           //  Version
	0,                                  //  Flags

	NULL,                               //  Context
	Callbacks,                          // 回调函数数组，可以处理所有请求，操作前后两种函数被分为Pre和Post两种回调函数

	MiniFilterDriverUnload,                           //  MiniFilterUnload

	MiniFilterDriverInstanceSetup,                    //  InstanceSetup
	MiniFilterDriverInstanceQueryTeardown,            //  InstanceQueryTeardown
	MiniFilterDriverInstanceTeardownStart,            //  InstanceTeardownStart
	MiniFilterDriverInstanceTeardownComplete,         //  InstanceTeardownComplete

	NULL,                               //  GenerateFileName
	NULL,                               //  GenerateDestinationFileName
	NULL                                //  NormalizeNameComponent

};



NTSTATUS
MiniFilterDriverInstanceSetup(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_SETUP_FLAGS Flags,
	_In_ DEVICE_TYPE VolumeDeviceType,
	_In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
)
/*++

Routine Description:

	This routine is called whenever a new instance is created on a volume. This
	gives us a chance to decide if we need to attach to this volume or not.

	If this routine is not defined in the registration structure, automatic
	instances are always created.

Arguments:

	FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
		opaque handles to this filter, instance and its associated volume.

	Flags - Flags describing the reason for this attach request.

Return Value:

	STATUS_SUCCESS - attach
	STATUS_FLT_DO_NOT_ATTACH - do not attach

--*/
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);
	UNREFERENCED_PARAMETER(VolumeDeviceType);
	UNREFERENCED_PARAMETER(VolumeFilesystemType);

	PAGED_CODE();

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("MiniFilterDriver!MiniFilterDriverInstanceSetup: Entered\n"));

	return STATUS_SUCCESS;
}


NTSTATUS
MiniFilterDriverInstanceQueryTeardown(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
)
/*++

Routine Description:

	This is called when an instance is being manually deleted by a
	call to FltDetachVolume or FilterDetach thereby giving us a
	chance to fail that detach request.

	If this routine is not defined in the registration structure, explicit
	detach requests via FltDetachVolume or FilterDetach will always be
	failed.

Arguments:

	FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
		opaque handles to this filter, instance and its associated volume.

	Flags - Indicating where this detach request came from.

Return Value:

	Returns the status of this operation.

--*/
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);

	PAGED_CODE();

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("MiniFilterDriver!MiniFilterDriverInstanceQueryTeardown: Entered\n"));

	return STATUS_SUCCESS;
}


VOID
MiniFilterDriverInstanceTeardownStart(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
)
/*++

Routine Description:

	This routine is called at the start of instance teardown.

Arguments:

	FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
		opaque handles to this filter, instance and its associated volume.

	Flags - Reason why this instance is being deleted.

Return Value:

	None.

--*/
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);

	PAGED_CODE();

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("MiniFilterDriver!MiniFilterDriverInstanceTeardownStart: Entered\n"));
}


VOID
MiniFilterDriverInstanceTeardownComplete(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
)
/*++

Routine Description:

	This routine is called at the end of instance teardown.

Arguments:

	FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
		opaque handles to this filter, instance and its associated volume.

	Flags - Reason why this instance is being deleted.

Return Value:

	None.

--*/
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);

	PAGED_CODE();

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("MiniFilterDriver!MiniFilterDriverInstanceTeardownComplete: Entered\n"));
}


/*************************************************************************
	MiniFilter initialization and unload routines.
*************************************************************************/
//与应用程序的通信端口使用的相关参数及回调
#define MINISPY_PORT_NAME								L"\\NPMiniPort"
PFLT_PORT 	gServerPort;
PFLT_PORT 	gClientPort;
//  Defines the commands between the utility and the filter
typedef enum _NPMINI_COMMAND {
	ENUM_PASS = 0,
	ENUM_BLOCK
} NPMINI_COMMAND;

//  Defines the command structure between the utility and the filter.
typedef struct _COMMAND_MESSAGE {
	NPMINI_COMMAND 	Command;
} COMMAND_MESSAGE, * PCOMMAND_MESSAGE;
NPMINI_COMMAND gCommand = ENUM_PASS;
NTSTATUS
NPMiniConnect(
	__in PFLT_PORT ClientPort,
	__in PVOID ServerPortCookie,
	__in_bcount(SizeOfContext) PVOID ConnectionContext,
	__in ULONG SizeOfContext,
	__deref_out_opt PVOID* ConnectionCookie
)
{
	DbgPrint("[mini-filter] NPMiniConnect");
	PAGED_CODE();

	UNREFERENCED_PARAMETER(ServerPortCookie);
	UNREFERENCED_PARAMETER(ConnectionContext);
	UNREFERENCED_PARAMETER(SizeOfContext);
	UNREFERENCED_PARAMETER(ConnectionCookie);

	ASSERT(gClientPort == NULL);
	gClientPort = ClientPort;
	return STATUS_SUCCESS;
}

//與user application Disconect
VOID
NPMiniDisconnect(
	__in_opt PVOID ConnectionCookie
)
{
	PAGED_CODE();
	UNREFERENCED_PARAMETER(ConnectionCookie);
	DbgPrint("[mini-filter] NPMiniDisconnect");

	//  Close our handle
	FltCloseClientPort(gFilterHandle, &gClientPort);
}

NTSTATUS
NPMiniMessage(
	__in PVOID ConnectionCookie,
	__in_bcount_opt(InputBufferSize) PVOID InputBuffer,
	__in ULONG InputBufferSize,
	__out_bcount_part_opt(OutputBufferSize, *ReturnOutputBufferLength) PVOID OutputBuffer,
	__in ULONG OutputBufferSize,
	__out PULONG ReturnOutputBufferLength
)
{

	NPMINI_COMMAND command;
	NTSTATUS status;

	PAGED_CODE();

	UNREFERENCED_PARAMETER(ConnectionCookie);
	UNREFERENCED_PARAMETER(OutputBufferSize);
	UNREFERENCED_PARAMETER(OutputBuffer);

	DbgPrint("[mini-filter] NPMiniMessage");

	//                      **** PLEASE READ ****    
	//  The INPUT and OUTPUT buffers are raw user mode addresses.  The filter
	//  manager has already done a ProbedForRead (on InputBuffer) and
	//  ProbedForWrite (on OutputBuffer) which guarentees they are valid
	//  addresses based on the access (user mode vs. kernel mode).  The
	//  minifilter does not need to do their own probe.
	//  The filter manager is NOT doing any alignment checking on the pointers.
	//  The minifilter must do this themselves if they care (see below).
	//  The minifilter MUST continue to use a try/except around any access to
	//  these buffers.    

	if ((InputBuffer != NULL) &&
		(InputBufferSize >= (FIELD_OFFSET(COMMAND_MESSAGE, Command) +
			sizeof(NPMINI_COMMAND)))) {

		try {
			//  Probe and capture input message: the message is raw user mode
			//  buffer, so need to protect with exception handler
			command = ((PCOMMAND_MESSAGE)InputBuffer)->Command;

		} except(EXCEPTION_EXECUTE_HANDLER) {

			return GetExceptionCode();
		}

		switch (command) {
			//開放規則
		case ENUM_PASS:
		{
			DbgPrint("[mini-filter] ENUM_PASS");
			gCommand = ENUM_PASS;
			status = STATUS_SUCCESS;
			break;
		}
		//阻擋規則
		case ENUM_BLOCK:
		{
			DbgPrint("[mini-filter] ENUM_BLOCK");
			gCommand = ENUM_BLOCK;
			status = STATUS_SUCCESS;
			break;
		}

		default:
			DbgPrint("[mini-filter] default");
			status = STATUS_INVALID_PARAMETER;
			break;
		}
	}
	else {

		status = STATUS_INVALID_PARAMETER;
	}

	return status;
}
NTSTATUS
DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
)
/*++

Routine Description:

	This is the initialization routine for this miniFilter driver.  This
	registers with FltMgr and initializes all global data structures.

Arguments:

	DriverObject - Pointer to driver object created by the system to
		represent this driver.

	RegistryPath - Unicode string identifying where the parameters for this
		driver are located in the registry.

Return Value:

	Routine can return non success error codes.

--*/
{
	NTSTATUS status;

	UNREFERENCED_PARAMETER(RegistryPath);

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("MiniFilterDriver!DriverEntry: Entered\n"));

	//向过滤管理器注册一个过滤器，使用FilterRegistration表示的
	status = FltRegisterFilter(DriverObject,
		&FilterRegistration,
		&gFilterHandle);

	FLT_ASSERT(NT_SUCCESS(status));

	if (NT_SUCCESS(status)) {
		//开始过滤行为
		status = FltStartFiltering(gFilterHandle);

		if (!NT_SUCCESS(status)) {

			FltUnregisterFilter(gFilterHandle);
		}
	}

	//提供与用户层的通信端口
	PSECURITY_DESCRIPTOR sd;
	OBJECT_ATTRIBUTES oa;
	UNICODE_STRING uniString;

	status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);

	if (!NT_SUCCESS(status)) {
		goto final;
	}


	status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);

	if (!NT_SUCCESS(status)) {
		goto final;
	}


	RtlInitUnicodeString(&uniString, MINISPY_PORT_NAME);

	InitializeObjectAttributes(&oa,
		&uniString,
		OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
		NULL,
		sd);

	status = FltCreateCommunicationPort(gFilterHandle,
		&gServerPort,
		&oa,
		NULL,
		NPMiniConnect,
		NPMiniDisconnect,
		NPMiniMessage,
		1);

	FltFreeSecurityDescriptor(sd);

	if (!NT_SUCCESS(status)) {
		goto final;
	}

	final :

	if (!NT_SUCCESS(status)) {

		if (NULL != gServerPort) {
			FltCloseCommunicationPort(gServerPort);
		}

		if (NULL != gFilterHandle) {
			FltUnregisterFilter(gFilterHandle);
		}
	}

	return status;
}

NTSTATUS
MiniFilterDriverUnload(
	_In_ FLT_FILTER_UNLOAD_FLAGS Flags
)
/*++

Routine Description:

	This is the unload routine for this miniFilter driver. This is called
	when the minifilter is about to be unloaded. We can fail this unload
	request if this is not a mandatory unload indicated by the Flags
	parameter.

Arguments:

	Flags - Indicating if this is a mandatory unload.

Return Value:

	Returns STATUS_SUCCESS.

--*/
{
	UNREFERENCED_PARAMETER(Flags);

	PAGED_CODE();

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("MiniFilterDriver!MiniFilterDriverUnload: Entered\n"));

	FltUnregisterFilter(gFilterHandle);

	return STATUS_SUCCESS;
}


/*************************************************************************
	MiniFilter callback routines.
*************************************************************************/
FLT_PREOP_CALLBACK_STATUS
MiniFilterDriverPreOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
/*++

Routine Description:

	This routine is a pre-operation dispatch routine for this miniFilter.

	This is non-pageable because it could be called on the paging path

Arguments:

	Data - Pointer to the filter callbackData that is passed to us.

	FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
		opaque handles to this filter, instance, its associated volume and
		file object.

	CompletionContext - The context for the completion routine for this
		operation.

Return Value:

	The return value is the status of the operation.

--*/
{
	NTSTATUS status;

	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("MiniFilterDriver!MiniFilterDriverPreOperation: Entered\n"));

	//
	//  See if this is an operation we would like the operation status
	//  for.  If so request it.
	//
	//  NOTE: most filters do NOT need to do this.  You only need to make
	//        this call if, for example, you need to know if the oplock was
	//        actually granted.
	//

	if (MiniFilterDriverDoRequestOperationStatus(Data)) {

		status = FltRequestOperationStatusCallback(Data,
			MiniFilterDriverOperationStatusCallback,
			(PVOID)(++OperationStatusCtx));
		if (!NT_SUCCESS(status)) {

			PT_DBG_PRINT(PTDBG_TRACE_OPERATION_STATUS,
				("MiniFilterDriver!MiniFilterDriverPreOperation: FltRequestOperationStatusCallback Failed, status=%08x\n",
					status));
		}
	}

	// This template code does not do anything with the callbackData, but
	// rather returns FLT_PREOP_SUCCESS_WITH_CALLBACK.
	// This passes the request down to the next miniFilter in the chain.

	return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}



VOID
MiniFilterDriverOperationStatusCallback(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
	_In_ NTSTATUS OperationStatus,
	_In_ PVOID RequesterContext
)
/*++

Routine Description:

	This routine is called when the given operation returns from the call
	to IoCallDriver.  This is useful for operations where STATUS_PENDING
	means the operation was successfully queued.  This is useful for OpLocks
	and directory change notification operations.

	This callback is called in the context of the originating thread and will
	never be called at DPC level.  The file object has been correctly
	referenced so that you can access it.  It will be automatically
	dereferenced upon return.

	This is non-pageable because it could be called on the paging path

Arguments:

	FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
		opaque handles to this filter, instance, its associated volume and
		file object.

	RequesterContext - The context for the completion routine for this
		operation.

	OperationStatus -

Return Value:

	The return value is the status of the operation.

--*/
{
	UNREFERENCED_PARAMETER(FltObjects);

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("MiniFilterDriver!MiniFilterDriverOperationStatusCallback: Entered\n"));

	PT_DBG_PRINT(PTDBG_TRACE_OPERATION_STATUS,
		("MiniFilterDriver!MiniFilterDriverOperationStatusCallback: Status=%08x ctx=%p IrpMj=%02x.%02x \"%s\"\n",
			OperationStatus,
			RequesterContext,
			ParameterSnapshot->MajorFunction,
			ParameterSnapshot->MinorFunction,
			FltGetIrpName(ParameterSnapshot->MajorFunction)));
}


FLT_POSTOP_CALLBACK_STATUS
MiniFilterDriverPostOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
)
/*++

Routine Description:

	This routine is the post-operation completion routine for this
	miniFilter.

	This is non-pageable because it may be called at DPC level.

Arguments:

	Data - Pointer to the filter callbackData that is passed to us.

	FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
		opaque handles to this filter, instance, its associated volume and
		file object.

	CompletionContext - The completion context set in the pre-operation routine.

	Flags - Denotes whether the completion is successful or is being drained.

Return Value:

	The return value is the status of the operation.

--*/
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("MiniFilterDriver!MiniFilterDriverPostOperation: Entered\n"));

	return FLT_POSTOP_FINISHED_PROCESSING;
}


FLT_PREOP_CALLBACK_STATUS
MiniFilterDriverPreOperationNoPostOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
/*++

Routine Description:

	This routine is a pre-operation dispatch routine for this miniFilter.

	This is non-pageable because it could be called on the paging path

Arguments:

	Data - Pointer to the filter callbackData that is passed to us.

	FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
		opaque handles to this filter, instance, its associated volume and
		file object.

	CompletionContext - The context for the completion routine for this
		operation.

Return Value:

	The return value is the status of the operation.

--*/
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("MiniFilterDriver!MiniFilterDriverPreOperationNoPostOperation: Entered\n"));

	// This template code does not do anything with the callbackData, but
	// rather returns FLT_PREOP_SUCCESS_NO_CALLBACK.
	// This passes the request down to the next miniFilter in the chain.

	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


BOOLEAN
MiniFilterDriverDoRequestOperationStatus(
	_In_ PFLT_CALLBACK_DATA Data
)
/*++

Routine Description:

	This identifies those operations we want the operation status for.  These
	are typically operations that return STATUS_PENDING as a normal completion
	status.

Arguments:

Return Value:

	TRUE - If we want the operation status
	FALSE - If we don't

--*/
{
	PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;

	//
	//  return boolean state based on which operations we are interested in
	//

	return (BOOLEAN)

		//
		//  Check for oplock operations
		//

		(((iopb->MajorFunction == IRP_MJ_FILE_SYSTEM_CONTROL) &&
			((iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_FILTER_OPLOCK) ||
				(iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_BATCH_OPLOCK) ||
				(iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_1) ||
				(iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_2)))

			||

			//
			//    Check for directy change notification
			//

			((iopb->MajorFunction == IRP_MJ_DIRECTORY_CONTROL) &&
				(iopb->MinorFunction == IRP_MN_NOTIFY_CHANGE_DIRECTORY))
			);
}
