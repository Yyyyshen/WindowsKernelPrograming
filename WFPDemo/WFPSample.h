#pragma once

#define WFP_SAMPLE_ESTABLISHED_CALLOUT_DISPLAY_NAME L"WfpSampleEstablishedCalloutName"
#define WFP_SAMPLE_SUB_LAYER_DISPLAY_NAME L"WfpSampleSubLayerName"
#define WFP_SAMPLE_FILTER_ESTABLISH_DISPLAY_NAME L"WfpSampleFilterEstablishName"
#define HTTP_DEFAULT_PORT 80
#define IOCTL_WFP_SAMPLE_ADD_RULE CTL_CODE(FILE_DEVICE_UNKNOWN,0x801,METHOD_BUFFERED,FILE_READ_ACCESS | FILE_WRITE_ACCESS)

// {D969FC67-6FB2-4504-91CE-A97C3C32AD36}
DEFINE_GUID(WFP_SAMPLE_ESTABLISHED_CALLOUT_V4_GUID, 0xd969fc67, 0x6fb2, 0x4504, 0x91, 0xce, 0xa9, 0x7c, 0x3c, 0x32, 0xad, 0x36);

// {ED6A516A-36D1-4881-BCF0-ACEB4C04C21C}
DEFINE_GUID(WFP_SAMPLE_SUBLAYER_GUID, 0xed6a516a, 0x36d1, 0x4881, 0xbc, 0xf0, 0xac, 0xeb, 0x4c, 0x4, 0xc2, 0x1c);


//#if (NTDDI_VERSION >= NTDDI_WIN10_RS3)
//typedef void (NTAPI* FWPS_CALLOUT_CLASSIFY_FN3)(
//	_In_ const FWPS_INCOMING_VALUES0* inFixedValues,
//	_In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
//	_Inout_opt_ void* layerData,
//	_In_opt_ const void* classifyContext,
//	_In_ const FWPS_FILTER3* filter,
//	_In_ UINT64 flowContext,
//	_Inout_ FWPS_CLASSIFY_OUT0* classifyOut
//	);
//之前在另一本书看到的例子是像系统API内一样用不同系统版本区分结构与函数指针，这里直接使用宏适配各版本
VOID NTAPI Wfp_Sample_Established_ClassifyFn_V4(
	IN const FWPS_INCOMING_VALUES* inFixedValues,
	IN const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
	IN OUT VOID* layerData,
	IN OPTIONAL const void* classifyContext,
	IN const FWPS_FILTER* filter,
	IN UINT64  flowContext,
	OUT FWPS_CLASSIFY_OUT* classifyOut
);

//#if (NTDDI_VERSION >= NTDDI_WIN10_RS3)
//typedef NTSTATUS(NTAPI* FWPS_CALLOUT_NOTIFY_FN3)(
//	_In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
//	_In_ const GUID* filterKey,
//	_Inout_ FWPS_FILTER3* filter
//	);
NTSTATUS NTAPI Wfp_Sample_Established_NotifyFn_V4(IN FWPS_CALLOUT_NOTIFY_TYPE notifyType, IN const GUID* filterKey, IN const FWPS_FILTER* filter);

//typedef void (NTAPI* FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN0)(
//	_In_ UINT16 layerId,
//	_In_ UINT32 calloutId,
//	_In_ UINT64 flowContext
//	);
VOID NTAPI Wfp_Sample_Established_FlowDeleteFn_V4(IN UINT16 layerId, IN UINT32 calloutId, IN UINT64 flowContext);


NTSTATUS WfpAddCallouts();

NTSTATUS WfpRegisterCallouts(IN OUT VOID* deviceObject);

NTSTATUS WfpRegisterCalloutImple(
	IN OUT void* deviceObject,
	IN  FWPS_CALLOUT_CLASSIFY_FN ClassifyFunction,
	IN  FWPS_CALLOUT_NOTIFY_FN NotifyFunction,
	IN  FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN FlowDeleteFunction,
	IN  GUID const* calloutKey,
	IN  UINT32 flags,
	OUT UINT32* calloutId
);

NTSTATUS WfpAddSubLayer();

NTSTATUS WfpAddFilters();


VOID WfpUnRegisterCallouts();

VOID WfpRemoveCallouts();

VOID WfpRemoveSubLayer();

VOID WfpRemoveFilters();

HANDLE OpenEngine();

void CloseEngine();

NTSTATUS InitWfp(PDEVICE_OBJECT DeviceObject);

VOID UninitWfp();