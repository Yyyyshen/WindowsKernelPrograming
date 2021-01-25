#define INITGUID
#include <guiddef.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include "WFPSample.h"
#include "Rule.h"

UINT32 g_uFwpsEstablishedCallOutId = 0;
UINT32 g_uFwpmEstablishedCallOutId = 0;
UINT64 g_uEstablishedFilterId = 0;

HANDLE	g_hEngine = NULL;

NTSTATUS InitWfp(PDEVICE_OBJECT DeviceObject)
{
	NTSTATUS nStatus = STATUS_UNSUCCESSFUL;
	do
	{
		g_hEngine = OpenEngine();
		if (g_hEngine == NULL)
		{
			break;
		}
		if (STATUS_SUCCESS != WfpRegisterCallouts(DeviceObject))
		{
			break;
		}
		if (STATUS_SUCCESS != WfpAddCallouts())
		{
			break;
		}
		if (STATUS_SUCCESS != WfpAddSubLayer())
		{
			break;
		}
		if (STATUS_SUCCESS != WfpAddFilters())
		{
			break;
		}
		nStatus = STATUS_SUCCESS;
	} while (FALSE);
	return nStatus;
}

VOID NTAPI Wfp_Sample_Established_ClassifyFn_V4(
	IN const FWPS_INCOMING_VALUES* inFixedValues,
	IN const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
	IN OUT VOID* layerData,
	IN OPTIONAL const void* classifyContext,
	IN const FWPS_FILTER* filter,
	IN UINT64  flowContext,
	OUT FWPS_CLASSIFY_OUT* classifyOut
)
{
	WORD	wDirection = 0;
	WORD	wRemotePort = 0;
	WORD	wSrcPort = 0;
	WORD	wProtocol = 0;
	ULONG	ulSrcIPAddress = 0;
	ULONG	ulRemoteIPAddress = 0;
	if (!(classifyOut->rights & FWPS_RIGHT_ACTION_WRITE))
	{
		return;
	}
	//wDirection表示数据包的方向,取值为	//FWP_DIRECTION_INBOUND/FWP_DIRECTION_OUTBOUND
	wDirection = inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_DIRECTION].value.int8;

	//wSrcPort表示本地端口，主机序
	wSrcPort = inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_PORT].value.uint16;

	//wRemotePort表示远端端口，主机序
	wRemotePort = inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_REMOTE_PORT].value.uint16;

	//ulSrcIPAddress 表示本地IP
	ulSrcIPAddress = inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_ADDRESS].value.uint32;

	//ulRemoteIPAddress 表示远端IP
	ulRemoteIPAddress = inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_REMOTE_ADDRESS].value.uint32;

	//wProtocol表示网络协议，可以取值是IPPROTO_ICMP/IPPROTO_UDP/IPPROTO_TCP
	wProtocol = inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_PROTOCOL].value.uint8;

	//输出一下
	KdPrint(("Direction:%d  Local: %d:%d  Remote: %d:%d Protocol: %d", wDirection, ulSrcIPAddress, wSrcPort, ulRemoteIPAddress, wRemotePort, wProtocol));

	//默认"允许"(PERMIT)
	classifyOut->actionType = FWP_ACTION_PERMIT;

	if (IsHitRule(wRemotePort))
	{
		classifyOut->actionType = FWP_ACTION_BLOCK;
	}
	//简单的策略判断，若满足为TCP、对外连接、端口为80，则拦截
	if ((wProtocol == IPPROTO_TCP) &&
		(wDirection == FWP_DIRECTION_OUTBOUND) &&
		(wRemotePort == HTTP_DEFAULT_PORT))
	{
		//TCP协议尝试发起80端口的访问，拦截(BLOCK)
		classifyOut->actionType = FWP_ACTION_BLOCK;
		//测试通过，也暂时没有蓝屏情况，回去看下另一个例子
	}

	//清除FWPS_RIGHT_ACTION_WRITE标记
	if (filter->flags & FWPS_FILTER_FLAG_CLEAR_ACTION_RIGHT)
	{
		classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
	}
	return;
}



NTSTATUS NTAPI Wfp_Sample_Established_NotifyFn_V4(
	IN  FWPS_CALLOUT_NOTIFY_TYPE        notifyType,
	IN  const GUID* filterKey,
	IN  const FWPS_FILTER* filter)
{
	return STATUS_SUCCESS;
}

VOID NTAPI Wfp_Sample_Established_FlowDeleteFn_V4(
	IN UINT16  layerId,
	IN UINT32  calloutId,
	IN UINT64  flowContext
)
{

}

NTSTATUS WfpRegisterCalloutImple(
	IN OUT void* deviceObject,
	IN  FWPS_CALLOUT_CLASSIFY_FN ClassifyFunction,
	IN  FWPS_CALLOUT_NOTIFY_FN NotifyFunction,
	IN  FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN FlowDeleteFunction,
	IN  GUID const* calloutKey,
	IN  UINT32 flags,
	OUT UINT32* calloutId
)
{
	FWPS_CALLOUT sCallout;
	NTSTATUS status = STATUS_SUCCESS;

	memset(&sCallout, 0, sizeof(FWPS_CALLOUT));

	sCallout.calloutKey = *calloutKey;
	sCallout.flags = flags;
	sCallout.classifyFn = ClassifyFunction;
	sCallout.notifyFn = NotifyFunction;
	sCallout.flowDeleteFn = FlowDeleteFunction;

	status = FwpsCalloutRegister(deviceObject, &sCallout, calloutId);

	return status;
}

NTSTATUS WfpRegisterCallouts(IN OUT VOID* deviceObject)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	do
	{
		if (deviceObject == NULL)
		{
			break;
		}
		status = WfpRegisterCalloutImple(deviceObject,
			Wfp_Sample_Established_ClassifyFn_V4,
			Wfp_Sample_Established_NotifyFn_V4,
			Wfp_Sample_Established_FlowDeleteFn_V4,
			&WFP_SAMPLE_ESTABLISHED_CALLOUT_V4_GUID,
			0,
			&g_uFwpsEstablishedCallOutId);
		if (status != STATUS_SUCCESS)
		{
			break;
		}
		status = STATUS_SUCCESS;
	} while (FALSE);
	return status;
}

VOID WfpUnRegisterCallouts()
{
	FwpsCalloutUnregisterById(g_uFwpsEstablishedCallOutId);
	g_uFwpsEstablishedCallOutId = 0;
}

NTSTATUS WfpAddCallouts()
{
	NTSTATUS status = STATUS_SUCCESS;
	FWPM_CALLOUT fwpmCallout = { 0 };
	fwpmCallout.flags = 0;
	do
	{
		if (g_hEngine == NULL)
		{
			break;
		}
		fwpmCallout.displayData.name = (wchar_t*)WFP_SAMPLE_ESTABLISHED_CALLOUT_DISPLAY_NAME;
		fwpmCallout.displayData.description = (wchar_t*)WFP_SAMPLE_ESTABLISHED_CALLOUT_DISPLAY_NAME;
		fwpmCallout.calloutKey = WFP_SAMPLE_ESTABLISHED_CALLOUT_V4_GUID;
		fwpmCallout.applicableLayer = FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4;//指定分层，ALE分层中，WFP维护数据包状态，如连接状态等，本例分层代表连接建立
		status = FwpmCalloutAdd(g_hEngine, &fwpmCallout, NULL, &g_uFwpmEstablishedCallOutId);
		if (!NT_SUCCESS(status) && (status != STATUS_FWP_ALREADY_EXISTS))
		{
			break;
		}
		status = STATUS_SUCCESS;
	} while (FALSE);
	return status;
}

VOID WfpRemoveCallouts()
{
	if (g_hEngine != NULL)
	{
		FwpmCalloutDeleteById(g_hEngine, g_uFwpmEstablishedCallOutId);
		g_uFwpmEstablishedCallOutId = 0;
	}

}

NTSTATUS WfpAddSubLayer()
{
	NTSTATUS nStatus = STATUS_UNSUCCESSFUL;
	FWPM_SUBLAYER SubLayer = { 0 };
	SubLayer.flags = 0;
	SubLayer.displayData.description = WFP_SAMPLE_SUB_LAYER_DISPLAY_NAME;
	SubLayer.displayData.name = WFP_SAMPLE_SUB_LAYER_DISPLAY_NAME;
	SubLayer.subLayerKey = WFP_SAMPLE_SUBLAYER_GUID;
	SubLayer.weight = 65535;//为子层设置权重
	if (g_hEngine != NULL)
	{
		nStatus = FwpmSubLayerAdd(g_hEngine, &SubLayer, NULL);
	}
	return nStatus;

}

VOID WfpRemoveSubLayer()
{
	if (g_hEngine != NULL)
	{
		FwpmSubLayerDeleteByKey(g_hEngine, &WFP_SAMPLE_SUBLAYER_GUID);
	}
}

NTSTATUS WfpAddFilters()
{
	NTSTATUS nStatus = STATUS_UNSUCCESSFUL;
	do
	{
		FWPM_FILTER Filter = { 0 };
		FWPM_FILTER_CONDITION FilterCondition[1] = { 0 };
		FWP_V4_ADDR_AND_MASK AddrAndMask = { 0 };//指定过滤IP和掩码
		if (g_hEngine == NULL)
		{
			break;
		}
		//过滤器属性
		Filter.displayData.description = WFP_SAMPLE_FILTER_ESTABLISH_DISPLAY_NAME;
		Filter.displayData.name = WFP_SAMPLE_FILTER_ESTABLISH_DISPLAY_NAME;
		Filter.flags = 0;
		Filter.layerKey = FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4;//设置分层
		Filter.subLayerKey = WFP_SAMPLE_SUBLAYER_GUID;//绑定子层
		Filter.weight.type = FWP_EMPTY;//指定权重为Empty，过滤引擎会自动为其分配一个权重
		Filter.numFilterConditions = 1;//一个过滤条件
		Filter.filterCondition = FilterCondition;
		Filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;//动作类型，标识与Callout接口关联，并且总是返回允许或者拦截
		Filter.action.calloutKey = WFP_SAMPLE_ESTABLISHED_CALLOUT_V4_GUID;
		//过滤条件
		FilterCondition[0].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;//表示检查远端IP
		FilterCondition[0].matchType = FWP_MATCH_EQUAL;//指定匹配类型为相等
		FilterCondition[0].conditionValue.type = FWP_V4_ADDR_MASK;
		FilterCondition[0].conditionValue.v4AddrMask = &AddrAndMask;//设置为0，表示所有数据包都去匹配这个过滤条件
		nStatus = FwpmFilterAdd(g_hEngine, &Filter, NULL, &g_uEstablishedFilterId);
		if (STATUS_SUCCESS != nStatus)
		{
			break;
		}
		nStatus = STATUS_SUCCESS;
	} while (FALSE);
	return nStatus;
}

VOID WfpRemoveFilters()
{
	if (g_hEngine != NULL)
	{
		FwpmFilterDeleteById(g_hEngine, g_uEstablishedFilterId);
	}
}

HANDLE OpenEngine()
{
	FWPM_SESSION0 Session = { 0 };
	HANDLE hEngine = NULL;
	FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, &Session, &hEngine);
	return hEngine;
}

void CloseEngine()
{
	if (g_hEngine != NULL)
	{
		FwpmEngineClose(g_hEngine);
	}
	g_hEngine = NULL;
}

VOID UninitWfp()
{
	WfpRemoveFilters();
	WfpRemoveSubLayer();
	WfpRemoveCallouts();
	WfpUnRegisterCallouts();
	CloseEngine();
}
