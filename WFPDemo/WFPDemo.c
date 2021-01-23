#include <ntddk.h>
#include <fwpsk.h> //使用fwp需要预定义NDIS支持版本：NDIS_SUPPORT_NDIS6
#include <fwpmk.h>
/**
 * WFP（Windows Filter Platform，Windows过滤平台）
 * 微软希望用WFP来代替之前的Winsock LSP、TDI以及NDIS等网络过滤驱动
 * 开发者可以在WFP划分的不同分层进行过滤、重定向、修改等
 * 通过WFP，可以实现防火墙、入侵检测、网络监视、流量控制等
 * WFP本身包含用户态API和内核态API，在用户层也可以处理网络数据包，主要学习下内核层使用
 *
 * WFP框架结构：
 *
 *				套接字应用程序						第三方防火墙					Windows防火墙					传统IPSec策略服务
 *			   (Ws2_32.dll模块)														   (mpssvc)						  (Policyagent)
 *			      --------------------------------------------------------------------------------------------------------------
 *																		|
 *																C管理API(fwpuclnt.dll)
 *																		|
 *																		|
 *																		|
 *		RPC服务应用程序
 *		  RPC运行时    ----  分类API(fwpuclnt.dll) -------->	RPC接口---------------------------------------------------------
 *		 (rpcrt4.dll)											   |														   |
 * 																   |										用户态过滤引擎	   |
 * 																   |														   |
 * 																   |														   |
 * 																   |						基础过滤引擎					   |
 * 																   |														   | <----> IKE协议|AuthIP协议
 * 																   |	用户态RPC层											   |
 * 																   |										IKE以及IPSec层	   |
 * 																   |														   |
 * 												|----------------> |														   |<---------------|
 * 												|				   |														   |				|
 * 												|				   -------------------------------------------------------------				|
 * 用户态										|									 |															|
 * =============================================|====================================|==========================================================|==============
 * 内核态										|									 |															|
 *												|									 |															|
 * ---------TCP/IP协议栈					IPSec框架				|--------命令控制接口(IOCTL)------|					|---第三方---|		    |
 * 		    (tcpip.sys) |											|								  |					| 			 |			|
 * 					    |											|								  |					| 			 |			|
 * 				数据流分层垫片										|		  流/报文 数据分层		  |					| 反病毒	 |			|
 * 					    |											|								  |					| 			 |			|
 * 					    |											|								  |					| 			 |			|
 * 				ALE网络连接管理									    |		发送/接收 ALE分层		  |					| 并行控制	 |			|
 * 					    |											|								  |					| 			 |			|
 * 					    |					<---->			分类API	|								  |	呼出接口API  <->| 			 |<->WFP内核态客户端
 * 						|											|								  |					| 			 |	 (fwpkclnt.sys)
 * 				传输分层垫片 TCP/UDP								|		发送/接收 传输分层		  |					| 入侵检测	 |
 * 					    |											|								  |					| 			 |
 * 					    |											|								  |					| IPSec		 |
 * 					    |											|								  |					| 			 |
 * 				网络分层垫片 IPv4/IPv6							    |		发送/接收 IP分层		  |					| NAT		 |
 * 					    |											|								  |					| 			 |
 * ----------------------											-----------------------------------					--------------
 *																				内核过滤引擎
 *
 */

 /**
  * 用户态接口通过基础过滤引擎最终会与内核态过滤引擎交互
  * 内核态引擎为主体，不同分层代表网络协议特定层，每一层中可以有子层和过滤器
  * 内核引擎会检查网络数据，是否命中过滤器规则（Rule），若命中则执行指定动作（Action）
  * 动作一般会表明是放行或是拦截，一次网络事件可能命中多个分层中多个子层的多个过滤器规则
  * 为了计算过滤动作，WFP有过滤仲裁模块，计算出过滤动作后交给内核过滤引擎，引擎把最终过滤结果反馈给垫片
  */

  /**
   * 垫片作为一种特殊内核模块，安插在系统的网络协议栈中不同层，不同层可以获取不同数据
   * 除了获取数据传递给过滤引擎，另一个作用是把内核过滤引擎的过滤结果反馈给协议栈
   * 是负责WFP数据来源以及执行数据拦截/放行最终动作的桥梁，但开发中无需过多关注
   * 从设计上，开发者可以主要集中于网络数据包的处理上
   */

   /**
	* 呼出接口，Callout，是一系列回调函数
	* 还包含GUID值来唯一的识别一个呼出接口
	* 在不同的编译环境，FWPS_CALLOUT结构体被宏定义为不同的编号，内含不同的成员
	* 对于每一个分层，有唯一的标识
	*/
typedef struct _my_fwps_callout
{
	GUID calloutKey;
	UINT32 flags;
	FWPS_CALLOUT_CLASSIFY_FN classifyFn;//不同环境中有不同编号
	FWPS_CALLOUT_NOTIFY_FN notifyFn;//不同环境中有不同编号
	FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN flowDeleteFn;//目前各环境都是同一个
}my_fwps_callout;

/**
 * 除了WFP划分好的分层，开发者可以划分子层并设置权重
 * 权重越大优先级越高
 */
typedef struct _my_fwpm_sublayer
{
	GUID subLayerKey;//唯一标识
	FWPM_DISPLAY_DATA displayData;//各环境相同
	UINT16 flags;//特性
	GUID* providerKey;
	FWP_BYTE_BLOB providerData;
	UINT16 weight;//权重
}my_fwpm_sublayer;

/**
 * 过滤器
 * 是一套规则和动作的集合，指明要过滤哪些网络包，命中规则时，执行相应动作
 * 同一个分层内，不同过滤器权重不能相同，所以可以指定关联一个子层，只要子层权重不同即可
 * 需要进行复杂分析处理时，还可以关联呼出接口，Callout回调执行完，将结果返回到WFP
 */
typedef struct _my_fwpm_filter
{
	GUID filterKey;//过滤器唯一标识，传0则会自动分配一个
	FWPM_DISPLAY_DATA displayData;//保存对象名字和描述
	UINT32 flags;//
	GUID* providerKey;
	FWP_BYTE_BLOB providerData;
	GUID layerKey;//分层GUID
	GUID subLayerKey;//子层GUID
	FWP_VALUE weight;//权重，比分层的权重复杂很多，是个结构体 主要使用type和uint64分别表示权重范围和具体权重值
	UINT32 numFilterConditions;//过滤条件个数
	FWPM_FILTER_CONDITION* filterCondition;//过滤条件，结构体内保存了网络数据包标识和匹配类型以及过滤条件的值
	FWPM_ACTION action;//所有过滤条件全部成立时执行动作，包括动作类型（允许/拦截/由回调呼出接口函数再决定）、过滤类型和callout标识（用于回调对应函数）
	union
	{
		UINT64 rawContext;
		GUID providerContextKey;
	};
	GUID* reserved;
	UINT64 filterId;
	FWP_VALUE effectiveWeight;
}my_fwpm_filter;

/**
 * 呼出接口回调函数
 * 主要是notifyFn、classifyFn、flowDeleteFn
 */
VOID NTAPI my_classifyFn(
	IN CONST FWPS_INCOMING_VALUES* inFixedValues, //传入参数，结构体内包含了网络数据包信息（本地和远程地址及端口
	IN CONST FWPS_INCOMING_METADATA_VALUES* inMetaValues, //元数据值，包含过滤相关信息（进程ID、数据流句柄等），成员很多但并发都有效，由currentMetadataValues决定
												//有一个宏可以方便查询是否包含某个具体标识符，确认成员是否有效：FWPS_IS_METADATA_FIELD_PRESENT，返回非0表示有效
	IN OUT VOID* layerData, //被过滤的原始网络数据，在有些分层中可能为NULL
	IN OPTIONAL CONST VOID* classifyContext, //与呼出接口驱动关联的上下文
	IN CONST FWPS_FILTER* filter, //过滤器指针
	IN UINT64 flowContext, //与流句柄关联的上下文
	OUT FWPS_CLASSIFY_OUT* classifyOut //过滤结果，包含操作类型、和一些系统保留值
)
{
	//无返回值
}
NTSTATUS NTAPI my_notifyFn(
	IN FWPS_CALLOUT_NOTIFY_TYPE notifyType, //通知类型，表明此次回调的原因
	IN CONST GUID* filterKey, //过滤器标识，使用前需要判空，因为只有类型为FWPS_CALLOUT_NOTIFY_ADD_FILTER时，此值才非空
	IN CONST FWPS_FILTER* filter //过滤器指针，标识将要被添加或删除的过滤器
)
{
	//返回值表示是否接受这个事件，比如即将添加过滤器但返回错误码则表示过滤器不允许被添加，但删除一定会删除
}
VOID NTAPI my_flowDeleteFn(
	IN UINT16 layerId, //分层标识
	IN UINT32 calloutId, //呼出接口标识
	IN UINT64 flowContext //关联的上下文
)
{
	//当一个数据流要被终止时，此函数会被回调（只有在这个将要终止的数据流被关联的情况下，才会被调用）
}


NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	return STATUS_SUCCESS;
}