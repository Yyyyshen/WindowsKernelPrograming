#include <ntddk.h>
#include <ndis.h> //手动链接ndis.lib

/**
 * NDIS协议驱动
 *
 * 在Windows网络驱动里，广域网、无线局域网在连接建立后，将连接虚拟为了以太网形式
 * 以太网包结构为：
 *		源地址（6字节）		目标地址（6字节）		类型（2字节）		其他（数据）
 * 这里地址指的都是网卡MAC地址，类型例如0x80、0x00说明是个IP包
 *
 * 上层用户用Socket调用TCP协议发送数据时，驱动把这些数据封装为IP包，再封装为以太网包发出去；接收时则解析后再提交给上层应用
 * 实际应用中，协议驱动常用于网络嗅探，一般不用于防火墙，因为难以干预收发包
 *
 * NDIS驱动有三种：协议驱动、小端口驱动、中间层驱动
 * 协议驱动上层提供直接供应用层socket使用的数据传输接口；下层绑定小端口，小端口驱动直接针对网卡，用于发送与接收以太网包
 * 传统中间层驱动以特殊方式插入协议驱动和小端口驱动之间，但逐渐被过滤驱动代替
 */

 /**
  * 协议驱动主要编写过程：
  *
  * 在入口函数填写协议特征（协议的回调函数列表）
  * 使用NdisRegisterProtocolDriver将自己注册为协议驱动
  * 系统会对每个实际存在的网卡实例调用本协议驱动提供的回调函数，这个回调函数中应决定是否绑定一个网卡
  * 发生各种事件时，特征集中某函数被调用，协议开发者在其中决定如何处理接收到的数据包
  * 当应用试图发送数据时，可以打开这个协议并发出请求（使用socket或协议自己提供的设备接口）
  *
  * 示例：
  * 见官方github
  * https://github.com/microsoft/Windows-driver-samples/tree/master/network/ndis
  */
VOID manual(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	NTSTATUS status = STATUS_SUCCESS;
	//创建设备
	PDEVICE_OBJECT deviceObj; //过程略
	//协议特征变量
	NDIS_PROTOCOL_CHARACTERISTICS protocolChar;
	//填写协议特征
	NdisZeroMemory(&protocolChar, sizeof(NDIS_PROTOCOL_CHARACTERISTICS));
	protocolChar.MajorNdisVersion = 5;
	protocolChar.MinorNdisVersion = 0;
	//protocolChar.OpenAdapterCompleteHandler = handler;
	//...各种handler注册
	//注册协议
	NDIS_HANDLE ndis_handle;
	NdisRegisterProtocol((PNDIS_STATUS)&status, &ndis_handle, &protocolChar, sizeof(NDIS_PROTOCOL_CHARACTERISTICS));
	if (status != NDIS_STATUS_SUCCESS)
	{
		//注册失败
	}
	//注册各分发函数
	//...
}

/**
 * 与网卡之间的绑定（Bind）
 * 与设备对象之间绑定（Attach）是不同的
 * 当协议驱动绑定了网卡，网卡收到的数据将提交给这个协议，协议可以使用这个网卡发送数据包
 * 但并非一对一关系，一般协议都会绑定所有网卡
 */
VOID bind()
{
	//协议特征中可以设置绑定回调函数
	NDIS_PROTOCOL_CHARACTERISTICS protocolChar;
	NdisZeroMemory(&protocolChar, sizeof(NDIS_PROTOCOL_CHARACTERISTICS));
	//protocolChar.BindAdapterHandler = NdisProtBindAdapter;
	//protocolChar.UnbindAdapterHandler = NdisProtUnbindAdapter;
	//当Windows内核检测到网卡存在时，就会调用每个注册过协议的BindAdapterHandler函数
}

/**
 * 具体的绑定过程
 * 完整代码比较复杂，放在另一个项目里ndisprot
 */


NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	return STATUS_SUCCESS;
}