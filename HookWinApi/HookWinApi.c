/**
 * Windows内核挂钩
 *
 * 系统服务描述符表挂钩 SSDT HOOK
 * 函数导出表挂钩 Export Table HOOK
 * 中断挂钩 IDT/IOAPIC HOOK
 * 分发函数挂钩 Dispatch Function HOOK
 * 系统调用入口挂钩 Syscall Entry HOOK
 * 内联挂钩 Inline HOOK
 * 调试挂钩	Debug HOOK
 */

 /**
  * SSDT
  * 系统服务描述符表是Windows内核中一个数据结构
  * 保存了内核导出的一系列供用户态调用的函数地址
  * 用户模式下所有系统调用，都先通过特殊指令进入内核，再通过服务编号在系统描述符表中找到相应系统函数提供服务
  * 表地址可从内核中导出的结构KeServiceDescriptorTable中获得，主要记录了基址和函数数量
  * 结构体中需要关注ServiceTableBase域，指向一个指针数组，数组中每个元素都是系统服务处理函数的指针，服务编号就是索引
  * 通过修改这个数组中的函数指针，可以达到一些目的，而64位中会检查这个域，发现有改动就直接蓝屏
  * 例子在随书代码sh_ssdt_hook.h，有汇编，需要32位编译
  */

  /**
   * 函数导出表挂钩
   * 还有一些内核函数没有放到系统服务描述符表
   * 保存原始地址，替换跳转指令，完成需要的处理后，再调用回原来的地址
   * 例子挂钩IoCallDriver——xtbl_hook.h
   */

#include <ntddk.h>

NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObject, IN PUNICODE_STRING pRegistryPath)
{
	return STATUS_SUCCESS;
}