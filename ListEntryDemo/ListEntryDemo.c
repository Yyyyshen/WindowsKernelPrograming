#include "ntddk.h"

/**
 * 链表
 * 使用较多的为双向链表，WDK中对链表的一个节点定义为LIST_ENTRY
 */

 //LIST_ENTRY只包含两个指针指向前后节点，使用时需要将其作为成员定义一个结构体
typedef struct _TestListEntry
{
	VOID* m_data;
	LIST_ENTRY m_list_entry;//每个节点的Flink和Blink都指向前（后）一个节点的Flink
} TestListEntry, * PTestListEntry;
//一般会定义一个链表头节点，不包含任何内容，只是一个LIST_ENTRY

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	NTSTATUS status = TRUE;

	//初始化头节点使其Flink和Blink指向自身
	LIST_ENTRY ListHeader = { 0 };
	InitializeListHead(&ListHeader);

	//插入节点
	TestListEntry EntryA = { 0 };
	TestListEntry EntryB = { 0 };
	TestListEntry EntryC = { 0 };
	EntryA.m_data = 'A';
	EntryB.m_data = 'B';
	EntryC.m_data = 'C';
	InsertHeadList(&ListHeader, &EntryB.m_list_entry);
	InsertHeadList(&ListHeader, &EntryA.m_list_entry);
	InsertTailList(&ListHeader, &EntryC.m_list_entry);

	//遍历节点，通过Flink从前向后
	PLIST_ENTRY pListEntry = NULL;
	pListEntry = ListHeader.Flink;
	while (pListEntry != &ListHeader)
	{
		PTestListEntry pTestListEntry = CONTAINING_RECORD(pListEntry, TestListEntry, m_list_entry);
		DbgPrint("ListPtr = %p, Entry = %p, Tag = %c \n", pListEntry, pTestListEntry, (CHAR)pTestListEntry->m_data);
		pListEntry = pListEntry->Flink;
	}

	//节点移除，头尾移除/指定移除
	PLIST_ENTRY RemoveEntryA = RemoveHeadList(&ListHeader);
	DbgPrint("RemoveEntryA = %p", RemoveEntryA);
	PLIST_ENTRY RemoveEntryC = RemoveTailList(&ListHeader);
	DbgPrint("RemoveEntryC = %p", RemoveEntryC);
	BOOLEAN isEmpty = RemoveEntryList(&EntryB.m_list_entry);
	DbgPrint("After remove EntryB, List is Empty: %d", isEmpty);
	BOOLEAN isListEmpty = IsListEmpty(&ListHeader);
	DbgPrint("List is Empty: %d", isListEmpty);

	return status;
}