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
LIST_ENTRY g_ListHeader = { 0 };
VOID Test_List()
{
	//初始化头节点使其Flink和Blink指向自身
	InitializeListHead(&g_ListHeader);

	//插入节点
	TestListEntry EntryA = { 0 };
	TestListEntry EntryB = { 0 };
	TestListEntry EntryC = { 0 };
	EntryA.m_data = 'A';
	EntryB.m_data = 'B';
	EntryC.m_data = 'C';
	InsertHeadList(&g_ListHeader, &EntryB.m_list_entry);
	InsertHeadList(&g_ListHeader, &EntryA.m_list_entry);
	InsertTailList(&g_ListHeader, &EntryC.m_list_entry);

	//遍历节点，通过Flink从前向后
	PLIST_ENTRY pListEntry = NULL;
	pListEntry = g_ListHeader.Flink;
	while (pListEntry != &g_ListHeader)
	{
		PTestListEntry pTestListEntry = CONTAINING_RECORD(pListEntry, TestListEntry, m_list_entry);
		DbgPrint("ListPtr = %p, Entry = %p, Tag = %c \n", pListEntry, pTestListEntry, (CHAR)pTestListEntry->m_data);
		pListEntry = pListEntry->Flink;
	}

	//节点移除，头尾移除/指定移除
	PLIST_ENTRY RemoveEntryA = RemoveHeadList(&g_ListHeader);
	DbgPrint("RemoveEntryA = %p", RemoveEntryA);
	PLIST_ENTRY RemoveEntryC = RemoveTailList(&g_ListHeader);
	DbgPrint("RemoveEntryC = %p", RemoveEntryC);
	BOOLEAN isEmpty = RemoveEntryList(&EntryB.m_list_entry);
	DbgPrint("After remove EntryB, List is Empty: %d", isEmpty);
	BOOLEAN isListEmpty = IsListEmpty(&g_ListHeader);
	DbgPrint("List is Empty: %d", isListEmpty);
}

/**
 * 链表这样的结构总是会面临多线程同步问题，需要使用锁
 * 自旋锁是内核中提供的高IRQL锁，用同步以及独占方式访问某个资源
 */
KSPIN_LOCK g_my_spin_lock = { 0 };
VOID Init_Lock()
{
	//初始化自旋锁
	KeInitializeSpinLock(&g_my_spin_lock);
}
VOID Test_Lock()
{
	//使用
	KIRQL irql;//中断级别
	KeAcquireSpinLock(&g_my_spin_lock, &irql);//KeAcquireSpinLock会提高当前中断级别，将旧的中断级别保存到irql
	// do something 只有单线程执行中间部分代码，也就是只有一个线程能获得自旋锁
	KeReleaseSpinLock(&g_my_spin_lock, irql);
}
//一般使用锁，在操作前调用获取锁，执行操作后，释放锁，但LIST_ENTRY的操作中，可以传递一个锁进去
VOID Op_List_With_Lock()
{
	TestListEntry EntryTest = { 0 };
	EntryTest.m_data = '0';
	//普通插入
	//InsertHeadList(&g_ListHeader, &EntryTest);
	//带锁插入
	ExInterlockedInsertHeadList(&g_ListHeader, &EntryTest, &g_my_spin_lock);
	//带锁移除
	PLIST_ENTRY pRemoveEntry = NULL;
	pRemoveEntry = ExInterlockedRemoveHeadList(&g_ListHeader, &g_my_spin_lock);
}
VOID Test_Lock_In_List()
{
	//初始化头节点
	InitializeListHead(&g_ListHeader);
	//初始化自旋锁
	Init_Lock();

	//操作链表
	Op_List_With_Lock();
}
//队列自旋锁，性能更好，并且遵循先等待的先获取原则
KSPIN_LOCK g_my_queue_spin_lock = { 0 };
VOID Init_Queue_Lock()
{
	//初始化方式与普通自旋锁方式相同
	KeInitializeSpinLock(&g_my_queue_spin_lock);
}
VOID Test_Queue_Lock()
{
	//使用不同
	KLOCK_QUEUE_HANDLE my_lock_queue_handle;//增加一个数据结构唯一的表示一个队列自旋锁
	KeAcquireInStackQueuedSpinLock(&g_my_queue_spin_lock, &my_lock_queue_handle);
	// do something
	KeReleaseInStackQueuedSpinLock(&g_my_queue_spin_lock, &my_lock_queue_handle);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	NTSTATUS status = TRUE;

	//链表使用
	//Test_List();

	//锁应用
	Test_Lock_In_List();

	return status;
}