#include <ntddk.h>

/**
 * 文件系统透明加密
 *
 * 很多企业为了防止信息泄密，都会有这样的需求：工作人员在公司内自由使用加密文件，但无法在公司外使用
 * 例如，对于程序员工作，核心代码可以给予控制，只允许使用某种编辑器
 * 加密策略应满足以下几点：
 *	所有工作软件新建的文件是加密的
 *	工作软件打开加密文件时，过滤驱动进行自动解密
 *	禁止工作软件通过网络将文件发送到其他计算机
 *	其他软件可以自由上网，但打开加密文件时不解密
 *
 * 这样可以无需禁用U盘或禁止上网，不影响其他工作；并且及时文件拷到公司外电脑，会因没有解密驱动而无法使用
 *
 * 书作者写了一个WinXP下FAT32文件系统的透明加密驱动，只支持记事本，作为学习使用
 */

 /**
  * 首先
  * 区分进程
  * 普通进程不进行加解密操作，机密进程可以正常读取机密文档
  * 进程区分使用进程名和对比可执行文件内容进行验证
  * Windows内部对每个进程都维护了EPROCESS结构，结构中保存了进程名，但并没有公开
  * 有人想出了办法：
  * 内核模块DriverEntry总在一个名为System的进程中被执行，那么可以确定DriverEntry当前进程名为System
  * 虽然不知道EPROCESS结构，但可以在其中搜索System字符串，并记录偏移量
  * 这样，只要根据这个偏移量，就能获取进程名了
  */
  // 这个函数必须在DriverEntry中调用，否则cfCurProcName将不起作用。
static size_t s_cf_proc_name_offset = 0;
void cfCurProcNameInit()
{
	ULONG i;
	PEPROCESS  curproc;
	curproc = PsGetCurrentProcess();
	// 搜索EPROCESS结构，在其中找到字符串
	for (i = 0; i < 3 * 4 * 1024; i++)
	{
		if (!strncmp("System", (PCHAR)curproc + i, strlen("System")))
		{
			s_cf_proc_name_offset = i;
			break;
		}
	}
}

// 以下函数可以获得进程名。返回获得的长度。
ULONG cfCurProcName(PUNICODE_STRING name)
{
	PEPROCESS  curproc;
	ULONG	i, need_len;
	ANSI_STRING ansi_name;
	if (s_cf_proc_name_offset == 0)
		return 0;

	// 获得当前进程PEB,然后移动一个偏移得到进程名所在位置。
	curproc = PsGetCurrentProcess();

	// 这个名字是ansi字符串，现在转化为unicode字符串。
	RtlInitAnsiString(&ansi_name, ((PCHAR)curproc + s_cf_proc_name_offset));
	need_len = RtlAnsiStringToUnicodeSize(&ansi_name);
	if (need_len > name->MaximumLength)
	{
		return RtlAnsiStringToUnicodeSize(&ansi_name);
	}
	RtlAnsiStringToUnicodeString(name, &ansi_name, FALSE);
	return need_len;
}

// 判断当前进程是不是notepad.exe
BOOLEAN cfIsCurProcSec(void)
{
	WCHAR name_buf[32] = { 0 };
	UNICODE_STRING proc_name = { 0 };
	UNICODE_STRING note_pad = { 0 };
	ULONG length;
	RtlInitEmptyUnicodeString(&proc_name, name_buf, 32 * sizeof(WCHAR));
	length = cfCurProcName(&proc_name);
	RtlInitUnicodeString(&note_pad, L"notepad.exe");
	if (RtlCompareUnicodeString(&note_pad, &proc_name, TRUE) == 0)
		return TRUE;
	return FALSE;
}

/**
 * 内存映射与文件缓冲
 * 要对记事本的文件操作进行加密，可以在文件过滤中读文件的读写操作进行过滤
 * 如果发现进程为记事本，则对读操作进行解密，对写操作进行加密
 * 其他进程不做处理
 * 
 * 其中，记事本对文件操作有几个特点；
 * 在explorer中用记事本打开某个文件，一般不会有读请求出现
 * 如果编辑这个文件，保存，则会有写请求出现，但始终没有读请求
 * 用记事本打开一个文件时，并不是一直打开状态，在编辑文件过程中也不会操作文件，只有保存时，文件才会被打开然后发出写请求，之后马上关闭
 * 所以，没有读请求，记事本如何获得文件内容？
 * Windows有一种特殊机制——内存映射
 * 它将一个文件映射到某个内存空间，访问这个文件内容的进程只要访问这个内存空间即可
 * 进程对内存的访问无法被文件过滤驱动捕获
 * 而文件内容是通过缺页中断从硬盘挪到了进程空间，在这个时候，被内存映射的文件实际上成了一个分页交换文件
 * 一旦进程访问到不存在的内存页（还在硬盘上），就会有一个文件上的页面被交换到内存
 * 在交换发生时，有一个特殊标记（irp->Flags带有IRP_PAGING_IO或IRP_SYNCHRONOUS_PAGING_IO）的IRP_MJ_READ请求会被发送到文件驱动
 * 可以称这种读写请求为分页读写请求
 * 分页读请求时可以捕获的，但记事本打开文件过程没有读请求的问题还是存在的
 * 
 * Windows中有文件缓冲机制，就是只要一个文件被以缓冲方式打开过，则其内容全部或者一部分就已经保存在内存里了
 * 这种文件缓冲是全局的，一般对于一个文件来说，无论多少个进程在访问，都只有一份缓冲
 * 一般应用层的读写请求都是普通读写请求，这种请求的特点是文件系统会调用CcCopyRead和CcCopyWrite来完成
 * 这两个函数会直接从缓冲中读取数据，如果缓冲中没有，会转换为分页读写请求，可以称这种普通读写请求称为缓冲读写请求
 * 
 * 所以，记事本在第一次打开一个文件之前，这个文件应该不存在文件缓冲，所以记事本即使从缓冲中读取数据，也应该由于缓冲还不存在或者数据不全而发生分页读写请求
 * 但是实际上一般都看不到分页读写请求，这是因为我们使用Explorer来浏览文件并找到文件，在双击文件打开时，explorer已经打开了文件导致它被读入了缓冲
 * 并且由于文本文件一般比较小，会整个得读完到缓冲中，所以过滤记事本得文件操作，往往看不到读请求
 * 
 * 
 * 				应用程序看到的文件内容
 * 
 *				缓冲写↓		↑缓冲读
 * 
 * 				文件缓冲中的文件内容
 * 
 *				分页写↓		↑分页读
 * 
 * 				真实硬盘上的文件内容
 * 
 * 可以根据IRP的当前栈空间指针来区分四种请求
 * 文件内容被分为了三个可以互通的拷贝
 * 对于机密进程来说
 * 真实硬盘上的文件内容必须是密文、应用程序看到的文件内容是明文
 * 对于普通进程而言
 * 看到的文件内容必须是密文
 * 对于文件缓冲上的内容
 * 则不一定，如果用密文，则必须截获缓冲读写请求来加解密，对于使用内存映射文件的情况就难以处理了
 * 所以，文件缓冲为密文的情况一般都只能将不使用内存映射文件的软件作为机密进程
 * 使用明文的话会比较好处理，这样只需要处理分页读写请求，并且分页读写请求无论是否使用内存映射文件都是存在的，就不需要分开处理
 * 但存在一个问题，由于文件缓冲是全局的，一般对于各进程来说，这份缓冲只有一份，那么如果是明文，其他普通进程从缓冲中读到的就是明文
 * 对于两种方式存在的问题，书中采取了如下办法：
 * 当普通进程打开文件时，文件缓冲为密文，并且不允许机密进程打开这个文件
 * 当机密进程打开一个文件时，文件缓冲为明文，并且不允许普通进程打开这个文件
 * 二者切换时，中间清除文件缓冲
 */

/**
 * 项目文件放在目录下， 但没加入项目编译
 */

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
	return STATUS_SUCCESS;
}