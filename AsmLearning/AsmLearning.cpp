// AsmLearning.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>

/**
 * 了解x86汇编有利于内核开发中的调试
 *
 * x86常用寄存器：eax,ebx,ecx,edx,esi,edi,esp,ebp
 * x64为：rax,rbx,rcx,rdx,rsi,rdi,rsp,rbp以及r8~r15
 */

int add(int a, int b);

int main()
{
	int a = 1, b;
	//b = a;
	//断点查看反汇编代码
	//00A31D3F 8B 45 F4             mov         eax, dword ptr[a]
	//00A31D42 89 45 E8             mov         dword ptr[b], eax
	__asm {
		mov eax, a
		mov b, eax
	}

	//x86处理器会认为esp保存的数据就是栈顶地址
	//__asm push eax //这条指令会把esp减少4并把eax数据存入esp所指内存地址空间
	//对eax操作
	//__asm pop eax //恢复eax的值
	//这样的push，pop操作经常用于值备份和传递参数

	//通常希望，调用一个函数，得到想要的结果，调用前后不影响当前环境
	//所以，一般c语言编译出的函数，都会保证不影响eax外的通用寄存器值（有时还有esp）
	//这是由于一般c语言编译出的函数返回值使用eax传递的
	//程序开头，编译器判断会用到这几个寄存器，所以备份原值
	//002C2279 53                   push        ebx
	//002C227A 56                   push        esi
	//002C227B 57                   push        edi
	//...中间过程
	//程序结尾，执行完程序逻辑，从栈内存中恢复寄存器原本值，由于栈结构，要相反顺序pop
	//002C22FC 5F                   pop         edi
	//002C22FD 5E                   pop         esi
	//002C22FE 5B                   pop         ebx
	//还需要保证栈平衡，有多少数据压栈，就应该有多少数据出栈
	//而esp栈顶指针的备份和恢复则不能用入栈出栈方式了，因为栈平衡本身就是esp相同，出入栈方式保存则没有意义
	//所以一般编译器会将ebp备份到栈内存后来保存esp，程序结束时把值还给esp并在栈中取回自身原值
	//程序开头
	//00CB2270 55                   push        ebp
	//00CB2271 8B EC                mov         ebp, esp
	//程序结尾，比较ebp与esp检查是否栈平衡，恢复值
	//00CB230F 3B EC                cmp         ebp, esp
	//00CB2311 E8 6F EF FF FF       call        __RTC_CheckEsp(0CB1285h)
	//00CB2316 8B E5                mov         esp, ebp
	//00CB2318 5D                   pop         ebp
	//这就需要保证ebp不被改变，如果不人为写代码做操作，编译器会自动避免这种情况

	//用汇编特性就可以很好的解释全局变量和局部变量作用域
	//函数中的局部变量往往在栈中，所以函数返回之后就失效了
	//这样也有好处，多线程情况下，局部变量必须是不被共享的
	//所以，每个线程执行函数时都有单独的堆栈，只要线程切换时同时切换esp，这个问题就很简单了

	//32位情况下，进入函数体后，esp减少4*n，相当于分配了4*n个字节空间用于保存内部变量
	//00FA2273 81 EC DC 00 00 00    sub         esp, 0DCh  ;程序开头保存了ebp和esp之后的操作
	//由于ebp保存了esp初始值，访问内部变量使用[ebp-x]即可
	//00DF227C 8D BD 24 FF FF FF    lea         edi,[ebp-0DCh]	;同时用edi保存了局部变量开始地址
	//向这个地址开始填入0xCC
	//00F92282 B9 37 00 00 00       mov         ecx, 37h
	//00F92287 B8 CC CC CC CC       mov         eax, 0CCCCCCCCh
	//00F9228C F3 AB                rep stos    dword ptr es : [edi]
	//rep表示重复执行，直至ecx减为0；stos会向指定地址写入32位(4字节)数据，执行后edi自动+4
	//0x37*0x4=0xDC，其实就是向局部变量的栈空间内写入0xCC，而0xCC是一条单字节机器指令，对应汇编的int3，作用是发生调试中断
	//填充的目的是确保内部变量空间只用来保存数据而不被执行，程序出错时，执行到这里就会出现调试中断（release版会优化掉这些过程）

	//关于lea指令，作用是取有效地址，也就是取逻辑地址（segment:offset）中的offset值
	//例如：
	//lea eax,[eax+ebx*4+0x0c] ;相当于	eax=eax+ebx*4+0x0c
	//如果使用mov指令，则需要单步分解用好几条计算来代替
	//再比如：
	//int i = 0;
	//int* p = &i;
	//假设只有这两个变量，则会分配8字节栈空间，变量i地址为[ebp-8]，指针p地址为{ebp-4]，可能被编译为如下汇编形式：
	//mov dword ptr [ebp-8], 0
	//lea eax, [ebp-8]
	//mov dword ptr [ebp-4],eax //常见用法就是这样取地址值后给指针赋值

	//调用指令call，是一个提取eip的过程，eip是个特殊寄存器，指示处理器之后要执行指令的地址；另外在跳转前，会把当前指令的下面一条指令地址压栈，用于返回
	int c = add(a, b);
	//00FE1D45 8B 45 E8             mov         eax, dword ptr[b] ;参数倒序压栈，最后是返回地址
	//00FE1D48 50                   push        eax				  ;有一个疑问是为什么不直接 push dword ptr[b] 而要使用寄存器转一次
	//00FE1D49 8B 4D F4             mov         ecx, dword ptr[a]
	//00FE1D4C 51                   push        ecx
	//00FE1D4D E8 FF F6 FF FF       call        std::basic_ostream<char, std::char_traits<char> >::sentry::sentry(0FE1451h)
	//00FE1D52 83 C4 08             add         esp, 8	;为了堆栈平衡，必须调整esp，偏移参数长度的地址，这其实是一种代码冗余
	//00FE1D55 89 45 DC             mov         dword ptr[c], eax
	//上面call 0FE1451h找到对应地址后，是如下语句，跳转到具体函数地址
	//00FE1451 E9 AA 0A 00 00       jmp         add(0FE1F00h)


	//最后，同一个值异或结果就是0
	//xor eax,eax ;将eax清零并返回
	return 0;
}

//函数大多是有参数的，call指令只能实现压入返回地址和跳转，并没有明确指定参数保存的地址
//而要传参，可以有多种方式：通过内存（堆栈）传递、整型参数可通过寄存器传递、浮点参数可通过浮点寄存器传递
//通过堆栈的好处是不污染寄存器，传参个数基本没限制，但需要读写内存，效率不如读写寄存器
//Windows内核中有快速调用协议（fastcall），第一个参数用ecx传递，第二个用edx传递，其他参数用堆栈
//普通C调用则是全部使用堆栈
int add(int a, int b)
{
	//00FE1F00 55                   push        ebp																		|					 |
	//00FE1F01 8B EC                mov         ebp, esp																|--------------------|
	//00FE1F03 81 EC C0 00 00 00    sub         esp, 0C0h																|		 ??			 |
	//00FE1F09 53                   push        ebx																		|--------------------|
	//00FE1F0A 56                   push        esi																		|		 ??			 |
	//00FE1F0B 57                   push        edi																		|--------------------|
	//00FE1F0C 8D BD 40 FF FF FF    lea         edi, [ebp - 0C0h]										 ret弹出地址 ->	|	   返回地址		 |
	//00FE1F12 B9 30 00 00 00       mov         ecx, 30h																|--------------------|
	//00FE1F17 B8 CC CC CC CC       mov         eax, 0CCCCCCCCh															|		参数a		 |
	//00FE1F1C F3 AB                rep stos    dword ptr es : [edi]													|--------------------|
	//00FE1F1E B9 29 E0 FE 00       mov         ecx, 0FEE029h															|		参数b		 |
	//00FE1F23 E8 48 F4 FF FF       call        @__CheckForDebuggerJustMyCode@4 (0FE1370h)			   esp+n调整平衡 ->	|--------------------|
	return a + b;
	//00FE1F28 8B 45 08             mov         eax, dword ptr[a]
	//00FE1F2B 03 45 0C             add         eax, dword ptr[b]
}
//00FE1F2E 5F                   pop         edi
//00FE1F2F 5E                   pop         esi
//00FE1F30 5B                   pop         ebx
//00FE1F31 81 C4 C0 00 00 00    add         esp, 0C0h
//00FE1F37 3B EC                cmp         ebp, esp
//00FE1F39 E8 47 F3 FF FF       call        __RTC_CheckEsp(0FE1285h)
//00FE1F3E 8B E5                mov         esp, ebp
//00FE1F40 5D                   pop         ebp
//00FE1F41 C3                   ret		;函数结果返回，从堆栈弹出一个地址，然后让处理器跳转到这个地址

/**
 * 常见调用协议
 *
 * 堆栈传参，参数倒序压栈，最后由调用者负责平衡堆栈的方式为C调用（C Call)
 * 传参与之相同，但平衡堆栈由函数本身处理的方式为标准调用（stdcall，是WindowsAPI常见方式）
 * Win32中，常见快速调用方式（fastcall），用ecx、edx传前两个参数，多出来的用堆栈，平衡由函数自身处理
 *
 * 可以用这些关键字指定调用方式：_fastcall,_stdcall,_cdecl（不加关键字默认为这个）
 *
 * 使用stdcall或者fastcall时，ret指令后会跟一个参数总长度（例如上面add函数，最后会变成 ret 08h，用于实现平衡）
 */