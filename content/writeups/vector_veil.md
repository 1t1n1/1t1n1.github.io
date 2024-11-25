---
title: "Vector Veil - CyberSci Regionals 2024"
date: 2024-11-24T12:30:00-04:00
author: "1t1n1"
# cover: "/images/vector_veil/cover.png"
description: "A Reverse Engineering challenge that dives into the AVX extensions to the x86 instructions set"
showFullContent: false
readingTime: false
hideComments: false
color: ""
---

The challenge I am presenting to you was part of the CyberSci Regionals 2024 edition and was the first in the Reverse Engineering track. Being an avid reverse engineering enthusiast myself, I didn't even look at the other challenges and immediately started with the one called "Vector Veil", unaware that I was embarking on a journey that would take up all the time I had at the competition...

## So it begins...

The competition's theme was that we were hired as cybersecurity consultants to help secure the election of the fictional Val Verde nation. In this context, the description of the challenge read as follows:

> To streamline the election process, Val Verde has implemented a digital check-in system allowing voters to pre-register online and receive a unique digital code, replacing traditional ID checks at polling stations. The system verifies the code upon arrival to ensure only registered voters can proceed to vote. Although these check-in machines are closely guarded, the Central Electoral Commission (CEC) wants to ensure that the system remains secure even if someone gains access to one of the machines.
> 
> As a hired security consultant, your task is to evaluate the system's security. You are tasked with figuring out how to forge a registration code, demonstrating how an attacker might exploit the system to gain unauthorized access. Your findings will be crucial in securing Val Verde's election.
> 
> Your task is to analyze the binary further to uncover how the digital check-in system's authentication mechanism works. The system generates unique registration codes for each voter, and you must determine how these codes are created.
> 
> You are required to forge a valid registration code for General Mateo Alvarez. Successfully generating this code will simulate bypassing the check-in process and impersonating the General. The integrity of your nation rests in your hands!
> 
> (Calculate the registration code for the name "Mateo Alvarez" and submit it as the flag.)


We are given [a binary](https://github.com/1t1n1/CTFs/blob/main/CyberSci_Regionals_2024/vecveil/vecveil) which asks us for our name and registration code when run:

```shell
Please enter your name: <name_here>  
Please enter your registration code: <reg_code_here>
```

Entering `Mateo Alvarez` followed by `123456789` (not the correct registration code) prints `Invalid registration code provided.`. Our goal is to find the right code that will return a message such as `Correct registration code provided.`.

## Initial static analysis

Let's open the binary in Ghidra to understand what we are dealing with. 

```c
void processEntry entry(void)

{
    undefined4 uVar1;
    long lVar2;
    code *UNRECOVERED_JUMPTABLE;
    undefined8 in_RCX;
    undefined8 uVar3;
    undefined *puVar4;
    undefined8 in_R8;
    undefined8 uVar5;
    bool bVar6;
    undefined auVar7 [32];
    undefined auVar8 [16];
    undefined auVar9 [16];
    undefined in_YMM2 [32];
    undefined auVar10 [32];
    
    auVar8 = vmovq_avx(0x43800000);
    auVar8 = vcvttps2dq_avx(auVar8);
    auVar9 = vmovq_avx(&stack0x00000000);
    auVar7 = vpsubq_avx2(ZEXT1632(auVar9),ZEXT1632(auVar8));
    puVar4 = (undefined *)vmovq_avx(auVar7._0_16_);
    auVar8 = vmovq_avx(0x431d0000);
    auVar8 = vcvttps2dq_avx(auVar8);
    vpextrq_avx(auVar8,0);
    auVar10 = vxorps_avx(in_YMM2,in_YMM2);
    auVar8 = auVar10._0_16_;
    vmovq_avx(auVar8);
    vmovq_avx(auVar8);
    uVar5 = vmovq_avx(auVar8);
    syscall();
    auVar8 = vmovq_avx(0x42640000);
    auVar8 = vcvttps2dq_avx(auVar8);
    lVar2 = vmovq_avx(auVar8);
    syscall();
    bVar6 = lVar2 != 0;
    if (bVar6) {
        auVar8 = vmovq_avx(0x42740000);
        auVar8 = vcvttps2dq_avx(auVar8);
        UNRECOVERED_JUMPTABLE = (code *)vpextrq_avx(auVar8,0);
        auVar7 = vxorps_avx(auVar10,auVar10);
        uVar3 = vmovq_avx(auVar7._0_16_);
        vmovq_avx(auVar7._0_16_);
        syscall();
        auVar8 = vmovss_avx(*(undefined4 *)(puVar4 + -8));
        vptest_avx(auVar8,auVar8);
        if (!bVar6) {
        UNRECOVERED_JUMPTABLE = (code *)&DAT_004011c5;
        }
                        /* WARNING: Could not recover jumptable at 0x004011c3. Too many branches */
                        /* WARNING: Treating indirect jump as call */
        (*UNRECOVERED_JUMPTABLE)(auVar8._0_8_,lVar2,(long)puVar4 + -8,uVar3,in_RCX,in_R8,uVar5);
        return;
    }
    auVar8 = vmovq_avx(0x42dc0000);
    auVar8 = vcvttps2dq_avx(auVar8);
    lVar2 = vpextrq_avx(auVar8,0);
    syscall();
    auVar8 = vmovq_avx(0x42ca0000);
    auVar8 = vcvttps2dq_avx(auVar8);
    uVar5 = vpextrq_avx(auVar8,0);
    auVar8 = vmovq_avx(0x41800000);
    auVar8 = vcvttps2dq_avx(auVar8);
    vpextrq_avx(auVar8,0);
    auVar10 = vpxor_avx2(auVar10,auVar10);
    auVar9 = auVar10._0_16_;
    vmovq_avx(auVar9);
    vmovq_avx(auVar9);
    syscall();
    auVar7 = vxorps_avx(auVar7,auVar7);
    auVar8 = vcvtsi2ss_avx(auVar7._0_16_,uVar5);
    vptest_avx(auVar8,auVar8);
    if (bVar6) {
        auVar8 = vmovq_avx(0x43800000);
        auVar8 = vcvttps2dq_avx(auVar8);
        auVar7 = ZEXT1632(auVar8);
        auVar8 = vmovq_avx(puVar4);
        auVar10 = vpaddq_avx2(ZEXT1632(auVar8),auVar7);
        puVar4 = (undefined *)vmovq_avx(auVar10._0_16_);
        auVar8 = vmovq_avx(0x42700000);
        auVar8 = vcvttps2dq_avx(auVar8);
        vpextrq_avx(auVar8,0);
        auVar7 = vpxor_avx2(auVar7,auVar7);
        auVar7 = vpcmpeqd_avx2(auVar7,auVar7);
        auVar7 = vpsrld_avx2(auVar7,0x1f);
        vpextrq_avx(auVar7._0_16_,0);
        syscall();
        auVar7 = vpxor_avx2(auVar7,auVar7);
        auVar7 = vpcmpeqd_avx2(auVar7,auVar7);
        auVar7 = vpsrld_avx2(auVar7,0x1f);
        vpextrq_avx(auVar7._0_16_,0);
        vpextrq_avx(auVar7._0_16_,0);
        auVar8 = vmovq_avx(0x42080000);
        auVar8 = vcvttps2dq_avx(auVar8);
        vpextrq_avx(auVar8,0);
        auVar8 = vmovq_avx(0x72756f59);
        uVar1 = vmovss_avx(auVar8);
        *(undefined4 *)(puVar4 + -0x28) = uVar1;
        auVar8 = vmovq_avx(0x65646920);
        uVar1 = vmovss_avx(auVar8);
        *(undefined4 *)(puVar4 + -0x24) = uVar1;
        auVar8 = vmovq_avx(0x7469746e);
        uVar1 = vmovss_avx(auVar8);
        *(undefined4 *)(puVar4 + -0x20) = uVar1;
        auVar8 = vmovq_avx(0x61682079);
        uVar1 = vmovss_avx(auVar8);
        *(undefined4 *)(puVar4 + -0x1c) = uVar1;
        auVar8 = vmovq_avx(0x65622073);
        uVar1 = vmovss_avx(auVar8);
        *(undefined4 *)(puVar4 + -0x18) = uVar1;
        auVar8 = vmovq_avx(0x76206e65);
        uVar1 = vmovss_avx(auVar8);
        *(undefined4 *)(puVar4 + -0x14) = uVar1;
        auVar8 = vmovq_avx(0x64696c61);
        uVar1 = vmovss_avx(auVar8);
        *(undefined4 *)(puVar4 + -0x10) = uVar1;
        auVar8 = vmovq_avx(0x64657461);
        uVar1 = vmovss_avx(auVar8);
        *(undefined4 *)(puVar4 + -0xc) = uVar1;
        lVar2 = 0xa2e;
        auVar8 = vmovq_avx(0xa2e);
        uVar1 = vmovss_avx(auVar8);
        *(undefined4 *)(puVar4 + -8) = uVar1;
        auVar8 = vxorps_avx(auVar8,auVar8);
        uVar1 = vmovss_avx(auVar8);
        *(undefined4 *)(puVar4 + -4) = uVar1;
        syscall();
    }
    else {
        auVar8 = vmovq_avx(0x42740000);
        auVar8 = vcvttps2dq_avx(auVar8);
        vpextrq_avx(auVar8,0);
        vmovq_avx(auVar9);
        vmovq_avx(auVar9);
        vmovq_avx(auVar9);
        syscall();
        auVar8 = vmovq_avx(0x42ca0000);
        auVar8 = vcvttps2dq_avx(auVar8);
        vpextrq_avx(auVar8,0);
        auVar8 = vmovq_avx(0x40e00000);
        auVar8 = vcvttps2dq_avx(auVar8);
        vpextrq_avx(auVar8,0);
        vmovq_avx(auVar9);
        vmovq_avx(auVar9);
        syscall();
        auVar8 = vmovq_avx(0x42ca0000);
        auVar8 = vcvttps2dq_avx(auVar8);
        vpextrq_avx(auVar8,0);
        auVar8 = vmovq_avx(0x41880000);
        auVar8 = vcvttps2dq_avx(auVar8);
        vpextrq_avx(auVar8,0);
        vmovq_avx(auVar9);
        vmovq_avx(auVar9);
        syscall();
    }
    auVar8 = vmovq_avx(0x43800000);
    auVar8 = vcvttps2dq_avx(auVar8);
    auVar9 = vmovq_avx(puVar4);
    auVar7 = vpaddq_avx2(ZEXT1632(auVar9),ZEXT1632(auVar8));
    vmovq_avx(auVar7._0_16_);
    auVar8 = vmovq_avx(0x42700000);
    auVar8 = vcvttps2dq_avx(auVar8);
    uVar5 = vpextrq_avx(auVar8,0);
    auVar8 = vxorps_avx(auVar8,auVar8);
    vpextrq_avx(auVar8,0);
    syscall();
    *(char *)(lVar2 + 0x59) = *(char *)(lVar2 + 0x59) + (char)uVar5;
                        /* WARNING: Bad instruction - Truncating control flow here */
    halt_baddata();
}
```

A quick visual scan reveals that the decompilation had trouble recovering the last instructions of the first if block, but we will leave this for later. We also see that the program is composed of a single function (the entrypoint), but it calls instructions such as `vmovq_avx` and `vcvttps2dq_avx` which I have never met before. They complicate the decompilation, so it would be better to rely on the disassembly.

These instructions are part of the [AVX (Advanced Vector Extensions) extensions to the x86 instructions set](https://en.wikipedia.org/wiki/Advanced_Vector_Extensions) and they are used to perform a single instruction on multiple pieces of data. Since this is my first time dealing with them, I first tried to extract information from what I was already familiar with: the syscalls.

## The syscalls

As you can see in the disassembly, a few system calls are being made. I identified them by running the program in GDB and breaking before the calls to retrieve the value of the `RAX` register (the number of the system call). Once this was done, I was left with something that looks like this:

```c
void processEntry entry(void)
{
    ...
    prctl(...);
    ...
    if (!fork()) {
        ...
        wait();
        ...
        if (...) {
            UNRECOVERED_JUMPTABLE = (code *)&DAT_004011c5;
        }
                        /* WARNING: Could not recover jumptable at 0x004011c3. Too many branches */
                        /* WARNING: Treating indirect jump as call */
        ...
        return;
    }
    ...
    int ppid = getppid();
    ...
    ptrace(PTRACE_ATTACH, ppid, 0, 0, 0);
    ...
    if (...) {
        ...
        exit();
        ...
        write(...);
    }
    else {
        // The child goes here
        ...
        wait();
        ...
        ptrace(PTRACE_CONT, ppid, 0, 0, 0);
        ...
        ptrace(PTRACE_DETACH, ppid, 0, 0, 0);
    }
    ...
    exit();
    ...
}
```

So we can see that the program forks, is attached to by the child, but nothing interesting seems to be done before the parent's execution is resumed. An important missing piece is the code that should prompt me for my name and registration code. At this point I was thought that the child might play with the parent's memory to make the `UNRECOVERED_JUMPTABLE` section executable. 

To further my analysis, I tried to find who between the child and the parent was in charge of asking the two pieces of information. The problem was that I could run both inside the debugger (use `set follow-fork-mode [child|parent]` in gdb to follow one or the other), but neither asked me for my information before quitting, and that puzzled me... What was interesting, though, is that the child did ask for the information _after_ exiting, so I thought the corresponding code was most likely executed by the parent.

## Inside the parent

Ghidra's disassembly around the `UNRECOVERED JUMPTABLE` looks as such:

```asm
        004011ab 0f 05           SYSCALL    ; Call to wait()
        004011ad 48 8d 1d        LEA        RBX,[DAT_004011c5]
                 11 00 00 00
        004011b4 c5 fa 10        VMOVSS     XMM0,dword ptr [RSP + -0x8]
                 44 24 f8
        004011ba c4 e2 79        VPTEST     XMM0,XMM0
                 17 c0
        004011bf 48 0f 44 c3     CMOVZ      RAX,RBX
        004011c3 ff e0           JMP        RAX
                             DAT_004011c5           XREF[1]:  entry:004011ad(*)  
        004011c5 c5              ??         C5h
        004011c6 fd              ??         FDh
        004011c7 ef              ??         EFh
        004011c8 c0              ??         C0h
        004011c9 c5              ??         C5h
        004011ca fd              ??         FDh
        004011cb 76              ??         76h
        004011cc c0              ??         C0h
```

In plain English, the code above takes a pointer to `DAT_004011c5` and jumps to it if `XMMO` is 0 (`CMOVZ` is a conditional `MOV`). Therefore, we know that what follows `DAT_004011c5` is not data but instructions! We can then safely disassemble the bytes in Ghidra and resolve the `UNRECOVERED JUMPTABLE` problem! To confirm this, we can simply jump over the `JMP RAX` instruction or patch it to `NOP` and continue execution to see that we are indeed asked for our information. For some reason that I didn't have the time to investigate, the `VPTEST` instruction (a simple `TEST` in AVX) returns true when the program is not being debugged, which is why I simply decided to patch and forget.

## The gist of the problem

By looking at the patterns in the newly disassembled code, and using the same technique of identifying syscalls, I was able to determine that the part of the code in charge of handling my information was most likely the block starting at `0x40187a`. In fact, there were three important blocks. 

The first one was in charge of handling the registration code:

```asm
    40187a:	c5 d5 ef ed          	vpxor       %ymm5,%ymm5,%ymm5
    40187e:	48 8d bc 24 40 ff ff 	lea         -0xc0(%rsp),%rdi
    401886:	48 0f b6 07          	movzbq      (%rdi),%rax
    40188a:	c4 e1 f9 6e c0       	vmovq       %rax,%xmm0
    40188f:	c4 e3 7d 38 c0 00    	vinserti128 $0x0,%xmm0,%ymm0,%ymm0
    401895:	b8 30 00 00 00       	mov         $0x30,%eax
    40189a:	c4 e1 f9 6e c8       	vmovq       %rax,%xmm1
    40189f:	c4 e3 75 38 c9 00    	vinserti128 $0x0,%xmm1,%ymm1,%ymm1
    4018a5:	c5 fd fb c1          	vpsubq      %ymm1,%ymm0,%ymm0
    4018a9:	b8 0a 00 00 00       	mov         $0xa,%eax
    4018ae:	c4 e1 f9 6e d0       	vmovq       %rax,%xmm2
    4018b3:	c4 e3 6d 38 d2 00    	vinserti128 $0x0,%xmm2,%ymm2,%ymm2
    4018b9:	c4 e2 55 40 ea       	vpmulld     %ymm2,%ymm5,%ymm5
    4018be:	c5 d5 fe e8          	vpaddd      %ymm0,%ymm5,%ymm5
    4018c2:	c5 f5 ef c9          	vpxor       %ymm1,%ymm1,%ymm1
    4018c6:	c4 e2 75 29 c1       	vpcmpeqq    %ymm1,%ymm1,%ymm0
    4018cb:	c5 fd 73 d0 3f       	vpsrlq      $0x3f,%ymm0,%ymm0
    4018d0:	c4 e1 f9 6e cf       	vmovq       %rdi,%xmm1
    4018d5:	c4 e3 75 38 c9 00    	vinserti128 $0x0,%xmm1,%ymm1,%ymm1
    4018db:	c5 f5 fe c8          	vpaddd      %ymm0,%ymm1,%ymm1
    4018df:	c4 e3 f9 16 cf 00    	vpextrq     $0x0,%xmm1,%rdi
    4018e5:	80 3f 0a             	cmpb        $0xa,(%rdi)
    4018e8:	74 05                	je          0x4018ef
    4018ea:	80 3f 00             	cmpb        $0x0,(%rdi)
    4018ed:	75 97                	jne         0x401886
```

The second one was in charge of the name:

```asm
    4018ef:	c5 f9 6e 05 be 02 00 	vmovd       0x2be(%rip),%xmm0
    4018f7:	c5 f9 6e 0d ba 02 00 	vmovd       0x2ba(%rip),%xmm1
    4018ff:	48 8d 7c 24 80       	lea         -0x80(%rsp),%rdi
    401904:	c5 d9 ef e4          	vpxor       %xmm4,%xmm4,%xmm4
    401908:	c4 e3 59 20 27 00    	vpinsrb     $0x0,(%rdi),%xmm4,%xmm4
    40190e:	c4 e2 79 17 e4       	vptest      %xmm4,%xmm4
    401913:	74 38                	je          0x40194d
    401915:	c5 e9 ef d2          	vpxor       %xmm2,%xmm2,%xmm2
    401919:	c4 e3 69 20 17 00    	vpinsrb     $0x0,(%rdi),%xmm2,%xmm2
    40191f:	c5 f9 ef c2          	vpxor       %xmm2,%xmm0,%xmm0
    401923:	c4 e2 79 40 c1       	vpmulld     %xmm1,%xmm0,%xmm0
    401928:	c5 ed ef d2          	vpxor       %ymm2,%ymm2,%ymm2
    40192c:	c4 e2 6d 29 d2       	vpcmpeqq    %ymm2,%ymm2,%ymm2
    401931:	c5 ed 73 d2 3f       	vpsrlq      $0x3f,%ymm2,%ymm2
    401936:	c4 e1 f9 6e e7       	vmovq       %rdi,%xmm4
    40193b:	c4 e3 5d 38 e4 00    	vinserti128 $0x0,%xmm4,%ymm4,%ymm4
    401941:	c5 dd fe e2          	vpaddd      %ymm2,%ymm4,%ymm4
    401945:	c4 e3 f9 16 e7 00    	vpextrq     $0x0,%xmm4,%rdi
    40194b:	eb b7                	jmp         0x401904
```

And the third one was in charge of the final decision:

```asm
    40194d:	c5 f9 6e 0d 49 02 00 	vmovd       0x249(%rip),%xmm1
    401955:	c5 f9 ef c1          	vpxor       %xmm1,%xmm0,%xmm0
    401959:	c5 f9 ef c5          	vpxor       %xmm5,%xmm0,%xmm0
    40195d:	c4 e2 79 17 c0       	vptest      %xmm0,%xmm0
    401962:	0f 84 1f 01 00 00    	je          0x401a87
```

At this point I decided that it would be convenient to develop a better understanding of AVX.

### AVX Essentials

AVX introduces new registers of 128 bits: `XMM[0-31]` and 256 bits: `YMM[0-31]`, where the first 128 bits are covered by the `XMM_` equivalent, just like `EAX` covers the first 32 bits of `RAX`.

AVX also introduces a bunch of new instructions mostly starting with the `VP` prefix and most have an equivalent in 64 bits. For example, `VPXOR` does a XOR in 128 bits in the same way that `XOR` does a XOR operation in 64 bits (or less). Other similar instructions are `VPTEST`, `VPADDD`, `VPSUBQ` and `VPMULLD`. We also have `VMOVQ` which moves a value from a 64-bit register to a 128-bit register and `VPSRLQ` which does a logical shift right of a 128-bit register.

With this new knowledge, I took a second look at the previous blocks and understood them better.

## Second analysis of the blocks

The last block will jump to a section that prints `Your identity has been validated` (at address `0x401a87`) if `XMM0 ^ XMM1 ^ XMM5 == 0`. 

I ran the program a few times with different inputs and determined that the value placed into `XMM1` at `0x40194d` was constantly `0x45425943`.

The content of `XMM0` is modified for the last time in the second block. We can see that it's a loop because of the last `JMP` instruction, and analyzing it dynamically with GDB tells us that it's the part involving the name. The result is therefore constant since we will always be using `Mateo Alvarez`, as stated in the description of the challenge. We then have `XMM0` set to `0xee8c028c`.

The last missing piece is `XMM5`. For the result of the triple-XOR to be 0, we must have `XMM5 = XMM0 ^ XMM1 = 0x45425943 ^ 0xee8c028c = 0xabce5bcf = 2882427855`.

## The last piece of the puzzle

The value of `XMM5` is modified indirectly in the first block through the use of the `YMM5` register. Since we will need to forge a registration code, a better understanding of the block is necessary. The relationship between the first block and the registration code was confirmed dynamically with GDB.

To better understand the code block, I figured it was better to break it down.

First, the `RDI` register is set to hold a pointer to the ascii string representing our code sent as input and `YMM5` is set to `0x00`.
```asm
    40187a:	c5 d5 ef ed          	vpxor       %ymm5,%ymm5,%ymm5
    40187e:	48 8d bc 24 40 ff ff 	lea         -0xc0(%rsp),%rdi
```

The second part is where the code jumps to at the end of the loop. The code takes care of placing the next char into `YMM0`.
```asm
    401886:	48 0f b6 07          	movzbq      (%rdi),%rax
    40188a:	c4 e1 f9 6e c0       	vmovq       %rax,%xmm0
    40188f:	c4 e3 7d 38 c0 00    	vinserti128 $0x0,%xmm0,%ymm0,%ymm0
```

The third part subtracts `0x30` from the current character, which yields the integer corresponding to the ascii character ('1' -> `0x01`, '6' -> `0x06`).
```asm
    401895:	b8 30 00 00 00       	mov         $0x30,%eax
    40189a:	c4 e1 f9 6e c8       	vmovq       %rax,%xmm1
    40189f:	c4 e3 75 38 c9 00    	vinserti128 $0x0,%xmm1,%ymm1,%ymm1
    4018a5:	c5 fd fb c1          	vpsubq      %ymm1,%ymm0,%ymm0
```

The fourth part multiplies `YMM5` by `0x0A` and adds the previous integer to the result. We therefore end up with something like this: `YMM5 = YMM5 * 10 + (YMM0 - 0x30)`. If `YMM5` was equal to, say, `36`, and the current integer was `5`, then the result would be `365`.
```asm
    4018a9:	b8 0a 00 00 00       	mov         $0xa,%eax
    4018ae:	c4 e1 f9 6e d0       	vmovq       %rax,%xmm2
    4018b3:	c4 e3 6d 38 d2 00    	vinserti128 $0x0,%xmm2,%ymm2,%ymm2
    4018b9:	c4 e2 55 40 ea       	vpmulld     %ymm2,%ymm5,%ymm5
    4018be:	c5 d5 fe e8          	vpaddd      %ymm0,%ymm5,%ymm5
```

The fifth part looks fancy, but it simply increments `RDI` so that it points to the next character.
```asm
    4018c2:	c5 f5 ef c9          	vpxor       %ymm1,%ymm1,%ymm1
    4018c6:	c4 e2 75 29 c1       	vpcmpeqq    %ymm1,%ymm1,%ymm0
    4018cb:	c5 fd 73 d0 3f       	vpsrlq      $0x3f,%ymm0,%ymm0
    4018d0:	c4 e1 f9 6e cf       	vmovq       %rdi,%xmm1
    4018d5:	c4 e3 75 38 c9 00    	vinserti128 $0x0,%xmm1,%ymm1,%ymm1
    4018db:	c5 f5 fe c8          	vpaddd      %ymm0,%ymm1,%ymm1
    4018df:	c4 e3 f9 16 cf 00    	vpextrq     $0x0,%xmm1,%rdi
```

Finally, the last part handles the end of the string.
```asm
    4018e5:	80 3f 0a             	cmpb        $0xa,(%rdi)
    4018e8:	74 05                	je          0x4018ef
    4018ea:	80 3f 00             	cmpb        $0x0,(%rdi)
    4018ed:	75 97                	jne         0x401886
```

The fourth part is the interesting one. Running it over the whole registration code, we simply end up with... the code, as an integer. In other words, the loop is a simple `atoi('<registration_code>')`.

Since we have determined that `XMM5` was supposed to be `2882427855`, I ran the program with the expected parameters and...

```shell
Please enter your name: Mateo Alvarez
Please enter your registration code: 2882427855
Your identity has been validated.
```

It worked!

## Conclusion

Thanks for reading!

It took me a lot of time to get acquainted with the new instructions both statically and dynamically. I was also slowed down by mistakes on my end that resulted with inconsistent values, which cost me a lot of time. I definitely need to be careful with this!

Since there were only three solves, I think that people were also afraid of the AVX instructions, even if, in the end, the program's logic was not very complicated.

It also occurred to me that it should definitely be possible to solve the challenge with [angr](https://angr.io/), but a quick and unexperienced attempt was not fruitful enough to pursue.

Thanks a lot to the challenge creators and organizers of the event; I definitely learned a lot along the way!
