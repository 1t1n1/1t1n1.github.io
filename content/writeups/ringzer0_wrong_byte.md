---
title: "Wrong Byte! - RingZer0"
date: 2024-01-07T21:30:28-04:00
author: "1t1n1"
cover: "/images/ringzer0_wrong_byte/ringzer0_wrong_byte1.png"
description: "A byte-level Reverse Engineering challenge from RingZer0. Brace yourself for x86 assembly!"
showFullContent: false
readingTime: false
hideComments: false
color: ""
---

Ok so this challenge was a quick but cool one. We are given a simple ELF binary that prints a string of seemingly random characters when run and exits with a status of 1. Diving into the code gives a broader understanding of what happens before we receive this string as output, which eventually leads us to the flag.

## Initial analysis

First, let's see what we're playing with.

> $ file d04497a8afdee258a04b004eb029eed8
>
> d04497a8afdee258a04b004eb029eed8: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=4d43964329bcfe200c4cd48f640fa452b0797b02, not stripped

It's an ELF binary, so it's intended to be executed on Linux. When run, the file prints a string that looks like garbage and returns a non-null exit code, which could mean that something wrong happened.

> $ ./d04497a8afdee258a04b004eb029eed8 
> 
> #,3).<<+6=i14
>
> \$ echo \$?
>
> 1

## The Code

After running the program once, I was interested in looking at what's under the hood. To do so, I opened Ghidra and started disassembling and decompiling the program. It was pretty straightforward. As you can see by reading the following decompiled code of the main function, the program loads hexadecimal values into memory and then executes it.

``` C
undefined8 main(void) {
  undefined4 local_68;
  undefined4 local_64;
  undefined4 local_60;
  undefined4 local_5c;
  undefined4 local_58;
  undefined4 local_54;
  undefined4 local_50;
  undefined4 local_4c;
  undefined4 local_48;
  undefined4 local_44;
  undefined4 local_40;
  undefined4 local_3c;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  undefined4 local_1c;
  undefined4 local_18;
  undefined local_14;
  undefined4 *local_10;
  
  local_68 = 0x485e2beb;
  local_64 = 0xc180c931;
  local_60 = 0x13368022;
  local_5c = 0xe2c6ff48;
  local_58 = 0xee8348f8;
  local_54 = 0xc0314822;
  local_50 = 0x894801b0;
  local_4c = 0xfa8948c7;
  local_48 = 0x23c28348;
  local_44 = 0x3148050f;
  local_40 = 0xf3cb0c0;
  local_3c = 0xffd0e805;
  local_38 = 0x60cffff;
  local_34 = 0xf670d0b;
  local_30 = 0x30071e23;
  local_2c = 0x3a05203f;
  local_28 = 0x9133d04;
  local_24 = 0x3c382f2f;
  local_20 = 0x250c071b;
  local_1c = 0x27227a2e;
  local_18 = 0xa090210;
  local_14 = 0;
  local_10 = &local_68;
  (*(code *)local_10)();
  return 0;
}
```

These hex values correspond to the machine code, so we can easily disassemble those using [CyberChef](https://cyberchef.org) with the "Disassemble x86" operation accompanied with a "Swap Endianness". Here's what we get:

``` ASM
0x0000000000000000 EB2B                            JMP 0x000000000000002D
0x0000000000000002 5E                              POP RSI
0x0000000000000003 4831C9                          XOR RCX,RCX
0x0000000000000006 80C122                          ADD CL,0x22
0x0000000000000009 803613                          XOR BYTE PTR [RSI],0x13
0x000000000000000C 48FFC6                          INC RSI
0x000000000000000F E2F8                            LOOP 0x0000000000000009
0x0000000000000011 4883EE22                        SUB RSI,0x22
0x0000000000000015 4831C0                          XOR RAX,RAX
0x0000000000000018 B001                            MOV AL,0x01
0x000000000000001A 4889C7                          MOV RDI,RAX
0x000000000000001D 4889FA                          MOV RDX,RDI
0x0000000000000020 4883C223                        ADD RDX,0x23
0x0000000000000024 0F05                            SYSCALL
0x0000000000000026 4831C0                          XOR RAX,RAX
0x0000000000000029 B03C                            MOV AL,0x3C
0x000000000000002B 0F05                            SYSCALL
0x000000000000002D E8D0FFFFFF                      CALL 0x0000000000000002
0x0000000000000032 0C06                            OR AL,0x06
0x0000000000000034 0B0D670F231E                    OR ECX,DWORD PTR [0x0000000-0xE1DCF05F]
0x000000000000003A 07                              ???
0x000000000000003B 303F                            XOR BYTE PTR [RDI],BH
0x000000000000003D 20053A043D13                    AND BYTE PTR [0x0000000-0xECC2FB83],AL
0x0000000000000043 092F                            OR DWORD PTR [RDI],EBP
0x0000000000000045 2F                              ???
0x0000000000000046 383C1B                          CMP BYTE PTR [RBX+RBX],BH
0x0000000000000049 07                              ???
0x000000000000004A 0C25                            OR AL,25
0x000000000000004C 2E7A22                          HNT  JP 0x0000000000000071
0x000000000000004F 27                              ???
0x0000000000000050 1002                            ADC BYTE PTR [RDX],AL
0x0000000000000052 090A                            OR DWORD PTR [RDX],ECX
```

## A Deeper Analysis

When you look closely at the code, you can see that it basically executes the function that starts at `0x0000000000000002`. The function first XORs a key (0x13) to 34 bytes (0x22) coming from the RSI register, then write the xored values to STDOUT using the `sys_write` syscall (0x01) and finally exits, now with the `sys_exit` syscall (0x3C), but takes the time to set the exit status to 1 instead of 0. Since there doesn't seem to be a choice between different exit values, 1 could actually the default in this case and, in that case, we shouldn't waste too much time on it. 

Now that we understand the program and since we still don't have the flag, let's get back to the name of the challenge: _Wrong Byte!_. The name implies that only one byte is wrong, not more. If we summarize the program's intent once more, it essentially XORs a given large hex value with the 0x13 key. What if this key is the wrong byte? We would get a different output for sure. 

To do this, we first need to extract the hexadecimal value. Since it corresponds to the value of the RSI register and it is set using `POP RSI` at the first instruction of the function, then we know that it is the return address, which means the first address following `CALL 0x0000000000000002`. Also, the instructions `XOR RCX, RCX` and `ADD CL, 0x22` tell us that the size of the hex value is 0x22 bytes (34 bytes) because RCX is the counter register, holding the number of times the `LOOP` instruction will loop. And it just happens to be that there are exactly 34 bytes following `CALL 0x0000000000000002`! So we know that our large hexadecimal value is this:

> 0x0C060B0D670F231E07303F20053A043D13092F2F383C1B070C252E7A22271002090A

## To Automation

To automate the process of finding the right key, I built this Python script which tries to decrypt with different one byte keys and stops once it found the flag.

``` python
def xor_string(input_bytes, key):
  key_byte = bytes([key])
  result_bytes = bytes([b ^ key for b in input_bytes])
  result_string = result_bytes.decode('utf-8')
  return result_string

hexadecimal_value = 0x0C060B0D670F231E07303F20053A043D13092F2F383C1B070C252E7A22271002090A.to_bytes(34, 'big')

for key in range(255):
    result = xor_string(hexadecimal_value, key)
    if result.startswith('FLAG-'):
      print(f"Key = {key}, flag = {result[:-1]}")
      exit()
```

When run, we get:

> Key = 74, flag = FLAG-EiTMzujOpNwYCeervQMFod0hmZHC

## Conclusion

This was a nice challenge, well built to prevent or limit the use of decompilers. It's also a great way to learn the language for someone new or eager to learn.
