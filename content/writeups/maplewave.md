+++
title = "Maplewave"
date = "2023-06-20T21:01:55-04:00"
author = "1t1n1 and Ch0ufleur"
# authorTwitter = "" #do not include @
cover = "/images/maplewave/maplewave_1.png"
# tags = ["RE", ""]
# keywords = ["", ""]
description = "A Reverse Engineering CTF challenge where Ch0ufleur and I dove into the details of the PulseAudio library..."
showFullContent = false
readingTime = false
hideComments = false
color = "" #color from the theme settings
+++

## Introduction
Our team, [PolyCyber](https://polycyber.io), is planning to host its own CTF competition a few months from now, so we were eager to see what other student clubs were doing across the country. Hence, we registered for MapleCTF, organized by The Maple Bacon CTF team of the University of British Columbia. This is what led us ([Ch0ufleur](https://ch0ufleur.dev) and 1t1n1) to try and tackle Maplewave-0, a “reverse engineering” and “audio” tagged challenge made by xal#3845.

## Tools
- [Cyberchef](https://gchq.github.io/CyberChef/), a web platform used to perform various type of encoding, decoding and data analysis;
- xxd, a tool for analyzing a file’s binary;
- strings, a command-line tool that outputs readable text from a file’s content;
- [Ghidra](https://ghidra-sre.org), a program decompiler, debugger and reverse engineering tool;
- [AccessData FTKImager](https://accessdata.com/product-download/ftk-imager-version-4-5), a forensics software used to view and find data in files up or whole disk partitions;
- gdb, a command line debugger, which can be used for dynamic analysis.

## Challenge prompt
> I've recorded some flags using some ancient proprietary software. The floppy disk containing the playback program is lost forever. Can you recover the audio?  
> Separate the words you hear with spaces and wrap them with maple{}.  
> The flag will match the regex ^maple{([a-z]+ )+[0-9]+}$  
> Author: xal#3845

## Files
Two files were provided with the challenge prompt. The first one was an executable command-line tool name _maplewave_. The second one was the encoded audio of the flag, _flag0.maplewave_.

## Research
Our initial thoughts after reading the challenge prompt led us to believe that we were looking for an ancient program in order to play the audio. We spent about half an hour trying to uncover old proprietary software in the far corners of the internet. Apart from the discovery that, for a few years, music had indeed been saved on floppy disks, we still had no idea of which potential formats we could try and convert the audio file to. Since the file was of MAPLEWAVE type, we agreed that it would probably be a .wav file that had been modified by the maplewave program (though we were not sure of it at that point).

Before opening up Ghidra, we took a look inside both files using the strings tool, xxd and Access Data FTK Imager. The only thing that we discovered through that analysis was that the first bytes of the flag0.maplewave spelled MPLEWAVE, and that another set of bytes appeared a few addresses further spelling what seemed to be a random character. Curious as to the significance of this set of bytes, we tried and used the maplewave program to record audio. The program could be used as follows:

> maplewave \[OPTIONS\] <out.maplewave>  
> Options :  
> compression : -c (0,1,2) defaults to 0

With all the audio that we recorded at different compression levels, we were unable to figure out the format of the file header following the initial MPLEWAVE bytes. We tried comparing each file with all the others and could not see any hints to that matter.

This is when we agreed that it would be best to switch our focus to the program itself - trying to reverse engineer it with the help of Ghidra surely would be the best way to go from there.

## Understanding the program
After loading the recording program, _maplewave_, into Ghidra, the analysis of the code began. We have done a few reverse engineering challenges before, but neither of us would say we are experts in it. We started with the main function, where we tried to understand how the program would parse the arguments and where they would end up in order to rename our variables accordingly.

A nice feature that Ghidra offers is the ability to rename variables, thus keeping track of where we are in our reversing process. You’ll agree that “ivar8” is far less understandable than “filename”. This is a methodology that we followed through the entire reverse engineering process because of its convenience.

The main function looked rather odd to us, since the _return 0;_ instruction (indicating that no errors occurred and that all completed successfully) was present in the first lines of the function. Even more so, a complete block of code seemed unreachable at the end of the main function. We decided to put our focus on the function called right before the _return 0;_ instruction, since it was surely the one that would start the recording process. Obviously, we renamed it accordingly. Let’s call it _recordAudio()_ for the purposes of this writeup.

The _recordAudio()_ function contained calls to functions that seemed interesting to us : _pa_simple_new()_ and _pa_simple_read()_.  
A quick Google search and we knew that these were part of a library called libpulse, which can be used to record and playback audio files, amongst other purposes such as managing the audio settings in Linux, for example. This is where we started to look if there was a way to use libpulse to decode the file.

### Libpulse and paplay
This is where began an eppopea to try and clone libpulse sources locally and run an example program that came with it, _pacat.c_. This program, [according to the documentation we found online](https://www.freedesktop.org/software/pulseaudio/doxygen/pacat-simple_8c-example.html), was a sample that could play a piece of audio encoded with libpulse.  We will spare you the hurdles of trying to compile the sources with gcc and installing all missing libraries - we were faced with numerous compilation errors and circular dependencies. Despite never succeeding to execute the _pacat.c_ program, other research on Google hinted us to another tool called paplay. This one is a command line tool already installed on Linux distributions that use the libpulse library. The help provided with paplay allowed for a “raw” option used to read an audio file that had no specified format. Our ears have never suffered that much! But, and this was for us a little victory, we managed to hear a sound! Playing around with different parameters such as the number of channels and the rate would give us slowed down audio, but we never managed to get anything clear. We still had this feeling that the audio was a recorded speech.

### Libpulse function parameters
Even if the last hour of trying to use libpulse and paplay to read the _flag0.maplewave_ file was not as productive as we’d wanted it to be, we still came out of it with a better understanding of how the libpulse library worked - including some of its functions.

Back to the program in Ghidra, after a bit of work to try and make sense of what the _recordAudio()_ function did, we singled out the _pa_simple_new()_ function which took 10 parameters. This kept us wondering for a bit, since the documentation of libpulse stated that the function would only take 9 \[1\]. Even if we were to ignore the last one, we could not figure out at first where to retrieve the data that was passed to the function. Our knowledge in using Ghidra stopped us at that point, and we became convinced there was no way to retrieve the parameters with a static code analysis.

### Try a dynamic analysis with gdb
That's where we decided to use gdb to dynamically analyze the program and, hopefully, retrieve the value of the parameters that are passed to _pa_simple_new()_. Since the program was compiled with PIE, the addresses were not the same as the ones we saw on Ghidra. To overcome this obstacle, we contacted a teammate, which gave us knowledge of the _info proc mappings_ command for gdb. This useful trick displayed the address range that gdb uses for the program being debugged.

![Console opened with info proc mappings command typed in gdb, showing the starting adress of the maplewave program.](/images/maplewave/maplewave_1.png)

_The maplewave executable process and the associated start address_

With this new information, we were able to convert the address of the _pa_simple_new()_ function call that we had in Ghidra to the address that was used by gdb. Then, we placed a breakpoint at the desired instruction, and analyzed the stack.

Another problem appeared: we could not find the parameters we were looking for in the stack. In fact, it didn’t even have enough parameters to call the function! We wondered where the missing arguments were. The thing is, for Linux 64-bits x86 binaries, the cdecl calling convention states that the first six arguments must be sent through the registers RDI, RSI, RDX, RCX, R8 and R9 (in this particular order). The rest then goes to the stack.

Having found that information, the problem was solved easily; all we had to do was to look in the registers! The _pa_simple_new()_ function takes a handful of arguments, but the only one that was interesting to us was the sixth, so we dumped R9’s value and it displayed 5555555590d8.

### Back to finding pa_simple_new() parameter values
Now what did we find at this address? The answer is: a structure. This means that we needed to understand the offsets of the struct and what they refer to if we wanted to make sense of it.

![Showcasing the sample_type data structure with values for all addresses in Ghidra](/images/maplewave/maplewave_2.png)

_Data structure **sample_type** in Ghidra_

[This page](https://www.freedesktop.org/software/pulseaudio/doxygen/sample_8h_source.html) gives access to the source code of the file that defines the _pa_simple_spec_ struct, which is the type of the argument we are interested in \[4\]. With this knowledge, we were able to find the number of channels and the rate that were used when recording the audio. So let’s try it!

![Command-line interface showing the corresponding paplay command : paplay --raw flag0.maplewave --channels=1 --rate=16000](/images/maplewave/maplewave_3.png)

_The paplay command executed with the retrieved parameters from the stack_

### Building a WAV file header
Ouch… Doesn’t sound like a human voice to me! Did we miss something? If you take the time to learn more about the wave file format, you can see that we did, in fact, miss a parameter. There is a property called “bits per sample” which is set to 16 by default. To modify this behavior, we have decided to override the _flag0.maplewave_ file header with our own WAV header. Since there is an offset for the number of channels, rate and number of bits per sample, the header is a good way to force the use of our options. We used CyberChef.org to write our forged header over the original _flag0.maplewave_ file. When we set the bits per sample to 8, we obtained a usable wave file. If you open it with any audio file player, you can hear someone reciting the words and numbers that compose the flag!

## Conclusion
That’s it! This may be quite a long writeup, but we really wanted to show the process that we went through to obtain the solution. This track also had the maplewave-1 and maplewave-2 challenges, presumably referencing the compression levels. We didn't have enough time to tackle them, but may do so in the future with the files downloaded during the competition.

We hope you had fun reading this writeup and learning cool stuff about wave files and reversing! Thanks to the MapleCTF organizers for this great competition, and a special thanks to xal#3845 for designing the challenge!

## References
\[1\] Free Desktop, PulseAudio. (2022) simple.h File Reference. \[online\]. Available : https://www.freedesktop.org/software/pulseaudio/doxygen/simple_8h.html#add9a7dce4e15955d4296726c26206689

\[2\] Free Desktop, PulseAudio. (2022) sample.h. \[online\]. Available: https://www.freedesktop.org/software/pulseaudio/doxygen/sample_8h_source.html

