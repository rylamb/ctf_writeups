---
layout: post
title: HTB Cyber Apocalypse 2021 - Authenticator (Reverse Engineering)
date: 2021-04-19
categories: HackTheBox
---

Category: Reverse Engineering

Difficulty: 1/4 stars

## Overview



## File Analysis
After downloading and extracting the file, we can begin by running `file` to better understand what this file is. The result shows that the file is a x86-64 linux unstripped executable.
```
$file authenticator 
authenticator: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=66286657ca5a06147189b419238b2971b11c72db, not stripped.

```
Next we'll run `checksec` to see what kind of protections the executable has. This executable shows stack canaries enabled, as well as ASLR and a non-executable stack (NX). This is fine since we won't need to do any binary exploitation this time.
```
$checksec --format=json --file=Authenticator
{
   "authenticator":{
      "relro":"full",
      "canary":"yes",
      "nx":"yes",
      "pie":"yes",
      "rpath":"no",
      "runpath":"no",
      "symbols":"yes",
      "fortify_source":"no",
      "fortified":"0",
      "fortify-able":"2"
   }
}
```
Running `strings` shows what looks to be a prompt to enter a pin. It seems that the pin is the flag and we are provided with the proper flag format.
```
$strings authenticator
...[truncated]...
Authentication System 
Please enter your credentials to continue.
Alien ID: 
11337
Access Denied!
Pin: 
Access Granted! Submit pin in the flag format: CHTB{fl4g_h3r3}
...[truncated]...
```
Since the executable is not stripped, we can run the executable in GDB. Executing `info func` inside of GDB shows us the functions within our program. Here we can see a `checkpin` method.
```m
(gdb) info func
All defined functions:

Non-debugging symbols:
0x0000000000000718  _init
0x0000000000000740  putchar@plt
0x0000000000000750  strlen@plt
0x0000000000000760  __stack_chk_fail@plt
0x0000000000000770  setbuf@plt
0x0000000000000780  printf@plt
0x0000000000000790  fgets@plt
0x00000000000007a0  strcmp@plt
0x00000000000007b0  usleep@plt
0x00000000000007c0  __cxa_finalize@plt
0x00000000000007d0  _start
0x0000000000000800  deregister_tm_clones
0x0000000000000840  register_tm_clones
0x0000000000000890  __do_global_dtors_aux
0x00000000000008d0  frame_dummy
0x00000000000008da  printstr
0x0000000000000959  checkpin
0x00000000000009db  main
0x0000000000000b00  __libc_csu_init
0x0000000000000b70  __libc_csu_fini
0x0000000000000b74  _fini
```
Analyzing the file with Ghidra allows us to look closer at the `checkpin` function using the decompiler feature. With a higher level view, we see that this method iterates the characters of the string `}a:Vh|}a:g}8j=}89gV<p<}:dV8<Vg9}V<9V<:j|{:` and attempts to XOR each character with the unsigned integer value `9`. This function appears to be checking the user input against the encoded pin, exiting prematurely if an invalid match is found.

```
undefined8 checkpin(char *param_1)

{
  size_t sVar1;
  int local_24;
  
  local_24 = 0;
  while( true ) {
    sVar1 = strlen(param_1);
    if (sVar1 - 1 <= (ulong)(long)local_24) {
      return 0;
    }
    if ((byte)("}a:Vh|}a:g}8j=}89gV<p<}:dV8<Vg9}V<9V<:j|{:"[local_24] ^ 9U) != param_1[local_24])
    break;
    local_24 = local_24 + 1;
  }
  return 1;
}
```
To get the flag, we can construct a python script that will decode the pin seen in the code above.

## Solution (Python 3.9)
```python
import sys

# Convert the encoded pin to bytes
pin = b'}a:Vh|}a:g}8j=}89gV<p<}:dV8<Vg9}V<9V<:j|{:' 

# Print the flag prefix
sys.stdout.write('CHTB{')

# XOR each character with 9, convert to ascii, and print.
# Note: For-each loops on bytes automatically converts the
#       bytes to integers.
for c in pin:
    sys.stdout.write(chr(c ^ 9))

# Print the flag suffix
sys.stdout.write('}\n')
```
```
$python3 auth.py 
CHTB{th3_auth3nt1c4t10n_5y5t3m_15_n0t_50_53cur3}
```