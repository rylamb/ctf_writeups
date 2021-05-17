---
Title: BabyRE
Date:   2021-02-23
Category: Reversing
Difficulty: Easy
Challenge Creator: Xh4H
---

**Challenge Description:**&quot;Show us your basic skills! (P.S. There are 4 ways to solve this, are you willing to try them all?)&quot;

Download and unzip the archive to retrieve the file. Analyzing with the `file` command show that this is a Linux executable.

![image1](./images/Picture1.png)

If we make the file executable with `chmod +x` and run it, it asks for a key to be inserted. Simply hitting enter gives us the message &quot;Try again later.&quot;

![image2](./images/Picture2.png)

## The Easy Way

Running `hexdump -C` shows the readable contents of the file.

![image3](./images/Picture3.png)

![image4](./images/Picture4.png)

Within the contents of the file is what appears to be a flag that is not quite properly formatted, a note saying, &quot;Don&#39;t run `strings` on this challenge, that is not the way!!!!&quot;. There are also the messages &quot;Insert key&quot; and &quot;Try again later&quot; with the value &quot;abcde122313&quot; nested between. We can try entering that as the key. Naturally we could have found the same information using `strings`.

## The Harder Way

We can take a closer look at how the flag is being created by using radare2, analyzing the file with `aaa`, then disassembling main.

![image5](./images/Picture5.png)

![image6](./images/Picture6.png)

The important pieces here are the variables on the stack…

![image7](./images/Picture7.png)

…and what looks to be flag construction and output.

![image8](./images/Picture8.png)

The break down of the code is as follows:

1. (0x11a3) The value [REDACTED] is loaded into the register RAX.
2. (0x11ad) Radare2 doesn&#39;t give a nice print out here, but if we split the values into hexadecimal bytes, reverse the order to account for little-endianness of x86 systems, and translate to an ASCII character, we can see that this line is storing the value [REDACTED] into the register RDX.
3. (0x11b7) [REDACTED], stored in RAX, is moved into the character pointer at the address referenced by RBP-0x40.
4. (0x11bb) [REDACTED], stored in RDX, is moved into var\_38h located at RBP-0x38.
5. (0x11bf) [REDACTED] is moved into var\_30h at the address of rbp-0x30.
6. (0x11c6) [REDACTED] is moved into var\_2ch at the address of rbp-0x2c.
7. (0x11cc – 0x11d0) Registers are loaded with our values in preparation for a system call.
8. (0x11d3) Puts() is called to print the value of our string located in the range of rbp-0x40 through rbp-0x20.

To simplify, this code simply constructs the string [REDACTED] and prints it to stdout. With this information we can bypass entering the key altogether!

## Solution

The full writeup is locked with the flag. [See the full writeup][writeup_url]

[writeup_url]: ./Baby%20RE.pdf
