
#include <unistd.h> // for syscall numbers

void _start() {
  // Stack-allocated string
  char msg[] = "Hello, World!\n";

  // Syscall: write(int fd, const void *buf, size_t count)
  asm volatile("mov $1, %%rax\n"   // syscall number for write (sys_write)
               "mov $1, %%rdi\n"   // file descriptor (1 = stdout)
               "lea (%0), %%rsi\n" // use RIP-relative addressing to load buffer
               "mov %1, %%rdx\n"   // message length
               "syscall\n"         // make the syscall
               :
               : "r"(msg), "r"(sizeof(msg) - 1)
               : "%rax", "%rdi", "%rsi", "%rdx");

  // Syscall: exit(int status)
  asm volatile("mov $60, %%rax\n"   // syscall number for exit (sys_exit)
               "xor %%rdi, %%rdi\n" // status (0)
               "syscall\n"          // make the syscall
               :
               :
               : "%rax", "%rdi");
}
