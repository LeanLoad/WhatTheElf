/* Preloaded via `ld.so --preload`: its constructor runs after the loader has
 * mapped + relocated every object but before the target program's own
 * constructors / entry, so it stops execution right at program start. Built
 * -nostdlib (raw _exit syscall) so it pulls in no libc dependency. */
__attribute__((constructor(101))) static void exit_before_main(void) {
    __asm__ volatile("syscall" :: "a"(60), "D"(0) : "rcx", "r11", "memory"); /* _exit(0) */
}
