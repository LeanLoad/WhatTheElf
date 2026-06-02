/* Minimal freestanding AFL++-compatible coverage + (old-protocol) forkserver
 * runtime for glibc's self-contained ld.so.
 *
 * ld.so is linked -nostdlib/-nostartfiles and resolves nothing externally, so
 * the full afl-compiler-rt (which needs ~50 libc symbols) cannot be embedded.
 * This runtime defines exactly the symbols the AFL/SanitizerCoverage
 * instrumentation references (__afl_area_ptr, the guard hooks) and drives the
 * AFL forkserver using only raw x86_64 syscalls plus glibc-internal __environ.
 *
 * Build with PLAIN clang (never afl-clang-fast) so it is not itself
 * instrumented:
 *   clang -O2 -fno-stack-protector -fno-builtin -ffreestanding -fPIC \
 *         -fcf-protection=none -c aflrt.c -o aflrt.o
 */

#include <stdint.h>
#include <stddef.h>

#define MAP_SIZE   65536
#define FORKSRV_FD 198

/* x86_64 syscall numbers */
#define SYS_read  0
#define SYS_write 1
#define SYS_close 3
#define SYS_shmat 30
#define SYS_fork  57
#define SYS_exit  60
#define SYS_wait4 61

extern char **__environ;

/* The coverage map. Defaults to a private buffer so the inlined edge writes
 * are harmless before (or without) AFL attaching a shared region. */
static uint8_t __afl_area_initial[MAP_SIZE];
uint8_t *__afl_area_ptr = __afl_area_initial;

static long syscall3(long n, long a, long b, long c) {
  long ret;
  __asm__ volatile("syscall"
                   : "=a"(ret)
                   : "a"(n), "D"(a), "S"(b), "d"(c)
                   : "rcx", "r11", "memory");
  return ret;
}

static long syscall4(long n, long a, long b, long c, long d) {
  long ret;
  register long r10 __asm__("r10") = d;
  __asm__ volatile("syscall"
                   : "=a"(ret)
                   : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10)
                   : "rcx", "r11", "memory");
  return ret;
}

#ifdef AFLRT_MARKERS
static void mark(const char *s) {
  unsigned long n = 0;
  while (s[n]) n++;
  syscall3(SYS_write, 2, (long)s, n);
}
#else
#define mark(s) ((void)0)
#endif

static int read_all(int fd, void *buf, unsigned long n) {
  unsigned char *p = buf;
  unsigned long off = 0;
  while (off < n) {
    long r = syscall3(SYS_read, fd, (long)(p + off), n - off);
    if (r <= 0) return 0;
    off += (unsigned long)r;
  }
  return 1;
}

static int write_all(int fd, const void *buf, unsigned long n) {
  const unsigned char *p = buf;
  unsigned long off = 0;
  while (off < n) {
    long r = syscall3(SYS_write, fd, (long)(p + off), n - off);
    if (r <= 0) return 0;
    off += (unsigned long)r;
  }
  return 1;
}

static const char *afl_getenv(const char *key) {
  char **e = __environ;
  if (!e) return 0;
  for (; *e; ++e) {
    const char *s = *e;
    const char *k = key;
    while (*k && *s == *k) {
      ++s;
      ++k;
    }
    if (*k == 0 && *s == '=') return s + 1;
  }
  return 0;
}

static int afl_atoi(const char *s) {
  int v = 0, neg = 0;
  if (*s == '-') {
    neg = 1;
    ++s;
  }
  while (*s >= '0' && *s <= '9') v = v * 10 + (*s++ - '0');
  return neg ? -v : v;
}

static int afl_started = 0;

/* Attach AFL's shared coverage map and run the old-style forkserver handshake.
 * Returns in the forked child (which resumes the loader); the forkserver
 * parent loops here until AFL closes the control pipe. Safe to call when not
 * running under AFL: the shm lookup and pipe writes simply no-op. */
static void afl_start(void) {
  if (__environ == 0) return; /* wait until rtld publishes the environment */
  afl_started = 1;            /* attempt the handshake exactly once */

  mark("[afl_start]\n");

  const char *shm = afl_getenv("__AFL_SHM_ID");
  if (shm) {
    long p = syscall3(SYS_shmat, afl_atoi(shm), 0, 0);
    if (p != -1) __afl_area_ptr = (uint8_t *)p;
  }

  uint32_t hello = 0;
  if (!write_all(FORKSRV_FD + 1, &hello, 4)) return; /* not under a forkserver */

  for (;;) {
    uint32_t cmd;
    if (!read_all(FORKSRV_FD, &cmd, 4)) syscall3(SYS_exit, 0, 0, 0);

    long pid = syscall3(SYS_fork, 0, 0, 0);
    if (pid < 0) syscall3(SYS_exit, 1, 0, 0);
    if (pid == 0) {
      syscall3(SYS_close, FORKSRV_FD, 0, 0);
      syscall3(SYS_close, FORKSRV_FD + 1, 0, 0);
      return; /* child resumes the loader */
    }

    uint32_t pid32 = (uint32_t)pid;
    if (!write_all(FORKSRV_FD + 1, &pid32, 4)) syscall3(SYS_exit, 0, 0, 0);

    int status = 0;
    if (syscall4(SYS_wait4, pid, (long)&status, 0, 0) < 0)
      syscall3(SYS_exit, 1, 0, 0);

    if (!write_all(FORKSRV_FD + 1, &status, 4)) syscall3(SYS_exit, 0, 0, 0);
  }
}

/* Monotonic guard id allocator (single-threaded `--verify`, so no locking). */
static uint32_t afl_next_guard = 0;

/* SanitizerCoverage per-edge callback (plain -fsanitize-coverage=trace-pc-guard).
 *
 * The loader does NOT run its own .init_array during `--verify`, so the module
 * constructor that calls guard_init never fires and the guards stay zero. We
 * therefore number each guard lazily on first hit here, and bootstrap the AFL
 * shared map + forkserver on the very first edge. */
void __sanitizer_cov_trace_pc_guard(uint32_t *guard) {
#ifndef AFLRT_MANUAL_START
  /* glibc fully self-relocates before any instrumented code runs, so the
     first edge can safely bring up shared memory + the forkserver. */
  if (!afl_started) afl_start();
#endif
  uint32_t g = *guard;
  if (g == 0) {
    g = ++afl_next_guard;
    if (g >= MAP_SIZE) g = (g % (MAP_SIZE - 1)) + 1; /* keep nonzero, in range */
    *guard = g;
  }
  __afl_area_ptr[g & (MAP_SIZE - 1)]++;
}

/* Explicit start hook. Some loaders (musl) run instrumented code *during* their
 * own relocation, before the GOT entry for libc's __environ is usable, so the
 * lazy auto-start above would fault. Those builds define AFLRT_MANUAL_START and
 * call this from a safe point (e.g. start of musl's __dls3, once __environ is
 * set and relocations are complete). The per-edge callback keeps recording
 * coverage into the (PC-relative, already-relocated) map in the meantime. */
void __afl_manual_start(void) {
  if (!afl_started) afl_start();
}

/* Called from a module constructor that the loader does not execute in
 * `--verify` mode; kept for completeness / non-loader use. Lazy numbering in
 * the callback above is what actually runs. */
void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop) {
  mark("[guard_init]\n");
  if (start == stop || *start) return;
  for (uint32_t *x = start; x < stop; ++x) {
    uint32_t g = ++afl_next_guard;
    if (g >= MAP_SIZE) g = (g % (MAP_SIZE - 1)) + 1;
    *x = g;
  }
}

#ifdef AFLRT_MARKERS
__attribute__((constructor)) static void afl_ctor(void) { mark("[ctor]\n"); }
#endif
