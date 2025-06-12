// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024-2025 Akira Moroo

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <assert.h>
#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef __FreeBSD__
#define PROCFS_MAP "/proc/self/map"
#else
#define PROCFS_MAP "/proc/self/maps"
#endif

#ifndef SUPPLEMENTAL__SYSCALL_RECORD
#define SUPPLEMENTAL__SYSCALL_RECORD 0
#endif

#if SUPPLEMENTAL__SYSCALL_RECORD
/*
 * SUPPLEMENTAL: syscall record without syscalls
 */
#define BM_BACKING_FILE "/tmp/syscall_record"
#define BM_SIZE (1UL << 9)
static char *bm_mem = NULL;

static void bm_init(void) {
  const char *filename = getenv("BM_BACKING_FILE");
  if (filename == NULL) {
    filename = BM_BACKING_FILE;
  }
  // Use file-backed memory to save the results.
  int fd = open(filename, O_RDWR | O_CREAT, 0644);
  assert(fd != -1);
  assert(ftruncate(fd, BM_SIZE) == 0);
  bm_mem = mmap(NULL, BM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  assert(bm_mem != MAP_FAILED);
  memset(bm_mem, 0, BM_SIZE);
}

static void bm_increment(size_t syscall_nr) {
  assert(syscall_nr < BM_SIZE);
  assert(bm_mem != NULL);
  assert(bm_mem[syscall_nr] < 0xff);
  bm_mem[syscall_nr] += 1;
}
#endif /* SUPPLEMENTAL__SYSCALL_RECORD */

extern void do_rt_sigreturn(void);
extern long enter_syscall(int64_t, int64_t, int64_t, int64_t, int64_t, int64_t,
                          int64_t, int64_t);
extern void asm_syscall_hook(void);

#define CONTEXT_SIZE 256
// clang-format off
#define __OP_CONTEXT(op, reg) \
  #op " xzr, x1, [" #reg ",#0] \n\t" \
  #op " x2, x3, [" #reg ",#16] \n\t" \
  #op " x4, x5, [" #reg ",#32] \n\t" \
  #op " x6, x7, [" #reg ",#48] \n\t" \
  #op " x8, x9, [" #reg ",#64] \n\t" \
  #op " x10, x11, [" #reg ",#80] \n\t" \
  #op " x12, x13, [" #reg ",#96] \n\t" \
  #op " x14, x15, [" #reg ",#112] \n\t" \
  #op " x16, x17, [" #reg ",#128] \n\t" \
  #op " x18, x19, [" #reg ",#144] \n\t" \
  #op " x20, x21, [" #reg ",#160] \n\t" \
  #op " x22, x23, [" #reg ",#176] \n\t" \
  #op " x24, x25, [" #reg ",#192] \n\t" \
  #op " x26, x27, [" #reg ",#208] \n\t" \
  #op " x28, x29, [" #reg ",#224] \n\t" \
  #op " x30, xzr, [" #reg ",#240] \n\t"
// clang-format on

#define SAVE_CONTEXT(reg) __OP_CONTEXT(stp, reg)
#define RESTORE_CONTEXT(reg) __OP_CONTEXT(ldp, reg)

#define __STR(x) #x
#define STR(x) __STR(x)
#define PUSH_CONTEXT(reg, size) "sub " #reg ", " #reg ", " STR(size) " \n\t"
#define POP_CONTEXT(reg, size) "add " #reg ", " #reg ", " STR(size) " \n\t"

void *syscall_table = NULL;
size_t syscall_table_size = 0;

void ____asm_impl(void) {
  /*
   * enter_syscall triggers a kernel-space system call
   * @param	a1	arg0 (x0)
   * @param	a2	arg1 (x1)
   * @param	a3	arg2 (x2)
   * @param	a4	arg3 (x3)
   * @param	a5	arg4 (x4)
   * @param	a6	arg5 (x5)
   * @param	a7	syscall NR (x6)
   * @param	a8	return address (x7)
   * @return		return value (x0)
   */
  asm volatile(
      ".extern syscall_table \n\t"
      ".globl enter_syscall \n\t"
      "enter_syscall: \n\t"
      "mov x8, x6 \n\t"
      /*
       * NOTE: Below assembly is same as "ldr x6, =syscall_table", but lld fails
       * to resolve relocation R_AARCH64_ABS64. So, we use adrp/ldr instead.
       */
      "adrp x6, :got:syscall_table \n\t"
      "ldr x6, [x6, #:got_lo12:syscall_table] \n\t"
      "ldr x6, [x6] \n\t"
      "add x6, x6, xzr, lsl #3 \n\t"
      "br x6 \n\t");

  /*
   * asm_syscall_hook is the address where the
   * trampoline code first lands.
   *
   * the procedure below calls the C function
   * named syscall_hook.
   *
   * at the entry point of this,
   * the register values follow the calling convention
   * of the system calls.
   */
  asm volatile(
      ".globl asm_syscall_hook \n\t"
      "asm_syscall_hook: \n\t"

      "cmp x8, #139 \n\t" /* rt_sigreturn */
      "b.eq do_rt_sigreturn \n\t" /* bypass hook */
      "cmp x8, #220 \n\t" /* clone */
      "b.eq handle_clone \n\t"
      "cmp x8, #435 \n\t" /* clone3 */
      "b.eq handle_clone3 \n\t"
      "b do_syscall_hook \n\t" /* other syscalls */

      "handle_clone: \n\t"
      "and x15, x0, #256 \n\t" /* (flags & CLONE_VM) != 0 */
      "cmp x15, #256 \n\t"
      "b.eq clone_stack_copy\n\t"

      "b do_syscall_hook \n\t"

      "clone_stack_copy: \n\t"
      PUSH_CONTEXT(x1, CONTEXT_SIZE)
      SAVE_CONTEXT(x1)
      "b do_syscall_hook \n\t"

      "handle_clone3: \n\t"
      "ldr x15, [x0,#0] \n\t" /* cl_args->flags */
      "and x15, x15, #256 \n\t" /* (flags & CLONE_VM) != 0 */
      "cmp x15, #256 \n\t"
      "b.eq clone3_stack_copy \n\t"

      "b do_syscall_hook \n\t"

      "clone3_stack_copy: \n\t"
      /* cl_args->stack_size -= CONTEXT_SIZE */
      "ldr x15, [x0,#48] \n\t"
      PUSH_CONTEXT(x15, CONTEXT_SIZE)
      "str x15, [x0,#48] \n\t"

      /* x15 = cl_args->stack + cl_args->stack_size */
      "ldr x13, [x0,#40] \n\t"
      "add x15, x15, x13 \n\t"

      /* Copy x0-x30 to cl_args->stack + cl_args->stack_size */
      SAVE_CONTEXT(x15)
      "b do_syscall_hook \n\t"

      "do_syscall_hook: \n\t"

      /* assuming callee preserves x19-x28  */

      PUSH_CONTEXT(sp, CONTEXT_SIZE)
      SAVE_CONTEXT(sp)

      /* arguments for syscall_hook */
      "mov x7, x14 \n\t" /* return address */
      "mov x6, x8 \n\t"  /* syscall NR */

      "bl syscall_hook \n\t"

      RESTORE_CONTEXT(sp)
      POP_CONTEXT(sp, CONTEXT_SIZE)

      "do_return: \n\t"
      /* Use x14 scratch register to return original pc */
      "br x14 \n\t"

      ".globl do_rt_sigreturn \n\t"
      "do_rt_sigreturn: \n\t"
      "svc #0 \n\t"
      "b do_return \n\t");
}

static long (*hook_fn)(int64_t a1, int64_t a2, int64_t a3, int64_t a4,
                       int64_t a5, int64_t a6, int64_t a7,
                       int64_t a8) = enter_syscall;

long syscall_hook(int64_t x0, int64_t x1, int64_t x2, int64_t x3, int64_t x4,
                  int64_t x5, int64_t x8, /* syscall NR */
                  int64_t retptr) {
#if SUPPLEMENTAL__SYSCALL_RECORD
  bm_increment(x8);
#endif /* SUPPLEMENTAL__SYSCALL_RECORD */
  return hook_fn(x0, x1, x2, x3, x4, x5, x8, retptr);
}

static inline size_t align_up(size_t value, size_t align) {
  return (value + align - 1) & ~(align - 1);
}

static inline size_t align_down(size_t value, size_t align) {
  return value & ~(align - 1);
}

static inline uint32_t gen_movz(uint8_t rd, uint16_t imm16, uint16_t shift) {
  assert(shift % 16 == 0);
  const uint32_t sf = 1;
  const uint32_t hw = (uint32_t)(shift >> 4);
  assert(hw < 4);
  const uint32_t insn = (sf << 31) | (0xa5 << 23) | (hw << 21) |
                        ((uint32_t)imm16 << 5) | ((uint32_t)rd << 0);
  return insn;
}

static inline uint32_t gen_movk(uint8_t rd, uint16_t imm16, uint16_t shift) {
  assert(shift % 16 == 0);
  const uint32_t sf = 1;
  const uint32_t hw = (uint32_t)(shift >> 4);
  assert(hw < 4);
  const uint32_t insn = (sf << 31) | (0xe5 << 23) | (hw << 21) |
                        ((uint32_t)imm16 << 5) | ((uint32_t)rd << 0);
  return insn;
}

/* Generate 64-bit stp with pre-index */
__attribute__((unused)) static inline uint32_t gen_stp(uint8_t rt1, uint8_t rt2,
                                                       uint8_t rn,
                                                       int16_t offset) {
  assert(offset % 8 == 0);
  assert(offset >= -256 && offset <= 255);

  const uint32_t imm7 = (uint32_t)((offset / 8) & 0x7f);
  const uint32_t insn = (0x2 << 30) | (0xa6 << 22) | (imm7 << 15) |
                        ((uint32_t)rt2 << 10) | ((uint32_t)rn << 5) |
                        ((uint32_t)rt1 << 0);
  return insn;
}

/* Generate 64-bit ldp with post-index */
__attribute__((unused)) static inline uint32_t gen_ldp(uint8_t rt1, uint8_t rt2,
                                                       uint8_t rn,
                                                       int16_t offset) {
  assert(offset % 8 == 0);
  assert(offset >= -256 && offset <= 255);

  const uint32_t imm7 = (uint32_t)((offset / 8) & 0x7f);
  const uint32_t insn = (0x2 << 30) | (0xa7 << 22) | (imm7 << 15) |
                        ((uint32_t)rt2 << 10) | ((uint32_t)rn << 5) |
                        ((uint32_t)rt1 << 0);
  return insn;
}

static inline void get_b_range(uintptr_t addr, uintptr_t *min, uintptr_t *max) {
  const uintptr_t NEG_OFF = 0x08000000u;
  const uintptr_t POS_OFF = 0x07fffffcu;

  uintptr_t min_addr = 0;
  if (addr > NEG_OFF) {
    min_addr = addr - NEG_OFF;
  }

  uintptr_t max_addr = UINTPTR_MAX;
  if (addr <= UINTPTR_MAX - POS_OFF) {
    max_addr = addr + POS_OFF;
  }

  min_addr &= ~(uintptr_t)3u;
  max_addr &= ~(uintptr_t)3u;

  assert(min_addr < max_addr);

  *min = min_addr;
  *max = max_addr;
}

static inline uint32_t gen_b(uintptr_t addr, uintptr_t target) {
  uintptr_t range_min = 0;
  uintptr_t range_max = 0;
  get_b_range(addr, &range_min, &range_max);
  assert(range_min <= target && target <= range_max);

  int64_t off = 0;
  if (target >= addr) {
    off = (int64_t)(target - addr);
  } else {
    off = -(int64_t)(addr - target);
  }

  assert((off & 3) == 0);
  assert(off >= -0x08000000LL && off <= 0x07fffffcLL);

  const uint32_t imm26 = (uint32_t)(off >> 2) & ((1L << 26L) - 1);
  const uint32_t insn = (0x5 << 26) | (imm26 << 0);

  return insn;
}

static inline uint32_t gen_br(uint8_t rn) {
  const uint32_t insn = (0x3587c0 << 10) | (rn << 5) | (0x0 << 0);
  return insn;
}

__attribute__((unused)) static inline uint32_t gen_ret(void) {
  return 0xd65f03c0;
}

__attribute__((unused)) static inline uint32_t gen_brk(uint16_t imm) {
  return 0xd4200000 | ((uint32_t)imm << 5);
}

__attribute__((unused)) static inline uint32_t gen_nop(void) {
  return 0xd503201f;
}

__attribute__((unused)) static inline uint32_t gen_svc(uint16_t imm) {
  return 0xd4000001 | ((uint32_t)imm << 5);
}

static inline bool is_svc(uint32_t insn) {
  return (insn & 0xffe0000f) == 0xd4000001;
}

static inline uint16_t get_svc_imm(uint32_t insn) {
  return (uint16_t)((insn >> 5) & 0xffff);
}

struct records_entry {
  uintptr_t *records;
  uint16_t *imms;
  size_t records_size_max;
  size_t count;
  uintptr_t reachable_range_min;
  uintptr_t reachable_range_max;
  void *trampoline;
  LIST_ENTRY(records_entry) entries;
};

LIST_HEAD(records_head, records_entry) head;

#ifndef PAGE_SIZE
#define PAGE_SIZE (0x1000)
#endif

#define INITIAL_RECORDS_SIZE (PAGE_SIZE / sizeof(uintptr_t))

static const size_t jump_code_size = 5;
static const size_t svc_entry_size = 2;

static const size_t gate_epilogue_size = 1;
static const size_t gate_common_code_size = 6;

static const size_t gate_size = gate_common_code_size + gate_epilogue_size;

static void init_records(struct records_entry *entry) {
  assert(entry != NULL);
  entry->trampoline = NULL;
  entry->reachable_range_min = 0;
  entry->reachable_range_max = UINT64_MAX;
  entry->count = 0;
  entry->records_size_max = INITIAL_RECORDS_SIZE;
  entry->records = malloc(entry->records_size_max * sizeof(uintptr_t));
  assert(entry->records != NULL);
  entry->imms = malloc(entry->records_size_max * sizeof(uint16_t));
  assert(entry->imms != NULL);
}

__attribute__((unused)) static void dump_records(struct records_entry *entry) {
  assert(entry != NULL);
  fprintf(stderr, "reachable_range: [0x%016lx-0x%016lx]\n",
          entry->reachable_range_min, entry->reachable_range_max);
  fprintf(stderr, "count: %ld\n", entry->count);
  fprintf(stderr, "records_size_max: 0x%lx\n", entry->records_size_max);
  for (size_t i = 0; i < entry->count; i++) {
    uintptr_t record = entry->records[i];
    fprintf(stderr, "record[%ld]: 0x%016lx %c%c%c\n", i, (record & ~0x3),
            (record & 0x2) ? 'r' : '-', (record & 0x1) ? 'w' : '-', 'x');
  }
}

static inline bool is_elf(const char *code) {
  return (code[0] == 0x7f) && (code[1] == 'E') && (code[2] == 'L') &&
         (code[3] == 'F');
}

static inline bool should_hook(uintptr_t addr) {
  return (addr != (uintptr_t)do_rt_sigreturn) &&
         (addr < (uintptr_t)syscall_table ||
          addr >= (uintptr_t)syscall_table + (uintptr_t)syscall_table_size);
}

/* find svc using pattern matching */
static void record_svc(char *section, size_t section_size, int mem_prot) {
  /* fixup as the section is not aligned */
  char *code = (char *)align_down((uintptr_t)section, PAGE_SIZE);
  size_t code_size = align_up(section_size, PAGE_SIZE);
  assert(code_size % PAGE_SIZE == 0);

  /* add PROT_READ to read the code */
  assert(!mprotect(code, code_size, PROT_READ | PROT_EXEC));
  bool has_r = mem_prot & PROT_READ;
  bool has_w = mem_prot & PROT_WRITE;
  for (size_t off = 0; off < section_size; off += 4) {
    uint32_t *ptr = (uint32_t *)((uintptr_t)section + (uintptr_t)off);
    if (!is_svc(*ptr)) {
      continue;
    }
    uintptr_t addr = (uintptr_t)ptr;
    assert((addr & 0x3ULL) == 0);
    if (!should_hook(addr)) {
      continue;
    }

    uintptr_t range_min = 0;
    uintptr_t range_max = 0;
    get_b_range(addr, &range_min, &range_max);

    struct records_entry *entry = LIST_FIRST(&head);
    if (entry == NULL || entry->reachable_range_max < range_min) {
      /*
       * No entry found or the reachable range of the address is out of
       * reachable max range
       */
      entry = malloc(sizeof(struct records_entry));
      init_records(entry);
      LIST_INSERT_HEAD(&head, entry, entries);
      entry->reachable_range_max = range_max;
    }
    assert(entry != NULL);

    /* Embed mem prot info in the last two bits */
    uintptr_t record = addr | (has_r ? (1 << 1) : 0) | (has_w ? (1 << 0) : 0);
    entry->records[entry->count] = record;
    entry->imms[entry->count] = get_svc_imm(*ptr);
    entry->count += 1;
    if (entry->count >= entry->records_size_max) {
      entry->records_size_max *= 2;
      entry->records =
          realloc(entry->records, entry->records_size_max * sizeof(uintptr_t));
      assert(entry->records != NULL);
      entry->imms =
          realloc(entry->imms, entry->records_size_max * sizeof(uint16_t));
      assert(entry->imms != NULL);
    }

    entry->reachable_range_min = range_min;
  }
  /* restore the memory protection */
  assert(!mprotect(code, code_size, mem_prot));
}

/* parse ELF and record svc for each executable section */
static void scan_exec_code(char *code, size_t code_size, int mem_prot,
                           char *path) {
  if (path == NULL || !is_elf(code)) {
    /* the code region is not ELF or the ELF binary path is not available */
    record_svc(code, code_size, mem_prot);
    return;
  }

  /* TODO: Check if there is only one executable segment */

  int fd = open(path, O_RDONLY);
  assert(fd != -1);
  struct stat st;
  assert(fstat(fd, &st) != -1);
  assert(st.st_size > 0);
  char *elf_bin = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  assert(elf_bin != MAP_FAILED);
  assert(memcmp(elf_bin, code, sizeof(Elf64_Ehdr)) == 0);

  Elf64_Ehdr *ehdr = (Elf64_Ehdr *)elf_bin;
  for (size_t i = 0; i < ehdr->e_shnum; i++) {
    Elf64_Shdr *shdr =
        (Elf64_Shdr *)(elf_bin + ehdr->e_shoff + i * sizeof(Elf64_Shdr));
    if (shdr->sh_type == SHT_PROGBITS && shdr->sh_flags & SHF_EXECINSTR) {
      assert(shdr->sh_offset + shdr->sh_size <= code_size);
      char *section = code + shdr->sh_offset;
      size_t section_size = shdr->sh_size;
      record_svc(section, section_size, mem_prot);
    }
  }
  munmap(elf_bin, st.st_size);
  close(fd);
}

#ifdef __FreeBSD__
/* entry point for binary scanning on FreeBSD */
static void scan_code(void) {
  LIST_INIT(&head);

  FILE *fp = NULL;
  /* get memory mapping information from procfs */
  assert((fp = fopen(PROCFS_MAP, "r")) != NULL);
  char buf[4096];
  while (fgets(buf, sizeof(buf), fp) != NULL) {
    /* we do not touch stack memory */
    if (strstr(buf, "[stack]") != NULL) {
      continue;
    }
    int mem_prot = 0;
    int i = 0;
    char from_addr[65] = {0};
    char to_addr[65] = {0};
    char *c = strtok(buf, " ");
    while (c != NULL) {
      switch (i) {
        case 0:
          strncpy(from_addr, c, sizeof(from_addr) - 1);
          break;
        case 1:
          strncpy(to_addr, c, sizeof(to_addr) - 1);
          break;
        case 5:
          for (size_t j = 0; j < strlen(c); j++) {
            if (c[j] == 'r') mem_prot |= PROT_READ;
            if (c[j] == 'w') mem_prot |= PROT_WRITE;
            if (c[j] == 'x') mem_prot |= PROT_EXEC;
          }
          break;
        case 9:
          if (strncmp(c, "COW", 3) == 0) {
            int64_t from = strtol(&from_addr[0], NULL, 16);
            int64_t to = strtol(&to_addr[0], NULL, 16);
            if (mem_prot & PROT_EXEC) {
              scan_exec_code((char *)from, (size_t)to - from, mem_prot, NULL);
            }
          }
          break;
      }
      if (i == 9) break;
      c = strtok(NULL, " ");
      i++;
    }
  }
  fclose(fp);
}
#else
/* entry point for binary scanning on Linux */
static void scan_code(void) {
  LIST_INIT(&head);

  FILE *fp = NULL;
  /* get memory mapping information from procfs */
  assert((fp = fopen(PROCFS_MAP, "r")) != NULL);
  char buf[4096];
  while (fgets(buf, sizeof(buf), fp) != NULL) {
    /* we do not touch stack memory */
    if (strstr(buf, "[stack]") != NULL) {
      continue;
    }
    int mem_prot = 0;
    int i = 0;
    char addr[65] = {0};
    int64_t addr_start = 0;
    int64_t addr_end = 0;
    char *c = strtok(buf, " ");
    while (c != NULL) {
      switch (i) {
        case 0:
          strncpy(addr, c, sizeof(addr) - 1);
          break;
        case 1:
          for (size_t j = 0; j < strlen(c); j++) {
            if (c[j] == 'r') mem_prot |= PROT_READ;
            if (c[j] == 'w') mem_prot |= PROT_WRITE;
            if (c[j] == 'x') mem_prot |= PROT_EXEC;
          }
          size_t k = 0;
          for (k = 0; k < strlen(addr); k++) {
            if (addr[k] == '-') {
              addr[k] = '\0';
              break;
            }
          }
          addr_start = strtol(&addr[0], NULL, 16);
          addr_end = strtol(&addr[k + 1], NULL, 16);
          break;
        case 5: {
          char *path = NULL;
          size_t path_len = 0;
          if (c[0] == '/') {
            path = strndup(c, sizeof(buf) - 1);
            path_len = strnlen(path, sizeof(buf) - 1);
            path[path_len - 1] = '\0';
          }
          if (mem_prot & PROT_EXEC) {
            scan_exec_code((char *)addr_start, (size_t)addr_end - addr_start,
                           mem_prot, path);
          }
          break;
        }
      }
      if (i == 5) break;
      c = strtok(NULL, " ");
      i++;
    }
  }
  fclose(fp);
}
#endif

/* entry point for binary rewriting */
static void rewrite_code(void) {
  struct records_entry *entry;

  while (!LIST_EMPTY(&head)) {
    entry = LIST_FIRST(&head);

    bool mprotect_active = false;
    uintptr_t mprotect_addr = UINTPTR_MAX;
    int mprotect_prot = 0;

    const uintptr_t trampoline = (uintptr_t)entry->trampoline;

    for (size_t i = 0; i < entry->count; i++) {
      uintptr_t record = entry->records[i];
      uintptr_t addr = record & ~0x3ULL;
      uint32_t *ptr = (uint32_t *)addr;

      int mem_prot = PROT_EXEC;
      mem_prot |= (record & 0x2) ? PROT_READ : 0;
      mem_prot |= (record & 0x1) ? PROT_WRITE : 0;

      if (mprotect_active) {
        if (!((mprotect_addr <= addr) && (addr < mprotect_addr + PAGE_SIZE))) {
          /* mprotect is active, but the address is out-of-bounds */
          assert(!mprotect((void *)mprotect_addr, PAGE_SIZE, mprotect_prot));
          mprotect_addr = UINTPTR_MAX;
          mprotect_prot = 0;
          mprotect_active = false;
        }
      }

      if (!mprotect_active) {
        mprotect_addr = align_down(addr, PAGE_SIZE);
        mprotect_prot = mem_prot;
        mprotect_active = true;
        assert(!mprotect((void *)mprotect_addr, PAGE_SIZE,
                         PROT_WRITE | PROT_READ | PROT_EXEC));
      }

      assert(is_svc(*ptr));
      const uintptr_t target =
          trampoline + (jump_code_size + gate_size * i) * sizeof(uint32_t);
      *ptr = gen_b(addr, target);
    }

    if (mprotect_active) {
      assert(!mprotect((void *)mprotect_addr, PAGE_SIZE, mprotect_prot));
      mprotect_addr = UINTPTR_MAX;
      mprotect_prot = 0;
      mprotect_active = false;
    }

    LIST_REMOVE(head.lh_first, entries);
    free(entry->records);
    entry->records = NULL;
    free(entry->imms);
    entry->imms = NULL;
    free(entry);
    entry = NULL;
  }
}

/* Create a system call table for every svc #imm */
/* NOTE: Although Linux does not use the #imm in svc instructions, some OSes
 * such as NetBSD and Windows use it to store the system call number. To support
 * such systems, we create a system call table for every svc #imm.
 */
static void setup_syscall_table(void) {
  const size_t nr_svc = UINT16_MAX + 1; /* 0x10000, as #imm is 16-bit */
  const size_t svc_table_size =
      align_up(sizeof(uint32_t) * svc_entry_size * nr_svc, PAGE_SIZE);
  void *svc_table = mmap(NULL, svc_table_size, PROT_READ | PROT_WRITE,
                         MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  assert(svc_table != MAP_FAILED);

  uint32_t *code = (uint32_t *)svc_table;
  size_t off = 0;
  for (size_t i = 0; i < nr_svc; i++) {
    assert(off == i * svc_entry_size);
    code[off++] = gen_svc(i); /* svc #i */
    code[off++] = gen_ret();  /* ret */
    assert(off - i * svc_entry_size == svc_entry_size);
  }

  syscall_table = svc_table;
  syscall_table_size = svc_table_size;

  assert(!mprotect(svc_table, svc_table_size, PROT_EXEC));
}

static void setup_trampoline(void) {
  struct records_entry *entry = NULL;

  LIST_FOREACH(entry, &head, entries) {
    uintptr_t range_min = align_up(entry->reachable_range_min, PAGE_SIZE);
    uintptr_t range_max = align_down(entry->reachable_range_max, PAGE_SIZE);

    assert(range_min < UINT64_MAX);
    assert(range_max > 0);
    assert(range_max - range_min >= PAGE_SIZE);

    assert(entry->count <= entry->records_size_max);

    const size_t mem_size =
        align_up((jump_code_size + gate_size * entry->count) * sizeof(uint32_t),
                 PAGE_SIZE);

    assert(range_min + mem_size <= range_max);

    assert(entry->trampoline == NULL);

    /* allocate memory at the aligned reachable address */
    void *trampoline = MAP_FAILED;
    for (uintptr_t addr = range_min; addr < range_max; addr += PAGE_SIZE) {
      trampoline = mmap((void *)addr, mem_size, PROT_READ | PROT_WRITE,
                        MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
      if (trampoline != MAP_FAILED) {
        break;
      }
    }

    if (trampoline == MAP_FAILED) {
      fprintf(stderr, "map failed\n");
      exit(1);
    }
    entry->trampoline = trampoline;

    /*
     * The trampoline code uses the following temporary registers:
     * x14: to save the return address
     * x15: to indirect branch to asm_syscall_hook
     */

    /*
     * put common code to indirect branch to asm_syscall_hook
     *
     * do_jump_asm_syscall_hook:
     * movz x15, (#asm_syscall_hook & 0xffff)
     * movk x15, ((#asm_syscall_hook >> 16) & 0xffff), lsl 16
     * movk x15, ((#asm_syscall_hook >> 32) & 0xffff), lsl 32
     * movk x15, ((#asm_syscall_hook >> 48) & 0xffff), lsl 48
     * br x15
     */
    const uintptr_t hook_addr = (uintptr_t)asm_syscall_hook;
    const uintptr_t do_jump_addr = (uintptr_t)entry->trampoline;

    size_t off = 0;
    uint32_t *code = (uint32_t *)entry->trampoline;
    code[off++] = gen_movz(15, (hook_addr >> 0) & 0xffff, 0);
    code[off++] = gen_movk(15, (hook_addr >> 16) & 0xffff, 16);
    code[off++] = gen_movk(15, (hook_addr >> 32) & 0xffff, 32);
    code[off++] = gen_movk(15, (hook_addr >> 48) & 0xffff, 48);
    code[off++] = gen_br(15);
    assert(off == jump_code_size);

    for (size_t i = 0; i < entry->count; i++) {
      /*
       * put 'gate' code for each svc instruction
       */

      const size_t gate_off = off;
      assert(gate_off == jump_code_size + gate_size * i);

      {
        const size_t common_gate_off = off;

        const uintptr_t return_pc =
            (uintptr_t)(&code[off + gate_common_code_size]);

        const uint16_t imm = entry->imms[i];

        /*
         * movz x6, (#imm & 0xffff)
         * movz x14, (#return_pc & 0xffff)
         * movk x14, ((#return_pc >> 16) & 0xffff), lsl 16
         * movk x14, ((#return_pc >> 32) & 0xffff), lsl 32
         * movk x14, ((#return_pc >> 48) & 0xffff), lsl 48
         * b do_jump_asm_syscall_hook
         */
        code[off++] = gen_movz(6, (imm >> 0) & 0xffff, 0);
        code[off++] = gen_movz(14, (return_pc >> 0) & 0xffff, 0);
        code[off++] = gen_movk(14, (return_pc >> 16) & 0xffff, 16);
        code[off++] = gen_movk(14, (return_pc >> 32) & 0xffff, 32);
        code[off++] = gen_movk(14, (return_pc >> 48) & 0xffff, 48);

        const uintptr_t current_pc = (uintptr_t)&code[off];
        code[off++] = gen_b(current_pc, do_jump_addr);

        assert(off - common_gate_off == gate_common_code_size);
      }

      {
        const size_t epilogue_gate_off = off;

        const uintptr_t current_pc = (uintptr_t)&code[off];
        const uintptr_t return_pc =
            (entry->records[i] & ~0x3) + sizeof(uint32_t);
        code[off++] = gen_b(current_pc, return_pc);

        assert(off - epilogue_gate_off == gate_epilogue_size);
      }

      assert(off - gate_off == gate_size);
    }

    /*
     * mprotect(PROT_EXEC without PROT_READ), executed
     * on CPUs supporting Memory Protection Keys for Userspace (PKU),
     * configures this memory region as eXecute-Only-Memory (XOM).
     * this enables to cause a segmentation fault for a NULL pointer access.
     */
    assert(!mprotect(entry->trampoline, mem_size, PROT_EXEC));
  }
}

static void load_hook_lib(void) {
  void *handle;
  {
    const char *filename;
    filename = getenv("LIBSVCHOOK");
    if (!filename) {
      fprintf(stderr,
              "env LIBSVCHOOK is empty, so skip to load a hook library\n");
      return;
    }

#ifdef __GLIBC__
    handle = dlmopen(LM_ID_NEWLM, filename, RTLD_NOW | RTLD_LOCAL);
#else
    handle = dlopen(filename, RTLD_NOW | RTLD_LOCAL);
#endif
    if (!handle) {
      fprintf(stderr, "dlopen/dlmopen failed: %s\n\n", dlerror());
      fprintf(
          stderr,
          "NOTE: this may occur when the compilation of your hook function "
          "library misses some specifications in LDFLAGS. or if you are using "
          "a C++ compiler, dlmopen may fail to find a symbol, and adding "
          "'extern \"C\"' to the definition may resolve the issue.\n");
      exit(1);
    }
  }
  {
    int (*hook_init)(long, ...);
    hook_init = dlsym(handle, "__hook_init");
    assert(hook_init);
    assert(hook_init(0, &hook_fn) == 0);
  }
}

__attribute__((constructor(0xffff))) static void __svc_hook_init(void) {
#if SUPPLEMENTAL__SYSCALL_RECORD
  bm_init();
#endif /* SUPPLEMENTAL__SYSCALL_RECORD */
  scan_code();
  setup_syscall_table();
  setup_trampoline();
  rewrite_code();
  load_hook_lib();
}
