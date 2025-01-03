// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024-2025 Akira Moroo

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <windows.h>
#include <winuser.h>

LIST_ENTRY *InitializeListHead(LIST_ENTRY *ListHead) {
  ListHead->Flink = ListHead;
  ListHead->Blink = ListHead;
  return ListHead;
}

LIST_ENTRY *InsertHeadList(LIST_ENTRY *ListHead, LIST_ENTRY *Entry) {
  Entry->Flink = ListHead->Flink;
  Entry->Blink = ListHead;
  Entry->Flink->Blink = Entry;
  ListHead->Flink = Entry;
  return ListHead;
}

#define PROT_READ 0x1
#define PROT_WRITE 0x2
#define PROT_EXEC 0x4

extern long enter_syscall(int64_t, int64_t, int64_t, int64_t, int64_t, int64_t,
                          int64_t, int64_t);
extern void asm_syscall_hook(void);

// #ifndef FULL_CONTEXT
#if 0
#define CONTEXT_SIZE 64
// clang-format off
#define __OP_CONTEXT(op, reg) \
  #op " x10, x11, [" #reg ",#0] \n\t" \
  #op " x12, x13, [" #reg ",#16] \n\t" \
  #op " x14, x15, [" #reg ",#32] \n\t" \
  #op " x30, xzr, [" #reg ",#48] \n\t"
// clang-format on
#else
#define CONTEXT_SIZE 256
/* FULL_CONTEXT saves all registers, but may decrease the performance. */
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
#endif /* FULL_CONTEXT */

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
      "ldr x15, =syscall_table \n\t"
      "ldr x15, [x15] \n\t"
      "add x15, x15, x13, lsl #3 \n\t"
      "br x15 \n\t");

  asm volatile(
      ".globl asm_syscall_hook \n\t"
      "asm_syscall_hook: \n\t"

      "do_syscall_hook: \n\t"

      /* assuming callee preserves x19-x28  */

      PUSH_CONTEXT(sp, CONTEXT_SIZE) SAVE_CONTEXT(sp)

      /* arguments for syscall_hook */
      // "mov x7, x14 \n\t" /* return address */
      // "mov x6, x8 \n\t"  /* syscall NR */

      "bl syscall_hook \n\t"

      RESTORE_CONTEXT(sp) POP_CONTEXT(sp, CONTEXT_SIZE)

          "do_return: \n\t"
          // "mov x8, x14 \n\t"

          /* XXX: We assume that the caller does not reuse the syscall number
             stored in x8. */
          "br x14 \n\t");
}

static long (*hook_fn)(int64_t a1, int64_t a2, int64_t a3, int64_t a4,
                       int64_t a5, int64_t a6, int64_t a7,
                       int64_t a8) = enter_syscall;

long syscall_hook(int64_t x0, int64_t x1, int64_t x2, int64_t x3, int64_t x4,
                  int64_t x5, int64_t x8, /* syscall NR */
                  int64_t retptr) {
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

static inline void get_b_range(uintptr_t addr, uintptr_t *min, uintptr_t *max) {
  const int64_t range_min_off = -0x8000000;
  const int64_t range_max_off = 0x7fffffc;
  *min = (uintptr_t)((int64_t)addr + range_min_off);
  *max = (uintptr_t)((int64_t)addr + range_max_off);
}

static inline uint32_t gen_b(uintptr_t addr, uintptr_t target) {
  uintptr_t range_min = 0;
  uintptr_t range_max = 0;
  get_b_range(addr, &range_min, &range_max);
  assert(range_min <= target && target <= range_max);

  const int64_t off = (int64_t)target - (int64_t)addr;
  const uint32_t imm26 = (uint32_t)(off >> 2) & ((1L << 26L) - 1);
  const uint32_t insn = (0x5 << 26) | (imm26 << 0);

  return insn;
}

static inline uint32_t gen_br(uint8_t rn) {
  const uint32_t insn = (0x3587c0 << 10) | (rn << 5) | (0x0 << 0);
  return insn;
}

static inline uint32_t gen_ret(void) { return 0xd65f03c0; }

static inline uint32_t gen_svc(uint16_t imm) {
  return 0xd4000001 | ((uint32_t)imm << 5);
}

static inline bool is_svc(uint32_t insn) {
  return (insn & 0xffe0000f) == 0xd4000001;
}

static inline uint16_t get_svc_imm(uint32_t insn) {
  return (uint16_t)((insn >> 5) & 0xffff);
}

static inline bool is_b(uint32_t insn) {
  return (insn & 0xfc000000) == 0x14000000;
}

static inline bool is_ret(uint32_t insn) {
  return (insn & 0xfffffc1f) == 0xd65f0000;
}

typedef struct records_entry {
  uintptr_t *records;
  uint16_t *imms;
  size_t records_size_max;
  size_t count;
  uintptr_t reachable_range_min;
  uintptr_t reachable_range_max;
  void *trampoline;
  LIST_ENTRY entries;
} RECORDS_ENTRY;

static LIST_ENTRY records_head = {NULL};

#ifndef PAGE_SIZE
#define PAGE_SIZE (0x1000)
#endif

#define INITIAL_RECORDS_SIZE (PAGE_SIZE / sizeof(uintptr_t))

static const size_t jump_code_size = 5;
static const size_t svc_entry_size = 2;
static const size_t svc_gate_size = 6;

static void init_records(RECORDS_ENTRY *entry) {
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

__attribute__((unused)) static void debug_printf(const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  char buf[256];
  vsprintf_s(buf, sizeof(buf), fmt, args);
  OutputDebugStringA(buf);
  va_end(args);
}

__attribute__((unused)) static void dump_records(RECORDS_ENTRY *entry) {
  assert(entry != NULL);
  debug_printf("reachable_range: [0x%016llx-0x%016llx]\n",
               entry->reachable_range_min, entry->reachable_range_max);
  debug_printf("count: %lld\n", entry->count);
  debug_printf("records_size_max: 0x%llx\n", entry->records_size_max);
  for (size_t i = 0; i < entry->count; i++) {
    uintptr_t record = entry->records[i];
    debug_printf("record[%lld]: 0x%016llx %c%c%c\n", i, (record & ~0x3),
                 (record & 0x2) ? 'r' : '-', (record & 0x1) ? 'w' : '-', 'x');
  }
}

static inline bool should_hook(uintptr_t addr) {
  return (addr < (uintptr_t)syscall_table ||
          addr >= (uintptr_t)syscall_table + (uintptr_t)syscall_table_size);
}

static uintptr_t valid_vm_addr[16] = {0};
static size_t valid_vm_size[16] = {0};

static size_t valid_region_count = 0;

/* find svc using pattern matching */
static void record_svc(char *code, size_t code_size, int mem_prot) {
  // TODO: Add PROT_READ to read the code
  // DWORD old_prot = 0;
  // assert(VirtualProtect((void *)code, code_size, PAGE_EXECUTE_READWRITE,
  // &old_prot));
  size_t svc_count = 0;
  bool has_r = mem_prot & PROT_READ;
  bool has_w = mem_prot & PROT_WRITE;
  for (size_t off = 0; off < code_size; off += 4) {
    uint32_t *ptr = (uint32_t *)(((uintptr_t)code) + off);
    if (!is_svc(*ptr) || !is_ret(*(ptr + 1))) {
      continue;
    }
    if (is_ret(*(ptr - 1)) || is_b(*(ptr - 1))) {
      continue;
    }

    uintptr_t addr = (uintptr_t)ptr;
    assert((addr & 0x3ULL) == 0);
    if (!should_hook(addr)) {
      continue;
    }

    svc_count += 1;

    uintptr_t range_min = 0;
    uintptr_t range_max = 0;
    get_b_range(addr, &range_min, &range_max);

    RECORDS_ENTRY *entry =
        CONTAINING_RECORD(records_head.Flink, RECORDS_ENTRY, entries);
    if (entry == NULL || entry->reachable_range_max < range_min) {
      /*
       * No entry found or the reachable range of the address is out of
       * reachable max range
       */
      entry = malloc(sizeof(RECORDS_ENTRY));
      init_records(entry);
      InsertHeadList(&records_head, &entry->entries);
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
  if (svc_count > 0) {
    debug_printf("svc_count: %d (#%d)\n", svc_count, valid_region_count);
    valid_vm_addr[valid_region_count] = (uintptr_t)code;
    valid_vm_size[valid_region_count] = code_size;
    valid_region_count += 1;
  }
}

/* Entry point for scanning memory */
void scan_code(void) {
  InitializeListHead(&records_head);

  MEMORY_BASIC_INFORMATION mbi;
  char *addr = 0;

  while (VirtualQuery(addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
    int mem_prot = 0;

    if (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                       PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) {
      mem_prot |= PROT_EXEC;
    }
    if (mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY |
                       PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) {
      mem_prot |= PROT_WRITE;
    }
    if (mbi.Protect & (PAGE_READONLY | PAGE_EXECUTE_READ | PAGE_READWRITE |
                       PAGE_EXECUTE_READWRITE)) {
      mem_prot |= PROT_READ;
    }

    if (mem_prot & PROT_EXEC) {
      debug_printf(
          "[0x%016llx-0x%016llx] %c%c%c S: 0x%lx T: 0x%lx P: 0x%lx\n",
          (uint64_t)mbi.BaseAddress,
          (uint64_t)mbi.BaseAddress + (uint64_t)mbi.RegionSize,
          mem_prot & PROT_READ ? 'r' : '-', mem_prot & PROT_WRITE ? 'w' : '-',
          mem_prot & PROT_EXEC ? 'x' : '-', mbi.State, mbi.Type, mbi.Protect);
      record_svc(mbi.BaseAddress, mbi.RegionSize, mem_prot);
    }

    addr += mbi.RegionSize;
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
  void *svc_table = VirtualAlloc(NULL, svc_table_size, MEM_COMMIT | MEM_RESERVE,
                                 PAGE_READWRITE);
  assert(svc_table != NULL);
  debug_printf("VirtualAlloc: [0x%016llx-0x%016llx]\n", (uintptr_t)svc_table,
               (uintptr_t)svc_table + svc_table_size);

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

  DWORD old_prot = 0;
  assert(
      VirtualProtect(svc_table, svc_table_size, PAGE_EXECUTE_READ, &old_prot));
}

static void setup_trampoline(void) {
  LIST_ENTRY *list_entry = NULL;

  for (list_entry = records_head.Flink; list_entry != &records_head;
       list_entry = list_entry->Flink) {
    RECORDS_ENTRY *entry =
        CONTAINING_RECORD(list_entry, RECORDS_ENTRY, entries);
    uintptr_t range_min = align_up(entry->reachable_range_min, PAGE_SIZE);
    uintptr_t range_max = align_down(entry->reachable_range_max, PAGE_SIZE);

    assert(range_min < UINT64_MAX);
    assert(range_max > 0);
    assert(range_max - range_min >= PAGE_SIZE);

    debug_printf("entry->count: %lld\n", entry->count);
    debug_printf("entry->records_size_max: 0x%lld\n", entry->records_size_max);
    assert(entry->count <= entry->records_size_max);
    dump_records(entry);

    const size_t mem_size = align_up(
        jump_code_size + svc_gate_size * sizeof(uint32_t) * entry->count,
        PAGE_SIZE);

    assert(range_min + mem_size <= range_max);

    assert(entry->trampoline == NULL);

    /* allocate memory at the aligned reachable address */
    void *trampoline = NULL;
    for (uintptr_t addr = range_min; addr < range_max; addr += PAGE_SIZE) {
      trampoline = VirtualAlloc((void *)addr, mem_size,
                                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
      if (trampoline != NULL) {
        debug_printf("VirtualAlloc: [0x%016llx-0x%016llx]\n", addr,
                     addr + mem_size);
        break;
      }
    }

    if (trampoline == NULL) {
      debug_printf("VirtualAlloc failed: %d\n", GetLastError());
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
      /* FIXME: We don't have to save full address */

      /*
       * put 'gate' code for each svc instruction
       *
       * movz x13, (#imm & 0xffff)
       * movz x14, (#return_pc & 0xffff)
       * movk x14, ((#return_pc >> 16) & 0xffff), lsl 16
       * movk x14, ((#return_pc >> 32) & 0xffff), lsl 32
       * movk x14, ((#return_pc >> 48) & 0xffff), lsl 48
       * b do_jump_asm_syscall_hook
       */

      const size_t gate_off = off;
      assert(gate_off == jump_code_size + svc_gate_size * i);

      const uint16_t imm = entry->imms[i];
      code[off++] = gen_movz(13, (imm >> 0) & 0xffff, 0);

      const uintptr_t return_pc = (entry->records[i] & ~0x3) + sizeof(uint32_t);
      code[off++] = gen_movz(14, (return_pc >> 0) & 0xffff, 0);
      code[off++] = gen_movk(14, (return_pc >> 16) & 0xffff, 16);
      code[off++] = gen_movk(14, (return_pc >> 32) & 0xffff, 32);
      code[off++] = gen_movk(14, (return_pc >> 48) & 0xffff, 48);

      const uintptr_t current_pc = (uintptr_t)&code[off];
      code[off++] = gen_b(current_pc, do_jump_addr);

      assert(off - gate_off == svc_gate_size);
    }

    DWORD old_prot = 0;
    assert(VirtualProtect(entry->trampoline, mem_size, PAGE_EXECUTE_READ,
                          &old_prot));
  }
}

/* entry point for binary rewriting */
static void rewrite_code(void) {
  for (size_t i = 0; i < valid_region_count; i++) {
    uintptr_t addr = valid_vm_addr[i];
    size_t size = valid_vm_size[i];
    debug_printf("VirtualProtect: [0x%016llx-0x%016llx]\n", addr,
                 addr + (uintptr_t)size);
    DWORD old_prot = 0;
    assert(
        VirtualProtect((void *)addr, size, PAGE_EXECUTE_READWRITE, &old_prot));
  }

  LIST_ENTRY *list_entry = NULL;

  for (list_entry = records_head.Flink; list_entry != &records_head;
       list_entry = list_entry->Flink) {
    RECORDS_ENTRY *entry =
        CONTAINING_RECORD(list_entry, RECORDS_ENTRY, entries);

    bool vprot_active = false;
    uintptr_t vprot_addr = UINTPTR_MAX;
    DWORD vprot_prot = 0;

    const uintptr_t trampoline = (uintptr_t)entry->trampoline;

    for (size_t i = 0; i < entry->count; i++) {
      uintptr_t record = entry->records[i];
      uintptr_t addr = record & ~0x3ULL;
      uint32_t *ptr = (uint32_t *)addr;

#if 0
      if (vprot_active) {
        if (!((vprot_addr <= addr) && (addr < vprot_addr + PAGE_SIZE))) {
          DWORD old_prot = 0;
          assert(VirtualProtect((void *)vprot_addr, PAGE_SIZE, vprot_prot, &old_prot));
          vprot_addr = UINTPTR_MAX;
          vprot_prot = 0;
          vprot_active = false;
        }
      }

      if (!vprot_active) {
        vprot_addr = align_down(addr, PAGE_SIZE);
        DWORD old_prot = 0;
        assert(VirtualProtect((void *)vprot_addr, PAGE_SIZE, PAGE_EXECUTE_READWRITE, &old_prot));
        vprot_prot = old_prot;
        vprot_active = true;
      }
#endif

      assert(is_svc(*ptr));
      const uintptr_t target =
          (uintptr_t)trampoline +
          (jump_code_size + svc_gate_size * i) * sizeof(uint32_t);
      *ptr = gen_b(addr, target);
    }

#if 0
    if (vprot_active) {
      DWORD old_prot = 0;
      assert(VirtualProtect((void *)vprot_addr, PAGE_SIZE, vprot_prot, &old_prot));
      vprot_addr = UINTPTR_MAX;
      vprot_prot = 0;
      vprot_active = false;
    }
#endif

    // TODO: Remove entry from records_head
  }
}

BOOL WINAPI DllMain(__attribute__((unused)) HINSTANCE hinstDLL, DWORD fdwReason,
                    __attribute__((unused)) LPVOID lpvReserved) {
  if (fdwReason != DLL_PROCESS_ATTACH) {
    return TRUE;
  }

  scan_code();
  debug_printf("scan_code done\n");
  setup_syscall_table();
  debug_printf("setup_syscall_table done\n");
  setup_trampoline();
  debug_printf("setup_trampoline done\n");
  rewrite_code();
  debug_printf("rewrite_code done\n");

  return TRUE;
}
