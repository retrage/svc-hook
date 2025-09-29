# svc-hook: System Call Hook for ARM64

svc-hook is a system call hook mechanism for ARM64. It is designed to be low performance overhead, independent of the target source code, without relying on kernel features. It utilizes binary rewriting, replacing every `svc` instruction with a `b` instruction in the loaded target binary code before the main function starts.

## Key Features

- 1,000 times faster than `ptrace`
- No need for target source code
- Works without relying on kernel features

## Target Platform

svc-hook supports ARM64 Linux, Android, FreeBSD, and NetBSD.

Note that NetBSD support is not upstreamed yet. See: [PR#29](https://github.com/retrage/svc-hook/pull/29).

## Build

svc-hook has no external dependencies.
To build `libsvchook.so`, run the following command in the root directory on an
ARM64 system:

```shell
make
```

If you are building on x86_64 or another host architecture, provide an ARM64
cross compiler via the `CC` variable:

```shell
make CC=aarch64-linux-gnu-gcc

# or with clang
make CC=aarch64-linux-gnu-clang
```

To build a simple hook application `libsvchook_basic.so`, use:

```shell
make -C apps/basic
```

## Usage

You need to set two environment variables:

- `LIBSVCHOOK`: Path to the hook application e.g., `apps/basic/libsvchook_basic.so`
- `LD_PRELOAD`: Path to `libsvchook.so`

### Example

```shell
LIBSVCHOOK=./apps/basic/libsvchook_basic.so LD_PRELOAD=./libsvchook.so [target]
```

Replace `[target]` with the binary whose system calls you wish to hook.

#### Example Output

```shell
LIBSVCHOOK=./apps/basic/libsvchook_basic.so LD_PRELOAD=./libsvchook.so /bin/ls
output from __hook_init: we can do some init work here
output from hook_function: syscall number 56
output from hook_function: syscall number 56
output from hook_function: syscall number 79
output from hook_function: syscall number 63
output from hook_function: syscall number 63
output from hook_function: syscall number 57
output from hook_function: syscall number 56
output from hook_function: syscall number 56
output from hook_function: syscall number 56
output from hook_function: syscall number 56
output from hook_function: syscall number 56
output from hook_function: syscall number 56
output from hook_function: syscall number 29
output from hook_function: syscall number 29
output from hook_function: syscall number 56
output from hook_function: syscall number 79
output from hook_function: syscall number 61
output from hook_function: syscall number 61
output from hook_function: syscall number 57
output from hook_function: syscall number 79
output from hook_function: syscall number 64
Documentation  LICENSE	Makefile  README.md  apps  libsvchook.so  main.c  main.o
output from hook_function: syscall number 57
```

## How It Works

svc-hook has four stages during initialization:

1. It records the addresses of `svc` instructions in the target code and computes the range a `b` instruction can branch to (from `pc - 0x8000000` to `pc + 0x7fffffc`).
2. It instantiates a custom trampoline code for each `svc` instruction. The recorded addresses are embedded in the custom trampoline code.
3. It rewrites every `svc` instruction to a `b` instruction that branches to the trampoline.
4. It loads the hook application specified by the `LIBSVCHOOK` environment variable.

When the target process executes a system call, it branches to the trampoline, which saves the CPU context and calls the hook function defined in the hook application. After executing the hook function, it restores the CPU context and returns to the instruction following the original `svc` instruction.

## Further Reading

- [My blog post (ja)](https://retrage.github.io/2024/07/31/svc-hook.html/): An initial introduction to svc-hook.
- [Supplemental Documentation](/Documentation/README.md): Supplemental documentation for svc-hook experimental results.

## License

svc-hook is released under the Apache license version 2.0.
