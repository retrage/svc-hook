# svc-hook: System Call Hook for ARM64

svc-hook is a system call hook mechanism for ARM64, achieving speeds about **2,000 times** faster than ptrace. It utilizes binary rewriting, replacing every `svc` instruction with a `b` instruction in the loaded target binary code before the main function starts.

Inspired by [zpoline](https://github.com/yasukata/zpoline) for x86_64 Linux, svc-hook adapts its concepts for ARM64, offering significant speed advantage without the need for target source code or kernel feature dependencies.

## Key Features

- Performance: 2,000 times faster than ptrace
- Independence: No need for target source code
- Simplicity: Works without relying on kernel features

Read [my blog post (ja)](https://retrage.github.io/2024/07/31/svc-hook.html/) for more details.

## Target Platform

svc-hook supports ARM64 Linux and FreeBSD.

## Build

svc-hook has no external dependencies.
To build `libsvchook.so`, run the following command in the root directory:

```shell
make
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

svc-hook has three stages during initialization:

1. It records the addresses of `svc` instructions in the target code and computes the range a `b` instruction can branch to (from `pc - 0x8000000` to `pc + 0x7fffffc`).
2. A custom trampoline is set within the calculated range.
3. The target code is rewritten accordingly.

### Overview Diagram

![svc-hook Overview](Documentation/img/svc-hook.svg)

## License

svc-hook is released under the Apache license version 2.0.
