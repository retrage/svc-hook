# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2025 Akira Moroo
# For Arm Windows using LLVM/Clang

NAME = svchook
LIB = $(NAME).lib
DLL = $(NAME).dll
PDB = $(NAME).pdb

LLVM_PATH = C:\\Program Files\\LLVM\\bin
CC = "$(LLVM_PATH)\\clang-cl.exe"
LD = "$(LLVM_PATH)\\lld-link.exe"

CFLAGS = \
	/c \
	-fms-compatibility \
	--target=aarch64-pc-windows-msvc

WIN_VER = 10
WIN_KIT_VER = 10.0.22621.0
WIN_KIT_PATH = "C:\Program Files (x86)\Windows Kits\$(WIN_VER)\Lib\$(WIN_KIT_VER)"

MSVC_EDITION = 2022
MSVC_VER = 14.42.34433
MSVC_LIB_PATH = "C:\Program Files\Microsoft Visual Studio\$(MSVC_EDITION)\Community\VC\Tools\MSVC\$(MSVC_VER)"

LDFLAGS = \
	/libpath:$(WIN_KIT_PATH)\um\arm64 \
	/libpath:$(WIN_KIT_PATH)\ucrt\arm64 \
	/libpath:$(MSVC_LIB_PATH)\lib\arm64 \
	/defaultlib:libcmt \
	/defaultlib:vcruntime \
	/implib:$(LIB) \
	/out:$(DLL) \
	/pdb:$(PDB) \
	/dll

C_SCRS = main.c
C_OBJS = main.obj

all: $(DLL)

$(DLL): $(C_OBJS)
	$(LD) $(LDFLAGS) $?

$(C_OBJS): $(C_SCRS)
	$(CC) $(CFLAGS) /Fo $@ $?

clean:
	del $(C_OBJS) $(LIB) $(DLL) $(PDB)