#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024 Akira Moroo

if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <syscall_record_file>"
    exit 1
fi

filename="$1"

# Read the file byte by byte and print non-zero values
od -An -t u1 -v "$filename" | awk '
{
    for (i = 1; i <= NF; i++) {
        if ($i != 0) {
            printf("syscall %d: %d\n", NR * 16 + i - 17, $i)
        }
    }
}
'
