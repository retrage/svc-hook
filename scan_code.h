/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SCAN_CODE_H
#define SCAN_CODE_H

#ifdef __FreeBSD__
#include "scan_code_freebsd.h"
#else
#include "scan_code_linux.h"
#endif

#endif /* SCAN_CODE_H */
