/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SCAN_CODE_FREEBSD_H
#define SCAN_CODE_FREEBSD_H

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/queue.h>

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

#endif /* SCAN_CODE_FREEBSD_H */
