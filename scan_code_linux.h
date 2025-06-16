/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SCAN_CODE_LINUX_H
#define SCAN_CODE_LINUX_H

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

#endif /* SCAN_CODE_LINUX_H */
