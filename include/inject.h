/*
 * inject.h
 */

#ifndef INJECT_H
#define INJECT_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>

#define TRAP_INST   0xCC
#define TRAP_MASK   0xFFFFFFFFFFFFFF00

#define Elf_Ehdr Elf64_Ehdr
#define Elf_Shdr Elf64_Shdr
#define Elf_Sym Elf64_Sym
#define Elf_Rel Elf64_Rela
#define ELF_R_SYM ELF64_R_SYM
#define REL_DYN ".rela.dyn"
#define REL_PLT ".rela.plt"

/* Maximum size for a path / argument. */
#define INJECT_PATH_SIZE 256

/* The backup size (in words) -- 256bytes. */
#define INJECT_BACKUP_SIZE 32

/* The maximum function name size. */
#define INJECT_FUNC_SIZE 64

typedef struct {
  char    map_path[INJECT_PATH_SIZE + 1];
  size_t  map_offset;
  char    symbol_name[INJECT_FUNC_SIZE + 1];
  size_t  symbol_offset;
  size_t  symbol_index;
} inject_info_t;

int inject_dlopen(int pid, const char *map_path);
char **inject_get_maps(int pid);
int inject_getaddr_info(int pid, const char *map, const char *func, inject_info_t *info);
int inject_call(int pid, inject_info_t *target, const char *arg);
int inject_remap(int pid, inject_info_t *original, inject_info_t *replacement);

#endif /* INJECT_H */
