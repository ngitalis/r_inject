/*
**                     Dependency Injection Library
**                               (inject.c) 
*/

#include <inject.h>

/*
** retrieves an address from /proc/[pid]/maps for name:library_filename
** and returns it as a (void *)
*/
static size_t find_address(int pid, const char *library_filename, char *lib_path) {
  int
    i;

  size_t
    converted_address,
    library_address = 0;

  FILE
    *f = NULL;

  char
    line[1024],
    *token = NULL,
    *found_address = NULL,
    *mmap_path = NULL,
    *history[6];

  mmap_path = malloc(sizeof(char) * strlen("/proc/maps") + 11);
  if(mmap_path == NULL) {
    goto end;
  }
  sprintf(mmap_path, "/proc/%d/maps", pid);

  f = fopen(mmap_path, "r");
  if (f == NULL)
    goto end;

  while(fgets(line, sizeof(line), f)) {
    token = strtok(line, " ");
    history[0] = token;

    for(i = 1; (token = strtok(NULL, " \n")) != NULL; i++) {
      history[i] = token;
    }

    if (strstr(history[i - 1], library_filename) != NULL) {
      found_address = strtok(history[0], "-");
      if(lib_path != NULL)
	strcpy(lib_path, history[i - 1]);
      break;
    }
  }

end:
  if(f != NULL)
    fclose(f);

  free(mmap_path);

  if(found_address != NULL) {
    converted_address = strtoll(found_address, NULL, 16);
    library_address = converted_address;
  }

  return library_address;
}

static int str2mcode(char *mcode, const int offset, const char *string) {
  unsigned int word;
  int i, z;

  /* converts a hex string into proper format for code injection: */
  /* 0x8AABBCCDD must become char[] = "\xDD \xCC \xBB \xAA \x08" */
  for(i = (strlen(string) - 2), z = offset;
      i >= 2;
      i -= 2, z++) {
    sscanf(string + i, "%2x", &word);
    mcode[z] = word;
  }
  /* if its odd length -> 0x (*) ** ** **, gotta grab one more */
  if(strlen(string) % 2 == 1) {
    sscanf(string + 2, "%1x", &word);
    mcode[z] = word;
  }

  return z - offset;
}

/*
** Read full ELF header into *header
*/
static int read_header(int d, Elf_Ehdr **header) {

  *header = (Elf_Ehdr *)malloc(sizeof(Elf_Ehdr));

  if (lseek(d, 0, SEEK_SET) < 0) {
    free(*header);
    return -1;
  }

  if (read(d, *header, sizeof(Elf_Ehdr)) <= 0) {
    free(*header);
    return -1;
  }

  return 0;
}

/*
** Uses *header to find the number of section headers in the section table
** Than reads the section header table into **table
*/
static int read_section_table(int d, Elf_Ehdr const *header, Elf_Shdr **table) {
  size_t size;

  if (NULL == header) {
    errno = EINVAL;
    return -1;
  }

  size = header->e_shnum * sizeof(Elf_Shdr);
  *table = (Elf_Shdr *)malloc(size);
  if(table == NULL) {
    return -1;
  }

  if (lseek(d, header->e_shoff, SEEK_SET) < 0) {
    free(*table);
    return -1;
  }

  if (read(d, *table, size) <= 0) {
    free(*table);
    return -1;
  }

  return 0;
}

/*
** Uses *section to determine the amount of symbol strings in the section
** Than reads the string table for *section into **strings
** Must feed in &sections[header->e_shstrndx] from a collection
**   for the string table index.
*/
static int read_string_table(int d, Elf_Shdr const *section, char const **strings) {
  errno = 0;

  if (NULL == section) {
    errno = EINVAL;
    return -1;
  }

  *strings = (char const *)malloc(section->sh_size);
  if(strings == NULL) {
    return -1;
  }

  if (lseek(d, section->sh_offset, SEEK_SET) < 0) {
    free((void *)*strings);
    return -1;
  }

  if (read(d, (char *)*strings, section->sh_size) <= 0) {
    free((void *)*strings);
    return -1;
  }

  return 0;
}

/*
** Uses *section to determine the amount of symbols in the section
** Than reads the symbol headers for *section into **table
** (different from read_string_table, in that this uses Elf_Sym type
**     rather then a string type array)
*/
static int read_symbol_table(int d, Elf_Shdr const *section, Elf_Sym **table) {
  errno = 0;

  if (NULL == section) {
    errno = EINVAL;
    return -1;
  }

  *table = (Elf_Sym *)malloc(section->sh_size);
  if(table == NULL) {
    return -1;
  }

  if (lseek(d, section->sh_offset, SEEK_SET) < 0) {
    free(*table);
    return -1;
  }

  if (read(d, *table, section->sh_size) <= 0) {
    free(*table);
    return -1;
  }

  return 0;
}

/*
** Reads header, than section table using header.
** Than copys index section header into **section
*/
static int section_by_index(int d, size_t index, Elf_Shdr **section) {
  Elf_Ehdr *header = NULL;
  Elf_Shdr *sections = NULL;
  int err = 0;

  errno = 0;
  *section = NULL;

  if (read_header(d, &header)
      || read_section_table(d, header, &sections)) {
    goto end;
  }

  if (index < header->e_shnum) {
    *section = (Elf_Shdr *)malloc(sizeof(Elf_Shdr));
    if (NULL == *section) {
      goto end;
    }

    memcpy(*section, sections + index, sizeof(Elf_Shdr));
  }
  else {
    errno = EINVAL;
  }

 end:
  if(errno)
    err = errno;

  free(header);
  free(sections);

  if(err) {
    errno = err;
    err = -1;
  }

  return err;
}

/*
** Reads header, than section table from header.
** Than scans through the section table looking for match on section_type
** Copys section_type section header into **section
*/
static int section_by_type(int d, size_t section_type, Elf_Shdr **section) {
  Elf_Ehdr *header = NULL;
  Elf_Shdr *sections = NULL;
  size_t i;
  int err = 0;

  errno = 0;
  *section = NULL;

  if (read_header(d, &header)
      || read_section_table(d, header, &sections)) {
    goto end;
  }

  for (i = 0; i < header->e_shnum; ++i) {
    if (section_type == sections[i].sh_type) {

      *section = (Elf_Shdr *)malloc(sizeof(Elf_Shdr));
      if (NULL == *section) {
        goto end;
      }

      memcpy(*section, sections + i, sizeof(Elf_Shdr));

      break;
    }
  }

 end:
  if(errno)
    err = errno;

  free(header);
  free(sections);

  if(err) {
    errno = err;
    err = -1;
  }

  return err;
}

/*
** Reads header, Than section table from header,
** Than String table using the header string index and the found section table.
**
** Scans through the string table looking for match on section_name
** Copys section_name section header into **section
*/
static int section_by_name(int d, char const *section_name, Elf_Shdr **section) {
  Elf_Ehdr *header = NULL;
  Elf_Shdr *sections = NULL;
  char const *strings = NULL;
  size_t i;
  int err = 0;

  errno = 0;
  *section = NULL;

  if (read_header(d, &header)
      || read_section_table(d, header, &sections)
      || read_string_table(d, &sections[header->e_shstrndx], &strings)) {
    goto end;
  }

  for (i = 0; i < header->e_shnum; ++i) {
    if (!strcmp(section_name, &strings[sections[i].sh_name])) {

      *section = (Elf_Shdr *)malloc(sizeof(Elf_Shdr));
      if (NULL == *section) {
        goto end;
      }

      memcpy(*section, sections + i, sizeof(Elf_Shdr));

      break;
    }
  }

 end:
  if(errno)
    err = errno;

  free(header);
  free(sections);
  free((void *)strings);

  if(err) {
    errno = err;
    err = -1;
  }

  return err;
}

/* Reads the .rel_plt table into rel_plt_table, remember to free it */
static int read_rel_table(int d, const Elf_Shdr *section, Elf_Rel **rel_plt_table) {
  errno = 0;

  *rel_plt_table = (Elf_Rel *)malloc(section->sh_size);

  if (lseek(d, section->sh_offset, SEEK_SET) < 0) {
    free(*rel_plt_table);
    return -1;
  }

  if (read(d, *rel_plt_table, section->sh_size) <= 0) {
    free(*rel_plt_table);
    return -1;
  }

  return 0;
}

/*
** Reads string table index into &strings_section using section->sh_link
**      (sections symtable strings index)
** Than reads strings for the *sections symbols into &strings
** Than reads symbol indexes for *section into &symbols
**
** Scans string table@index: symbols[i].st_name until match found on *name
** Copys found Symbol[i] into **symbol
*/
static int symbol_by_name(int d, const Elf_Shdr *section, char const *name, Elf_Sym **symbol,
                   size_t *index) {
  Elf_Shdr *strings_section = NULL;
  char const *strings = NULL;
  Elf_Sym *symbols = NULL;
  size_t i, amount;
  int err = 0;

  errno = 0;
  *symbol = NULL;
  *index = 0;

  if (section_by_index(d, section->sh_link, &strings_section)
      || read_string_table(d, strings_section, &strings)
      || read_symbol_table(d, section, &symbols)) {
    goto end;
  }

  amount = section->sh_size / sizeof(Elf_Sym);

  for (i = 0; i < amount; ++i) {
    if (!strcmp(name, &strings[symbols[i].st_name])) {

      *symbol = (Elf_Sym *)malloc(sizeof(Elf_Sym));
      if (NULL == *symbol) {
        goto end;
      }

      memcpy(*symbol, symbols + i, sizeof(Elf_Sym));
      *index = i;

      break;
    }
  }

  if (i == amount) {
    errno = ENOENT;
    goto end;
  }

 end:
  if(errno)
    err = errno;

  free(strings_section);
  free((void *)strings);
  free(symbols);

  if(err) {
    errno = err;
    err = -1;
  }
  return err;
}

static int inject_attach(int pid, int *status) {
  int err;

  err = ptrace(PTRACE_ATTACH, pid, NULL, NULL);
  if(err)
    goto end;
  wait(status);

 end:
  return err;
}

static int inject_detach(int pid, int *status) {
  int err;

  err = ptrace(PTRACE_DETACH, pid, NULL, NULL);
  if(err)
    goto end;

  wait(status);  
 end: 
  return err;
}

static int inject_cont(int pid, int *status) {
  int err;

  err = ptrace(PTRACE_CONT, pid, 0 , 0);
  if(err)
    goto end;

  wait(status);
 end:
  return err;
}

/* for pid: pauses the program, and injects some machine code to call 
 *          func_info function with a single string argument arg, than calls it and reverts
 *          pid program to its state before this was called    
 * this program briefly pauses the running process!
 */
int inject_call(int pid, inject_info_t *func_info, const char *arg) {
  int
    i, z, err = 0,
    status,
    prog_fd;

  Elf_Shdr
    *dynsym = NULL,
    *dot_text = NULL;

  Elf_Sym
    *symbol = NULL;

  size_t
    offset,
    orig_mcode[INJECT_BACKUP_SIZE];

  struct user_regs_struct
    original_regs,
    regs;

  char
    sub_addr[18],
    *fd_path = NULL,
    mcode[41] =
/* _start */
    "\xeb\x1e"                                       /* JMP B */
/* A: */
    "\x48\x31\xc0"                                   /* xor %rax, %rax */
    "\x48\x31\xf6"                                   /* xor %rsi, %rsi */
    "\x48\x31\xff"                                   /* xor %rdi, %rdi */
    "\x48\xb8\x00\x00\x00\x00\x00\x00\x00\x00"       /* movabs $address, %rax */
    "\x48\xc7\xc6\x02\x00\x00\x00"                   /* mov $0x2, %rsi */
    "\x5f"                                           /* pop %rdi */
    "\xff\xd0"                                       /* call *%rax */
    "\xcc"                                           /* int3 */
/* B: */
    "\xe8\xdd\xff\xff\xff"                           /* JMP A */
    "\x00\x00\x00";                                  /* argument / path to file ... */

  errno = 0;

  /* make sure path is under INJECT_PATH_SIZE characters */
  if(arg != NULL && strlen(arg) > INJECT_PATH_SIZE) {
    errno = EINVAL;
    return -1;
  }

  /* write dlopen address into x00's "\x48\xb8\x00\x00\x00\x00\x00\x00\x00\x00" */
  sprintf(sub_addr, "%p", (size_t *)(func_info->map_offset + func_info->symbol_offset));
  /* 13 = offset into mcode to put $address */
  str2mcode(mcode, 13, sub_addr);

  /* get the application fd */
  fd_path = malloc(sizeof(char) * strlen("/proc//exe") + 11);
  if(fd_path == NULL) {
    goto end;
  }
  sprintf(fd_path, "/proc/%d/exe", pid);

  prog_fd = open(fd_path, O_RDONLY);
  if (prog_fd < 0) {
    goto end;
  }

  /* set offset to application fd -> .text section */
  if(section_by_name(prog_fd, ".text", &dot_text)) {
    goto end;
  }
  offset = dot_text->sh_addr;

  /* TODO: CHECK TEXT SECTION SIZE */

  /* pause pid */
  if(inject_attach(pid, &status))
     goto end;

  /* get regs */
  err = ptrace(PTRACE_GETREGS, pid, NULL, &original_regs);
  if(err) {
    goto end;
  }
  regs = original_regs;

  /* store original code  */
  for(i = 0, z = 0; z < INJECT_BACKUP_SIZE; i += 8, z++) {
    orig_mcode[z] = ptrace(PTRACE_PEEKDATA, pid, (offset + i), 0);
    if(orig_mcode[z] == -1) {
      goto end;
    }
  }

  /* write NEW mcode 5 * 8 bytes! */
  for(i = 0; i <= 40; i += 8) {
    err = ptrace(PTRACE_POKEDATA, pid, (offset + i), *(size_t *)(mcode + i));
    if (err)
      goto fix_attempt;
  }

  /* write in path to injectme (up to INJECT_PATH_SIZE characters) */
  /* i starts at 37, as the actual end of mcode = offset 37 */
  if( arg != NULL ) {
    for(i = 37, z = 0; i <= (strlen(arg) + 37); i += 8, z += 8) {
      err = ptrace(PTRACE_POKEDATA, pid, (offset + i), *(size_t *)(arg + z));
      if (err)
        goto fix_attempt;
    }
  }

  /* set stack pointer to .text offset */
  regs.rip = (offset + 2);
  err = ptrace(PTRACE_SETREGS, pid, NULL, &regs);
  if(err)
    goto fix_attempt;

  /* continue */
  if(inject_cont(pid, &status))
    goto fix_attempt;

  /* replace saved code */
  for(i = 0, z = 0; z < INJECT_BACKUP_SIZE; i += 8, z++) {
    err = ptrace(PTRACE_POKEDATA, pid, offset + i, (size_t *)orig_mcode[z]);
    if(err)
      exit(1);
  }

  /* replace original register values */
  err = ptrace(PTRACE_SETREGS, pid, NULL, &original_regs);
  if(err)
    exit(1);

 end:
  if(errno)
    err = errno;

  close(prog_fd);
  free(dynsym);
  free(symbol);
  free(dot_text);
  free(fd_path);
  inject_detach(pid, &status);

  if(err) {
    errno = err;
    err = -1;
  }

  return err;

 fix_attempt:
  for(i = 0, z = 0; i < INJECT_BACKUP_SIZE; i += 8, z++) {
    err = ptrace(PTRACE_POKEDATA, pid, offset + i, (size_t *)orig_mcode[z]);
    err = ptrace(PTRACE_SETREGS, pid, NULL, &original_regs);
    if (err)
      exit(1);
  }
  errno = EINVAL;
  goto end;
}

/* Uses call to one off call dlopen on map_path */
int inject_dlopen(int pid, const char *map_path) {
  int map_path_check = -1;
  inject_info_t func_info;

  if(map_path == NULL || map_path[0] != '/') {
    errno = EINVAL;
    return -1;
  }

  map_path_check = open(map_path, O_RDONLY);
  if(map_path_check < 0) {
    errno = EINVAL;
    close(map_path_check);
    return -1;
  }

  close(map_path_check);

  /* get address of function */
  if(inject_getaddr_info(pid, "/libc-", "__libc_dlopen_mode", &func_info) < 0)
      return -1;

  return inject_call(pid, &func_info, map_path);
}

/* gets a list of target pid's individual maps (r-xp only) in /proc/[pid]/maps */
char **inject_get_maps(int pid) {
  int
    i, x = 0,
    err = 0,
    total_count = 0;

  FILE
    *f = NULL;

  char
    line[1024],
    *token = NULL,
    *mmap_path = NULL,
    *history[6],
    **map_list = NULL;

  errno = 0;

  mmap_path = malloc(sizeof(char) * strlen("/proc//maps") + 11);
  if(mmap_path == NULL) {
    goto end;
  }
  sprintf(mmap_path, "/proc/%d/maps", pid);


  /* count */
  f = fopen(mmap_path, "r");
  if (f == NULL)
    goto end;

  while(fgets(line, sizeof(line), f)) {
    token = strtok(line, " ");
    history[0] = token;

    for(i = 1; ( (token = strtok(NULL, " \n")) != NULL ) && i < 6; i++) {
      history[i] = token;
    }

    /* 7fbc40ef7000-7fbc40ef9000 r-xp 00021000 08:01 19009135 /lib/x86_64-linux-gnu/ld-2.13.so */
    /* if value @ token: 19009135 is NOT 0 */
    /* and is r-xp */
    if(strcmp("0", history[i - 2]) != 0
       && strcmp("r-xp", history[i - 5]) == 0) {
      total_count++;
    }
  }


  /* malloc */
  map_list = (char **)malloc(sizeof(char *) * total_count + 1);
  if(map_list == NULL)
    goto end;

  /* add null terminator */
  for(i = 0; i < total_count; i++) {
    map_list[i] = (char *)malloc(sizeof(char) * INJECT_PATH_SIZE);
    if(map_list[i] == NULL) {
      free(map_list);
      map_list = NULL;
      goto end;
    }
  }
  map_list[i] = NULL;


  /* reopen and write */
  f = freopen(mmap_path, "r", f);
  if (f == NULL)
    goto end;

  while(fgets(line, sizeof(line), f)) {
    token = strtok(line, " ");
    history[0] = token;

    for(i = 1; (token = strtok(NULL, " \n")) != NULL; i++) {
      history[i] = token;
    }

    /* 7fbc40ef7000-7fbc40ef9000 r-xp 00021000 08:01 19009135 /lib/x86_64-linux-gnu/ld-2.13.so */
    /* if value @ token: 19009135 is NOT 0 */
    /* and is r-xp */
    if(strcmp("0", history[i - 2]) != 0
       && strcmp("r-xp", history[i - 5]) == 0) {
      if(snprintf(map_list[x], strlen(history[i - 1]) + 1, "%s", history[i - 1]) < 0) {
	/* error - free and null */
	for(x = 0; x < total_count + 1; x++)
	  free(map_list[x]);
	free(map_list);
	map_list = NULL;
	goto end;
      }
      x++;
    }
  }


end:
  if(errno)
    err = errno;

  if(f != NULL)
    fclose(f);

  if(err) {
    errno = err;
    err = -1;
  }

  return map_list;
}

/* populates a inject_info_t struct with the information neccesary for relocation to happen
 * map = a mapname to find in /proc/[pid]/maps
 * func = a function to find that resides inside *map
 */
int inject_getaddr_info(int pid, const char *map, const char *func, inject_info_t *info) {
  int
    fd,
    err = 0;

  Elf_Shdr
    *dynsym = NULL;

  Elf_Sym
    *symbol = NULL;

  size_t
    symbol_index,
    temp_offset;

  char
    lib_path[INJECT_PATH_SIZE + 1];

  errno = 0;

  if(map == NULL
     || func == NULL
     || info == NULL) {
    errno = EINVAL;
    goto end;
  }

  if(strlen(func) > INJECT_FUNC_SIZE) {
    errno = EINVAL;
    goto end;
  }

  if(strlen(map) > INJECT_PATH_SIZE) {
    errno = EINVAL;
    goto end;
  }

  /* get library_address */
  /* temp as this is called in a loop, and gets to this point and fails */
  /* we need library address to not be re-written in that case */
  temp_offset = find_address(pid, map, lib_path);
  if(temp_offset == 0) {
    errno = EINVAL;
    goto end;
  }

  /* get file descriptor */
  fd = open(lib_path, O_RDONLY);
  if (fd < 0) {
    goto end;
  }

  if (section_by_type(fd, SHT_DYNSYM, &dynsym)) {
    goto end;
  }

  if(symbol_by_name(fd, dynsym,
		    func, &symbol, &symbol_index)) {
    goto end;
  }

  if(snprintf(info->map_path, strlen(lib_path) + 1, "%s", lib_path) < 0) {
    goto end;
  }

  if(snprintf(info->symbol_name, strlen(func) + 1, "%s", func) < 0) {
    goto end;
  }

  info->symbol_offset = symbol->st_value;

  info->symbol_index = symbol_index;
  
  info->map_offset =  temp_offset;

 end:
  if(errno)
    err = errno;

  if(fd > 0) {
    close(fd);
  }
  free(dynsym);
  free(symbol);

  if(err) {
    errno = err;
    err = -1;
  }

  return err;
}

/* performs the relocation swap of original with replacement on pid */
/* this function briefly pauses the running pid */
int inject_remap(int pid, inject_info_t *original, inject_info_t *replacement) {
  int
    fd, i,
    found = 0,
    err = 0,
    status;

  Elf_Shdr
    *rel_plt = NULL;

  Elf_Rel
    *rel_plt_table = NULL;

  size_t
    rel_plt_amount;

  errno = 0;

  if(original == NULL
     || replacement == NULL) {
    errno = EINVAL;
    goto end;
  }

  fd = open(original->map_path, O_RDONLY);
  if (fd < 0) {
    goto end;
  }

  if (section_by_name(fd, REL_PLT, &rel_plt)) {
    goto end;
  }

  if (read_rel_table(fd, rel_plt, &rel_plt_table)) {
    goto end;
  }

  rel_plt_amount = rel_plt->sh_size / sizeof(Elf_Rel);


  for (i = 0; i < rel_plt_amount; ++i) {
    /* if the symbol index from .dynsym matches index of symbol in .rela.plt */
    if (ELF_R_SYM(rel_plt_table[i].r_info) == original->symbol_index) {
      /* write our substitute function address to memory offset @((size_t)library_address)
      **                                                         + rel_plt_table[i].r_offset)
      */
      if(inject_attach(pid, &status))
	goto end;

      err = ptrace(PTRACE_POKEDATA, pid, rel_plt_table[i].r_offset,
		   replacement->map_offset + replacement->symbol_offset);
      if(err)
	goto end;

      if(inject_detach(pid, &status))
	goto end;

      found = 1;
      break;
    }
  }

  if(!found)
    errno = EINVAL;

 end:
  if(errno)
    err = errno;

  free(rel_plt);
  free(rel_plt_table);

  if(err) {
    errno = err;
    err = -1;
  }

  return err;
}
