#ifndef _SOLIST_H
#define _SOLIST_H

#include <elf.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <elf.h>
#include <sys/mman.h>


#define ANDROID_ARM_LINKER

#define SOINFO_NAME_LEN 128

#define SHT_ARM_EXIDEX 0x70000001
#define SHF_LINKORDER 0x80
#define SHT_FINI_ARRAY 15
#define SHT_INIT_ARRAY 14
#define PT_ARM_EXIDEX 0x70000001

#ifndef DT_INIT_ARRAY
#define DT_INIT_ARRAY      25
#endif

#ifndef DT_FINI_ARRAY
#define DT_FINI_ARRAY      26
#endif

#ifndef DT_INIT_ARRAYSZ
#define DT_INIT_ARRAYSZ    27
#endif

#ifndef DT_FINI_ARRAYSZ
#define DT_FINI_ARRAYSZ    28
#endif

#ifndef DT_PREINIT_ARRAY
#define DT_PREINIT_ARRAY   32
#endif

#ifndef DT_PREINIT_ARRAYSZ
#define DT_PREINIT_ARRAYSZ 33
#endif

struct link_map
{
	uintptr_t l_addr;
	char * l_name;
	uintptr_t l_ld;
	struct link_map * l_next;
	struct link_map * l_prev;
};

typedef struct soinfo soinfo;

struct soinfo
{
	const char name[SOINFO_NAME_LEN];
	Elf32_Phdr *phdr;
	int phnum;
	unsigned entry;
	unsigned base;
	unsigned size;

	unsigned *dynamic;

	unsigned wrprotect_start;
	unsigned wrprotect_end;

	soinfo *next;
	unsigned flags;

	const char *strtab;
	Elf32_Sym *symtab;
	unsigned strsz;

	unsigned nbucket;
	unsigned nchain;
	unsigned *bucket;
	unsigned *chain;

	unsigned *plt_got;

	Elf32_Rel *plt_rel;
	int plt_rel_count;

	Elf32_Rel *rel;
	int rel_count;

	unsigned *preinit_array;
	unsigned preinit_array_count;

	unsigned *init_array;
	unsigned init_array_count;
	unsigned *fini_array;
	unsigned fini_array_count;

	void(*init_func)(void);
	void(*fini_func)(void);

#ifdef ANDROID_ARM_LINKER
	unsigned *ARM_exidx;
	unsigned ARM_exidx_count;
#endif
	unsigned refcount;
	struct link_map linkmap;
};

struct stFunction
{
	char name[256];
	unsigned addr;
	unsigned offset;
};


#endif
