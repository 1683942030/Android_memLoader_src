/*
*****************************************************************************
* Copyright (C) 2005-2015 UCWEB Inc. All rights reserved
* File        : Loader.h
* Description : mem_loader 内存加载劫持加壳
* Creation    : 2015.8.5
* Author      : LLhack  <yiliu.zyl@alibaba-inc.com>
* History     :
*
******************************************************************************
**/


#ifndef _LOADER_H
#define _LOADER_H

#include "solist.h"
#include "utils.h"
#include <android/log.h> 
#include <pthread.h>

using namespace std;



#define  __TESTER

#ifdef __TESTER
#define  __BINTEST
#define LOG_TAG "LL"
#ifdef __BINTEST 
#define LDBG(format, ...) printf (format, ##__VA_ARGS__)
#else
#define LDBG(format, ...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, format, ##__VA_ARGS__)
#endif
#else
#define LDBG(format, ...)
#endif

/*
* add_elf_define
*/
#define ELF_PAGE_SIZE        4096
#define ELF_PAGE_MASK        4095
#define SO_MAX               128
#define FLAG_EXE             0x00000004
#ifndef PT_ARM_EXIDX
#define PT_ARM_EXIDX         0x70000001
#endif

/*
* added
*/
#define R_ARM_COPY       20
#define R_ARM_GLOB_DAT   21
#define R_ARM_JUMP_SLOT  22
#define R_ARM_RELATIVE   23
#define R_ARM_ABS32      2
#define R_ARM_REL32      3

/*
* define_mmap_prot
*/
#define MAYBE_MAP_FLAG(x,from,to)    (((x) & (from)) ? (to) : 0)
#define PFLAGS_TO_PROT(x)            (MAYBE_MAP_FLAG((x), PF_X, PROT_EXEC) | \
	MAYBE_MAP_FLAG((x), PF_R, PROT_READ) | \
	MAYBE_MAP_FLAG((x), PF_W, PROT_WRITE))

#define  MAX_SIZE 512

class loader
{
public:
	loader();
	~loader();
	int m_soCount;
	soinfo* m_sopool_dep[SO_MAX];
	int m_pid;
	

public:
	soinfo* LL_dlopen(char *path);
	soinfo* LL_dlopenwitBuffer(const char *selfname, unsigned char* buffer);
	unsigned int LL_dlsym(soinfo *si, char *func_name);
	int		LL_dlcolse(soinfo *si);
	void	LL_getMySymAddr(soinfo *si);

private:
	int _traveDir(char* path, char filePath[][MAX_SIZE], int pathSize, int depth);
	unsigned _elfhash(const char *_name);
	unsigned _getLibExtents(void *__hdr, unsigned *size);
	int _allocMemRegion(soinfo *si);
	void _call_array(unsigned *ctor, int count, int reverse);
	int _linkImage(soinfo *si);
	unsigned _findSym(soinfo *si, const char* name);
	int relocLibrary(soinfo *si, Elf32_Rel *rel, unsigned count);
	soinfo *alloc_info(const char *name);
	int loadDependedLibray(soinfo *si);
	int isFindedModule(int pid, char *module_name);
	int relocSym(const char *name, unsigned base, unsigned r_offset);
	int doDependeLibSymReloc(soinfo *si);
	void callConstructors(soinfo *si);
	void callDestructors(soinfo *si);
	soinfo *loadLibrary(const char* name);
	soinfo *loadLibrarywithBuffer(const char* name, unsigned char* buffer);
	int getLibBufferbyBin(const char *name, unsigned char *buffer);
	int loadSegmentswitBuff(void *header, soinfo *si);
	soinfo *loadLibInternalwithBuffer(const char *name, unsigned char *buffer);
};

extern "C"int __aeabi_atexit(void* object, void(*destructor)(void*), void* dso_handle); 

/*  we also use it
extern "C" int __cxa_atexit(void(*)(void*), void*, void*);

static int __aeabi_atexit(void* object, void(*destructor)(void*), void* dso_handle)
{
	return __cxa_atexit(destructor, object, dso_handle);
}
*/
#endif

