/*
*****************************************************************************
* Copyright (C) 2005-2015 UCWEB Inc. All rights reserved
* File        : Loader.cpp
* Description : mem_loader 内存加载劫持加壳
* Creation    : 2015.8.5
* Author      : LLhack  <yiliu.zyl@alibaba-inc.com>
* History     :
*
******************************************************************************
**/

#include "Loader.h"
#include <dlfcn.h> 
#include <jni.h>
#include "solist.h"
#include <dirent.h>
#include "utils.h"




namespace
{
	const char* const kDefaultLdPaths[] =
	{ 
		"/system/lib",
		"/vendor/lib", 
		NULL 
	};
	soinfo slf = {0};
}

loader::loader()
	: m_pid(0),
	m_soCount(0)
{
	m_sopool_dep[SO_MAX] = {0};
}

loader::~loader()
{

}

int loader::isFindedModule(int m_pid, char *module_name)
{
	char filename[256] = { 0 };
	char name[256] = { 0 };
	snprintf(filename, sizeof(filename), "/proc/%d/maps", m_pid);
	FILE *fsrc;
	int ret = 0;
	if ((fsrc = fopen(filename, "r")) == NULL)
	{
		return 0;
	}
	else
	{
		while (ret != EOF)
		{
			ret = fscanf(fsrc, "%s\n", name);
			LDBG("is load lib:[%s]\n", name);
			if (strstr(name, module_name) != NULL)
			{
				fclose(fsrc);
				return 1;
			}
		}
	}
	return 0;
}


unsigned loader::_elfhash(const char *_name)
{
	const unsigned char *name = (const unsigned char *)_name;
	unsigned h = 0, g = 0;

	while (*name) {
		h = (h << 4) + *name++;
		g = h & 0xf0000000;
		h ^= g;
		h ^= g >> 24;
	}
	return h;
}

/*
* get_need_mmap_bufer
* buffe_size == si->size
*/
unsigned loader::_getLibExtents(void *__hdr, unsigned *size)
{
	unsigned req_base = 0;
	unsigned min_vaddr = 0xffffffff;
	unsigned max_vaddr = 0;
	unsigned char *_hdr = (unsigned char *)__hdr;
	Elf32_Ehdr *ehdr = (Elf32_Ehdr *)_hdr;
	Elf32_Phdr *phdr;
	int cnt;

	phdr = (Elf32_Phdr *)(_hdr + ehdr->e_phoff);

	/* find the min/max p_vaddrs from all the PT_LOAD segments so we can
	* get the range. */
	for (cnt = 0; cnt < ehdr->e_phnum; ++cnt, ++phdr)
	{
		if (phdr->p_type == PT_LOAD)
		{
			if ((phdr->p_vaddr + phdr->p_memsz) > max_vaddr)
				max_vaddr = phdr->p_vaddr + phdr->p_memsz;
			if (phdr->p_vaddr < min_vaddr)
				min_vaddr = phdr->p_vaddr;
		}
	}

	if ((min_vaddr == 0xffffffff) && (max_vaddr == 0))
	{
		return (unsigned)-1;
	}

	/* truncate min_vaddr down to page boundary */
	min_vaddr &= ~ELF_PAGE_MASK;

	/* round max_vaddr up to the next page */
	max_vaddr = (max_vaddr + ELF_PAGE_SIZE - 1) & ~ELF_PAGE_MASK;

	*size = (max_vaddr - min_vaddr);

	return (unsigned)req_base;
}

/*
* mmap_so_buffer
*/
int loader::_allocMemRegion(soinfo *si)
{
	void *base = mmap(NULL, si->size, PROT_READ | PROT_EXEC | PROT_WRITE,
		MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (base == MAP_FAILED)
	{
		LDBG("%5d mmap of library '%s' failed\n",
			m_pid, si->name);
		goto err;
	}
	si->base = (unsigned)base;
	return 0;

err:
	LDBG("OOPS: %5d cannot map library '%s'. no vspace available.",
		m_pid, si->name);
	return -1;
}

/*
* alloc_self_so_strcut 
*/
soinfo* loader::alloc_info(const char *name)
{
	soinfo *si = NULL;
	si = &slf;
	if (si == NULL)
	{
		LDBG("alloca is er \n");
		return NULL;
	}
	if (strlen(name) >= SOINFO_NAME_LEN)
	{
		LDBG("%5d library name %s too long", m_pid, name);
		return NULL;
	}

	if (m_soCount >= 128)
	{
		LDBG("No solist for %s", name);
		return NULL;
	}
	memset(si, 0, sizeof(soinfo));
	strncpy((char*)si->name, name, sizeof(si->name));
	si->next = NULL;
	si->refcount = 0;
	return si;
}

/*
* load_segment
* section to segment
*/
int loader::loadSegmentswitBuff(void *header, soinfo *si)
{
	
	Elf32_Ehdr *ehdr = (Elf32_Ehdr *)header;
	Elf32_Phdr *phdr = (Elf32_Phdr *)((unsigned char *)header + ehdr->e_phoff);
	unsigned char *base = (unsigned char *)si->base;
	int cnt;
	unsigned len;
	unsigned char *tmp;
	unsigned char *pbase;
	unsigned char *extra_base;
	unsigned extra_len;
	unsigned total_sz = 0;
	si->wrprotect_start = 0xffffffff;
	si->wrprotect_end = 0;

	LDBG("[ %5d - Begin loading segments for '%s' @ 0x%08x ]\n",
		m_pid, si->name, (unsigned)si->base);
	/* Now go through all the PT_LOAD segments and map them into memory
	* at the appropriate locations. */
	for (cnt = 0; cnt < ehdr->e_phnum; ++cnt, ++phdr)
	{
		if (phdr->p_type == PT_LOAD)
		{
			/* we want to map in the segment on a page boundary */
			tmp = base + (phdr->p_vaddr & (~ELF_PAGE_MASK));
			/* add the # of bytes we masked off above to the total length. */
			len = phdr->p_filesz + (phdr->p_vaddr & ELF_PAGE_MASK);

			LDBG("[ %d - Trying to load segment from '%s' @ 0x%08x "
				"(0x%08x). p_vaddr=0x%08x p_offset=0x%08x  data:[0x%x] ]\n", m_pid, si->name,
				(unsigned)tmp, len, phdr->p_vaddr, phdr->p_offset, *(char*)((unsigned)phdr + phdr->p_offset & (~ELF_PAGE_MASK)));
			memcpy(tmp, (void*)((unsigned)phdr + phdr->p_offset & (~ELF_PAGE_MASK)), len);
			pbase = tmp;
			LDBG("pbase:[%p]tmp:[%p]si.base:[%p]len[%d]\n", pbase, tmp,base, len);
			if (pbase == MAP_FAILED)
			{
				LDBG("%d failed to map segment from '%s' @ 0x%08x (0x%08x). "
					"p_vaddr=0x%08x p_offset=0x%08x", m_pid, si->name,
					(unsigned)tmp, len, phdr->p_vaddr, phdr->p_offset);
				goto fail;
			}

			/* If 'len' didn't end on page boundary, and it's a writable
			* segment, zero-fill the rest. */
			if ((len & ELF_PAGE_MASK) && (phdr->p_flags & PF_W))
				memset((void *)(pbase + len), 0, ELF_PAGE_SIZE - (len & ELF_PAGE_MASK));
			tmp = (unsigned char *)(((unsigned)pbase + len + ELF_PAGE_SIZE - 1) &
				(~ELF_PAGE_MASK));
			if (tmp < (base + phdr->p_vaddr + phdr->p_memsz))
			{
				extra_len = base + phdr->p_vaddr + phdr->p_memsz - tmp;
				/* map in the extra page(s) as anonymous into the range.
				* This is probably not necessary as we already mapped in
				* the entire region previously, but we just want to be
				* sure. This will also set the right flags on the region
				* (though we can probably accomplish the same thing with
				* mprotect).
				*/
				extra_base = (unsigned char*)mmap((void *)tmp, extra_len,
					PFLAGS_TO_PROT(phdr->p_flags),
					MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS,
					-1, 0);
				if (extra_base == MAP_FAILED)
				{
					LDBG("[ %5d - failed to extend segment from '%s' @ 0x%08x"
						" (0x%08x) ]", m_pid, si->name, (unsigned)tmp,
						extra_len);
					goto fail;
				}
			}
			/* set the len here to show the full extent of the segment we
			* just loaded, mostly for debugging */
			len = (((unsigned)base + phdr->p_vaddr + phdr->p_memsz +
				ELF_PAGE_SIZE - 1) & (~ELF_PAGE_MASK)) - (unsigned)pbase;
			total_sz += len;

			if (!(phdr->p_flags & PF_W))
			{
				if ((unsigned)pbase < si->wrprotect_start)
					si->wrprotect_start = (unsigned)pbase;
				if (((unsigned)pbase + len) > si->wrprotect_end)
					si->wrprotect_end = (unsigned)pbase + len;
				mprotect(pbase, len,
					PFLAGS_TO_PROT(phdr->p_flags) | PROT_WRITE);
			}
		}
		else if (phdr->p_type == PT_DYNAMIC)
		{

			si->dynamic = (unsigned *)(base + phdr->p_vaddr);
		}
		else
		{
#ifdef ANDROID_ARM_LINKER
			if (phdr->p_type == PT_ARM_EXIDX)
			{

				si->ARM_exidx = (unsigned *)phdr->p_vaddr;
				si->ARM_exidx_count = phdr->p_memsz / 8;
			}
#endif
		}
	}
	LDBG("%5d - Total length (0x%08x) of mapped segments from '%s' phdr:[%p] phnum:[%d] \n",
		m_pid, total_sz, si->name,si->phdr,si->phnum);
	/* Sanity check */
	if (total_sz > si->size)
	{
		LDBG("%5d - Total length (0x%08x) of mapped segments from '%s' is "
			"greater than what was allocated (0x%08x). THIS IS BAD!",
			m_pid, total_sz, si->name, si->size);
		goto fail;
	}
	return 0;

fail:
	munmap((void *)si->base, si->size);
	return -1;
}



soinfo* loader::loadLibInternalwithBuffer(const char *name, unsigned char *buffer)
{
	unsigned ext_sz;
	unsigned req_base;
	const char *bname;
	soinfo *si = NULL;
	Elf32_Ehdr *hdr;
	req_base = _getLibExtents(buffer, &ext_sz);
	if (req_base == (unsigned)-1)
		goto fail;

	bname = strrchr(name, '/');
	si = alloc_info(bname ? bname + 1 : name);
	if (si == NULL)
		goto fail;
	si->base = req_base;
	si->size = ext_sz;
	si->flags = 0;
	si->entry = 0;
	si->dynamic = (unsigned *)-1;

	if (_allocMemRegion(si) < 0)
		goto fail;

	if (loadSegmentswitBuff(buffer, si) < 0)
	{
		goto fail;
	}

	hdr = (Elf32_Ehdr *)si->base;
	si->phdr = (Elf32_Phdr *)((unsigned char *)si->base + hdr->e_phoff);
	si->phnum = hdr->e_phnum;
	return si;

fail:
	return NULL;
}



int loader::_linkImage(soinfo *si)
{
	unsigned *d;
	Elf32_Phdr *phdr = si->phdr;
	int phnum = si->phnum;

	if (si->flags & FLAG_EXE)
	{
		si->size = 0;
		for (; phnum > 0; --phnum, ++phdr)
		{
#ifdef ANDROID_ARM_LINKER
			if (phdr->p_type == PT_ARM_EXIDX)
			{
				/* exidx entries (used for stack unwinding) are 8 bytes each.
				*/
				si->ARM_exidx = (unsigned *)phdr->p_vaddr;
				si->ARM_exidx_count = phdr->p_memsz / 8;
			}
#endif
			if (phdr->p_type == PT_LOAD)
			{
				if (!(phdr->p_flags & PF_W))
				{
					unsigned _end;

					if (phdr->p_vaddr < si->wrprotect_start)
						si->wrprotect_start = phdr->p_vaddr;
					_end = (((phdr->p_vaddr + phdr->p_memsz + ELF_PAGE_SIZE - 1) &
						(~ELF_PAGE_MASK)));
					if (_end > si->wrprotect_end)
						si->wrprotect_end = _end;
				}
			}
			else if (phdr->p_type == PT_DYNAMIC)
			{
				if (si->dynamic != (unsigned *)-1)
				{
					LDBG("%5d multiple PT_DYNAMIC segments found in '%s'. "
						"Segment at 0x%08x, previously one found at 0x%08x",
						m_pid, si->name, si->base + phdr->p_vaddr,
						(unsigned)si->dynamic);
					goto fail;
				}
				si->dynamic = (unsigned *)(si->base + phdr->p_vaddr);
			}
		}
	}

	if (si->dynamic == (unsigned *)-1)
	{
		LDBG("%5d missing PT_DYNAMIC?!", m_pid);
		goto fail;
	}
	for (d = si->dynamic; *d; d++)
	{
		switch (*d++)
		{
		case DT_HASH:
			si->nbucket = ((unsigned *)(si->base + *d))[0];
			si->nchain = ((unsigned *)(si->base + *d))[1];
			si->bucket = (unsigned *)(si->base + *d + 8);
			si->chain = (unsigned *)(si->base + *d + 8 + si->nbucket * 4);
			break;
		case DT_STRTAB:
			si->strtab = (const char *)(si->base + *d);
			break;
		case DT_STRSZ:
			si->strsz = *d;
			break;
		case DT_SYMTAB:
			si->symtab = (Elf32_Sym *)(si->base + *d);
			break;
#if !defined(ANDROID_SH_LINKER)
		case DT_PLTREL:
			if (*d != DT_REL)
			{
				LDBG("DT_RELA not supported");
				goto fail;
			}
			break;
#endif
#ifdef ANDROID_SH_LINKER
		case DT_JMPREL:
			si->plt_rela = (Elf32_Rela*)(si->base + *d);
			break;
		case DT_PLTRELSZ:
			si->plt_rela_count = *d / sizeof(Elf32_Rela);
			break;
#else
		case DT_JMPREL:
			si->plt_rel = (Elf32_Rel*)(si->base + *d);
			break;
		case DT_PLTRELSZ:
			si->plt_rel_count = *d / 8;
			break;
#endif
		case DT_REL:
			si->rel = (Elf32_Rel*)(si->base + *d);
			break;
		case DT_RELSZ:
			si->rel_count = *d / 8;
			break;
#ifdef ANDROID_SH_LINKER
		case DT_RELASZ:
			si->rela_count = *d / sizeof(Elf32_Rela);
			break;
#endif
		case DT_PLTGOT:
			/* Save this in case we decide to do lazy binding. We don't yet. */
			si->plt_got = (unsigned *)(si->base + *d);
			break;
		case DT_DEBUG:
			break;
#ifdef ANDROID_SH_LINKER
		case DT_RELA:
			si->rela = (Elf32_Rela *)(si->base + *d);
			break;
#else
		case DT_RELA:
			LDBG("%5d DT_RELA not supported", m_pid);
			goto fail;
#endif
		case DT_INIT:
			si->init_func = (void(*)(void))(si->base + *d);
			LDBG("[so:]init_func addr:[%p] offset:[%p]\n",si->init_func,*d,si->name);
			//if (mprotect((void *)si->init_func, 0x10, PROT_READ | PROT_WRITE |PROT_EXEC) != -1)
			//{
			//	unsigned char setJmpself[4] = { 0xFE, 0xFF, 0xFF, 0xEA};
			//	memcpy((void *)si->init_func, &setJmpself[0], 4);
			//}
			break;
		case DT_FINI:
			si->fini_func = (void(*)(void))(si->base + *d);
			break;
		case DT_INIT_ARRAY:
			si->init_array = (unsigned *)(si->base + *d);
			break;
		case DT_INIT_ARRAYSZ:
			si->init_array_count = ((unsigned)*d) / sizeof(Elf32_Addr);
			break;
		case DT_FINI_ARRAY:
			si->fini_array = (unsigned *)(si->base + *d);
			break;
		case DT_FINI_ARRAYSZ:
			si->fini_array_count = ((unsigned)*d) / sizeof(Elf32_Addr);
			break;
		case DT_PREINIT_ARRAY:
			si->preinit_array = (unsigned *)(si->base + *d);
			break;
		case DT_PREINIT_ARRAYSZ:
			si->preinit_array_count = ((unsigned)*d) / sizeof(Elf32_Addr);
			break;
		case DT_TEXTREL:
			break;
		}
	}
	if ((si->strtab == 0) || (si->symtab == 0))
	{
		LDBG("%5d missing essential tables!!!!!!!!!!\n", m_pid);
		goto fail;
	}
	return 0;

fail:
	LDBG("failed to link%s\n", si->name);
	return -1;
}



soinfo* loader::loadLibrary(const char* name)
{
	soinfo *si = NULL;
	unsigned char *buffer = NULL;
	FILE *fp;
	int nSize = 0;

	if ((fp = fopen(name, "rb")) != NULL)
	{
		fseek(fp, 0, SEEK_END);
		nSize = ftell(fp);
		rewind(fp);
		if (nSize)
		{
			buffer = (unsigned char*)mmap(NULL, nSize, PROT_READ | PROT_EXEC | PROT_WRITE,
				MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
			fread(buffer, sizeof(char), nSize, fp);
		}
	}

	if (buffer != NULL)
	{
		printf("buff:%p\n", buffer);
		si = loadLibInternalwithBuffer(name, buffer);
	}

	munmap(buffer, nSize);
	
	fclose(fp);
	
	if (si == NULL)
	{
		LDBG("Load library [%s]failed\n", si->name);
		goto fail;
	}

	if (_linkImage(si))
	{
		LDBG("Init library [%s]failed\n", si->name);
		munmap((void *)si->base, si->size);
		goto fail;
	}
	return si;
fail:
	m_soCount--;
	return NULL;
}



soinfo* loader::loadLibrarywithBuffer(const char* name, unsigned char* buffer)
{
	soinfo *si = NULL;
	if (buffer != NULL)
	{
		si = loadLibInternalwithBuffer(name, buffer);
	}
	if (si == NULL)
	{
		LDBG("Load library [%s]failed\n", si->name);
		goto fail;
	}

	if (_linkImage(si))
	{
		LDBG("Init library [%s]failed\n", si->name);
		munmap((void *)si->base, si->size);
		goto fail;
	}
	return si;
fail:
	m_soCount--;
	return NULL;
}



int loader::loadDependedLibray(soinfo *si)
{
	unsigned *d;
	char libpath[MAX_PATH] = {0};
	char selfprocName[MAX_PATH] = {0};
	soinfo *sii = NULL;
	int i;
	for (d = si->dynamic; *d; d++)
	{
		switch (*d++)
		{
		case DT_NEEDED:
			for ( i = 0; kDefaultLdPaths[i] != NULL; ++i)
			{
				snprintf(libpath, sizeof(libpath), "%s/%s",
					kDefaultLdPaths[i], si->strtab + *d);
				LDBG("star serch sys dependedLib:[%s]\n", libpath);
				
				sii = (soinfo*)dlopen(libpath, RTLD_NOW);
	
				if (sii !=NULL)
				{
					break;
				}
			}
			if (sii==NULL)//get_self_folder
			{
				LDBG("Cannot find %s library from syspath\n", libpath);
				memset(selfprocName, 0, sizeof(selfprocName));

				utils::_getselfProcName(selfprocName,sizeof(selfprocName));/*apk 调用 使用这个路径*/
				
				/*parse name*/
				const char *bname;
				bname = strrchr(selfprocName, '/');
				
				if (bname[0] != 0)
				{
					snprintf(libpath, sizeof(libpath), "data/data/%s/lib/%s", 
						bname ? bname + 1 : selfprocName, si->strtab + *d);
					LDBG("start serch exe dependedLib:[%s]\n", libpath);
					sii = (soinfo*)dlopen(libpath, RTLD_NOW);
					if (sii==NULL)
					{ 
						return -1;
					}
				}
			}
			m_sopool_dep[m_soCount++] = sii;
			break;
		default:
			break;
		}
	}
	//dlclose(libpath);
	return 0;

}


int loader::relocSym(const char *name, unsigned base, unsigned r_offset)
{
	int i;
	void *vaddr = NULL;
	
	LDBG("m_soCount:%d\n", m_soCount);

	/*__aeabi_atexit weak 函数 需要在链接时自己导入,dlsym无法查询到此函数*/
	if (strcmp(name, "__aeabi_atexit") == 0)
	{
		vaddr = (void*)__aeabi_atexit;		/*extern this fuction*/
		LDBG("__aeabi_atexit:[%p]\n", vaddr);
		*((unsigned*)(base + r_offset)) = (unsigned)vaddr;
		return 0;
	}

	for (i = 0; i<m_soCount; i++)
	{
		soinfo *si = m_sopool_dep[i];
		vaddr  = (void*)dlsym(si, name);
		LDBG("func_name[%s]search_Dep[%s][base:%p]vaddr:[%p]\n",
			name, si->name, si->base, vaddr);
		if (vaddr!=NULL)
		{
			*((unsigned*)(base + r_offset)) = (unsigned)vaddr;
			return 0;
		}
	}

	return -1;
}

/*
* 对symbol_addr重定位
*/
int loader::doDependeLibSymReloc(soinfo *si)
{
	Elf32_Rel *rel = NULL;
	int i;
	rel = si->rel;
	for (i = 0; i < si->rel_count; i++, rel++)
	{
		unsigned sym = ELF32_R_SYM(rel->r_info);
		if (sym != 0)
		{
			LDBG("rel %s\n", si->strtab + si->symtab[sym].st_name);
			if (relocSym(si->strtab + si->symtab[sym].st_name, si->base, rel->r_offset) < 0)
			{
				if ((si->symtab[sym].st_info >> 4) != STB_WEAK)
				{
					LDBG("cannot relocate rel %s\n",
						si->strtab + si->symtab[sym].st_name);
					return -1;
				}
			}
		}
	}
	rel = si->plt_rel;
	for (i = 0; i < si->plt_rel_count; i++, rel++)
	{
		unsigned sym = ELF32_R_SYM(rel->r_info);
		//
		if (sym != 0)
		{
			LDBG("plt_rel %s\n", si->strtab + si->symtab[sym].st_name);
			if (relocSym(si->strtab + si->symtab[sym].st_name, si->base, rel->r_offset) < 0)
			{
				if ((si->symtab[sym].st_info >> 4) != STB_WEAK)
				{
					LDBG("cannot relocate plt_rel %s\n", 
						si->strtab + si->symtab[sym].st_name);
					return -1;
				}
			}
		}
	}
	return 0;
}

/*
* find neededSym addr
* 查询内存加载的so symbol
*/
unsigned loader::_findSym(soinfo *si, const char* name)
{
	unsigned i, hashval;
	Elf32_Sym *symtab = si->symtab;
	const char *strtab = si->strtab;
	unsigned nbucket = si->nbucket;
	unsigned *bucket = si->bucket;
	unsigned *chain = si->chain;

	hashval = _elfhash(name);
	for (i = bucket[hashval % nbucket]; i != 0; i = chain[i])
	{
		if (symtab[i].st_shndx != 0)
		{
			if (strcmp(strtab + symtab[i].st_name, name) == 0)
			{
				return symtab[i].st_value;  //offset
			}
		}
	}
	return 0;
}

/*
* 获取内存加载的so symAddr
*/
void loader::LL_getMySymAddr(soinfo *si)
{
	if (si != NULL)
	{
		unsigned i;
		Elf32_Sym *symtab = si->symtab;
		const char *strtab = si->strtab;
		unsigned nchain = si->nchain;
		
		for (int i = 0; i < si->nchain; i++)
		{
			stFunction stf;
			
			LDBG("symbol:[%s]Addr:[%p] cal_offset:[%p]\n", 
				symtab[i].st_name + strtab, 
				si->base + symtab[i].st_value, 
				symtab[i].st_value);
			//
			strncpy(stf.name, symtab[i].st_name + strtab, sizeof(stf.name));
			
			stf.addr = si->base + symtab[i].st_value;
			
			stf.offset = symtab[i].st_value;
		}
	}
}


void loader::_call_array(unsigned *ctor, int count, int reverse)
{
	int n, inc = 1;
	if (reverse) 
	{
		ctor += (count - 1);
		inc = -1;
	}
	for (n = count; n > 0; n--) 
	{
		void(*func)() = (void(*)()) *ctor;
		ctor += inc;
		if (((int)func == 0) || ((int)func == -1)) continue;
		LDBG("func_arry addr:[%p]", func);
		func();
	}
}

/*
* global data init 
* global static STL var init
*/
void loader::callConstructors(soinfo *si)
{
	if (si->flags & FLAG_EXE)
	{
		_call_array(si->preinit_array, si->preinit_array_count, 0);
	}
	else 
	{
		if (si->preinit_array) 
		{
			LDBG("%5d Shared library '%s' has a preinit_array table @ 0x%08x."
				" This is INVALID\n", getpid(), si->name,
				(unsigned)si->preinit_array);
		}
	}
	if (si->init_func) 
	{
		si->init_func();
	}
	if (si->init_array) 
	{
		_call_array(si->init_array, si->init_array_count, 0);
	}
}

/*
* 调用析构
*/
void loader::callDestructors(soinfo *si)
{
	if (si->fini_array)
	{
		_call_array(si->fini_array, si->fini_array_count, 1);
	}
	if (si->fini_func)
	{
		si->fini_func();
	}
}

/*
* global data reloc
*/
int loader::relocLibrary(soinfo *si, Elf32_Rel *rel, unsigned count)
{
	unsigned i;
	Elf32_Sym *s = NULL;

	for (i = 0; i < count; i++, rel++)
	{
		unsigned type = ELF32_R_TYPE(rel->r_info);
		unsigned reloc = (unsigned)(rel->r_offset + si->base);
		unsigned sym_addr = 0;

		switch (type)
		{
		case R_ARM_JUMP_SLOT:
			*((unsigned*)reloc) = sym_addr;
			break;
		case R_ARM_GLOB_DAT:
			*((unsigned*)reloc) = sym_addr;
			break;
		case R_ARM_ABS32:
			*((unsigned*)reloc) += sym_addr;
			break;
		case R_ARM_REL32:
			*((unsigned*)reloc) += sym_addr - rel->r_offset;
			break;
		case R_ARM_RELATIVE:
			*((unsigned*)reloc) += si->base;
			break;
		case R_ARM_COPY:
			memcpy((void*)reloc, (void*)sym_addr, s->st_size);
			break;
		default:
			return -1;
		}
	}
	return 0;
}

/*
* my dlopen wrap
*/
soinfo* loader::LL_dlopen(char *path)
{
	m_soCount = 0;

	if (path==NULL)
	{
		return NULL;
	}
	soinfo *si = NULL;

	si = loadLibrary(path);

	if (si == NULL)
	{
		LDBG("loadLibrary is failed\n");
		return NULL;
	}
	if (relocLibrary(si, si->rel, si->rel_count) < 0)
	{
		LDBG("relocLibrary is failed\n");
		return NULL;
	}
	if (loadDependedLibray(si) < 0)
	{
		LDBG("loadDependedLibray is failed\n");
		return NULL;
	}
	if (doDependeLibSymReloc(si) < 0)
	{
		LDBG("LibSymReloc is errrrr[so_name:%s]\n",
			si->name);
		return NULL;
	}

	si->flags |= FLAG_EXE;

	callConstructors(si); //init

	return si;
}

/*
* with buffer
*/
soinfo* loader::LL_dlopenwitBuffer(const char *selfname, unsigned char* buffer)
{
	m_soCount = 0;

	if (selfname == NULL)
	{
		return NULL;
	}
	soinfo *si = NULL;

	si = loadLibrarywithBuffer(selfname, buffer);
	if (si == NULL)
		return NULL;
	if (relocLibrary(si, si->rel, si->rel_count) < 0)
	{
		LDBG("relocLibrary is failed\n");
		return NULL;
	}
	if (loadDependedLibray(si) < 0)
		return NULL;
	if (doDependeLibSymReloc(si) < 0)
	{
		LDBG("LibSymReloc is errrrr[so_name:%s]\n",
			si->name);
		return NULL;
	}

	si->flags |= FLAG_EXE;

	callConstructors(si);
	
	return si;
}

/*
* my dlsym wrap
*/
unsigned int loader::LL_dlsym(soinfo *si, char *func_name)
{
	if (si == NULL)
	{
		return 0;
	}

	unsigned int func_addr = 0;
	unsigned int func_addr_offset = 0;

	func_addr_offset = _findSym(si, func_name);
	if (!func_addr_offset)
	{
		LDBG("LL_dlsym:search so_name[%s]cannot find sym %s\n", si->name,func_name);
		return 0;
	}

	func_addr = si->base + func_addr_offset;

	LDBG("loadso:[%s]so_base:[%p]func_name:[%s]func_addr:[%p] offset:[%p]\n",
		si->name, si->base, func_name, func_addr, func_addr_offset);
	
	return func_addr;
}


int loader::LL_dlcolse(soinfo *si)
{
	if (si!=NULL)
	{
		callDestructors(si);   /*调用析构函数*/

		if (mprotect((void *)si->base, si->size, PROT_READ | PROT_WRITE) == -1)
		{
			return -1;
		}

		munmap((void *)si->base, si->size);
	}
	return 0;
}










