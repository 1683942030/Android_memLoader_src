/*
*****************************************************************************
* File        : LL.cpp
* Description : mem_loader 内存加载
* Creation    : 2015.8.5
* Author      : ll-hack
* History     :	
*
******************************************************************************
**/

#include "LL.h"
#include <jni.h>
#include "loader/utils.h"
//#include "hookAnti.h"

#define NAMESIZE 256

loader ld;
/*
* export func as self linker
*/
#ifdef __cplusplus
extern "C" {
#endif

__attribute__((visibility("hidden"))) soinfo* Ex_dlopen(char *path)
{
	return ld.LL_dlopen(path);
}

__attribute__((visibility("hidden"))) soinfo* Ex_dlopenwitBuffer(unsigned char*buffer,int nSize)
{
	
	soinfo* siRet = NULL;

	if (nSize>0)
	{
		unsigned char* alignBuffer = (unsigned char*)mmap(NULL, nSize, PROT_READ | PROT_EXEC | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (alignBuffer != NULL)
		{
			memcpy(alignBuffer, (const void*)buffer, nSize);

			ld.LL_dlopenwitBuffer(SELFNAME, alignBuffer);
			
			munmap(alignBuffer, nSize);
		}	
	}
	return siRet;
}

__attribute__((visibility("hidden"))) unsigned Ex_dlsym(soinfo *si, char *func_name)
{
	return  ld.LL_dlsym(si, func_name);
}


__attribute__((visibility("hidden"))) int Ex_dlclose(soinfo *si)
{	
	
	return ld.LL_dlcolse(si);
}

__attribute__((visibility("default"))) void fuckin()
{
	initLoader();
}

typedef int(*MAIN)(int argc, char**argv);
int main(int argc, char**argv)
{
	MAIN pmain;
	soinfo *si=Ex_dlopen(argv[1]);
	unsigned pp = Ex_dlsym(si, "main");
	pmain = (MAIN)pp;
	pmain(argc, argv);
	return 0;
}

#ifdef __cplusplus  
}
#endif 







