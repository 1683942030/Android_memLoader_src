#ifndef _LL_H
#define _LL_H

#include "loader/Loader.h"
#include <unistd.h>
#include <dlfcn.h>
#include "Substrate/SubstrateHook.h"

#ifdef __cplusplus
extern "C" {
#endif

soinfo*  Ex_dlopen(char *path);
unsigned Ex_dlsym(soinfo *si, char *func_name);
int		 Ex_dlclose(soinfo *si);
soinfo* Ex_dlopenwitBuffer(unsigned char*buffer, int nSize);
void	 initShell();
void	 destuctShell();
unsigned Ex_dlsym_shell(soinfo *si, char *func_name);

#ifdef __cplusplus  
}
#endif

struct symTab
{
	char symName[256];
	uint32_t symAddr;
};

#endif
