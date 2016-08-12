#ifndef _UTILS_H
#define _UTILS_H

#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <stdio.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/inotify.h>

#define  MAX_PATH 512

class utils
{
public:
	utils();
	~utils();
	static char* _getEnv(const char* var_name);
	static char*  _getCurDir(char *buffer, int size);
	static bool  _pathExists(const char* path);
	static bool  _pathIsFile(const char* path);
	static const char* _getBaseNamePtr(const char* path);
	static uint32_t _getModuleBase(pid_t pid, const char *module_name); /*pid == -1  getselfbase*/
	static int _traveDir(char* path, char filePath[][MAX_PATH], int pathSize, int depth);
	static void _getselfProcName(char *procName,int nsize);
	static void _lookupMapsWithAddr(char *info, int nsize, unsigned addr, unsigned getOffset);
private:

};


#endif