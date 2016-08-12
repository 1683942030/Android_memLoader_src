/*
*****************************************************************************
* File        : LL.cpp
* Description : mem_loader 内存加载,劫持
* Creation    : 2015.8.5
* Author      : 青青我来啦啦啦
* History     :	
*
******************************************************************************
**/

#include "LL.h"
#include <jni.h>
#include "loader/utils.h"
//#include "hookAnti.h"


#define SELFNAME "LLHACK"
#define NAMESIZE 256

loader ld;

#define  SHELLMOD 

#ifdef SHELLMOD 

extern int _binary_libndk_load_so_end;
extern int _binary_libndk_load_so_start;

typedef unsigned(*PFUN_OLDDLSYM)(void* handle, char* symName);
typedef void(*PFUNCHOOKSTART)(char *lpApkPath, char *lpSoPath);

PFUN_OLDDLSYM  old_dlsym;

void *g_memSiHandle = NULL;
void *g_loaderHandler = NULL;

__attribute__((visibility("hidden"))) unsigned Ex_dlsym_shell(soinfo *si, char *func_name)
{
	soinfo *loadedSi = NULL;

	unsigned lr;

	_GETFUNCBACKADDR(lr);

	loadedSi = (soinfo*)g_memSiHandle;

	/*si->name 安卓版本不同,处于silist结构偏移不同,只能在特点rom中测试中用*/
	//LDBG("[Catch!!!Back_Addr:%p] function: [%s] is dlsym [srcsiAddr:%p][siname:%s]!!!!!!!!\n", lr,func_name,(void*)si,si->name);
	
	LDBG("[Catch!!!Back_Addr:%p] function: [%s] is dlsym [srcsiAddr:%p]!!!!!!!!\n", lr, func_name, (void*)si);

	unsigned symAddr = old_dlsym(si, func_name);

	if (!symAddr) 
	{
		LDBG("[search _MemLoader]function:[%s]isdlsym [g_loaderHandler:%p<==>srcsiAddr:%p][g_memSiHandle:%p]!!!!!!!!\n", 
			func_name, g_loaderHandler, (void*)si, (void*)loadedSi);
		if (g_loaderHandler == (void*)si || g_loaderHandler == 0)
		{
			symAddr = ld.LL_dlsym(loadedSi, func_name);
			LDBG("[search _MemLoader] is find!!!!:function:[%s] [symAddr]:[%p]\n", func_name, symAddr);
		}
		else
		{
			LDBG("[search _MemLoader] NOT find!!!!:function:[%s] [symAddr]:[%p]\n", func_name, symAddr);
		}
	}
	return symAddr;
}

__attribute__((visibility("hidden"))) void initLoader()
{

	/*
	* 测试劫持预加载!!!!!!!!!
	*/
	/*
	char szPath[] = "/data/local/tmp/libinjso.so";
	char szFuntionName[] = "HookStart";
	void* handle = dlopen(szPath, RTLD_NOW);
	if (handle)
	{
	PFUNCHOOKSTART pstart = (PFUNCHOOKSTART)dlsym(handle, szFuntionName);

	pstart("/data/local/tmp/xxleiting.apk", "/data/local/tmp/libxxleiting.so");
	}
	*/

	char LoaderName[NAMESIZE] = "libndk_load.so";

	/*
	* 测试从资源buffer加载动态库
	* 测试用的buffer 从静态data段映射进来,或者网络下发
	*/
#ifdef _LOADWITHBUFFER
	unsigned char * dataStart = (unsigned char *)& _binary_libndk_load_so_start;
	unsigned char * dataEnd = (unsigned char *)& _binary_libndk_load_so_end;
	int nSize = 0;
	unsigned char *buffer = NULL;
	nSize = dataEnd - dataStart;
	if (nSize > 0)
	{
		g_memSiHandle = (void*)Ex_dlopenwitBuffer(buffer, nSize);
	}
#else
	/*
	* 测试从文件加载动态库
	* 将测试加载的动态库放在dataPath路径下
	*/
	char dataPath[MAX_PATH] = { 0 };
	snprintf(dataPath, sizeof(dataPath), "/data/local/tmp/%s", LoaderName);
	g_memSiHandle = (void*)Ex_dlopen(dataPath);

#endif

	/*
	*  print symbol info
	*/

	ld.LL_getMySymAddr((soinfo*)g_memSiHandle);

	/*
	* 获取自身全局句柄
	*/
	char procName[NAMESIZE] = { 0 };
	char loaderPath[MAX_PATH] = { 0 };
	utils::_getselfProcName(procName, sizeof(procName));
	if (procName[0] != 0)
	{
		snprintf(loaderPath, sizeof(loaderPath), "/data/data/%s/lib/%s", procName, LoaderName);
		LDBG("loaderPath:[%s]\n", loaderPath);
	}

	g_loaderHandler = dlopen(loaderPath, RTLD_LAZY);

	LDBG("[path:[%s]!!!!loader_handler:%p\n]", loaderPath, g_loaderHandler);

	/*
	* hook linker dlsym
	* 外部函数调用流程转入myShell
	*/
	MSHookFunction((void*)dlsym, (void*)Ex_dlsym_shell, (void**)&old_dlsym);
}

__attribute__((constructor(101))) void initShell()
{
	/*
	* fuck_anti
	*/
	//fuck_anti();
}


/*
__attribute__((destructor(101))) void destuctShell()
{
	LDBG("[dl_close_Loader]!!!!!\n");
	MSHookFunction((void*)Ex_dlsym_shell, (void*)old_dlsym, (void**)&old_dlsym);
	Ex_dlclose((soinfo*)g_memSiHandle);
}
*/
#endif 




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


/*
* export jni_onload 
*/

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved)
{
	fuckin();
	jint(*jniOnLoad)(JavaVM*, void*);
	jniOnLoad = (jint(*)(JavaVM*, void*))(ld.LL_dlsym((soinfo*)g_memSiHandle, "JNI_OnLoad"));
	if (jniOnLoad != NULL)
	{
		return jniOnLoad(vm, reserved);
	}
	return 0;
}

#ifdef __cplusplus  
}
#endif 







