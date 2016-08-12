#include "utils.h"

utils::utils()
{
}

utils::~utils()
{
}


char* utils::_getEnv(const char* var_name)
{
	return getenv(var_name);
}

char* utils::_getCurDir(char *buffer, int size)/*apk ÎÞÐ§ */
{
	return getcwd(buffer, size);
}

bool utils::_pathExists(const char* path)
{
	struct stat st;
	if ((stat(path, &st)) < 0)
		return false;
	return S_ISREG(st.st_mode) || S_ISDIR(st.st_mode);
}

bool utils::_pathIsFile(const char* path)
{
	struct stat st;
	if ((stat(path, &st)) < 0)
		return false;
	return S_ISREG(st.st_mode);
}

// Return the base name from a file path. Important: this is a pointer
// into the original string.
// static
const char*utils::_getBaseNamePtr(const char* path)
{
	const char* p = strrchr(path, '/');
	if (!p)
		return path;
	else
		return p + 1;
}


int utils::_traveDir(char* path, char filePath[][MAX_PATH], int pathSize, int depth)
{
	int dirCount = 0;
	DIR *d;
	struct dirent *file;
	struct stat sb;
	if (!(d = opendir(path)))
	{
		return -1;
	}
	while ((file = readdir(d)) != NULL && dirCount < pathSize)
	{
		if (!strncmp(file->d_name, ".", 1))
			continue;
		if (!strstr(file->d_name, ".so")) //is library
			continue;
		snprintf(filePath[dirCount++], MAX_PATH, "%s/%s",
			path, file->d_name);
		if (stat(file->d_name, &sb) >= 0 &&
			S_ISDIR(sb.st_mode) &&
			depth <= 1)
		{
			_traveDir(file->d_name, filePath, pathSize, depth + 1);
		}
	}
	closedir(d);
	return dirCount;
}


/**
* get_module_base
*/
uint32_t utils:: _getModuleBase(pid_t pid, const char *module_name) 
{
	FILE *fp = NULL;
	char *pch = NULL;
	char filename[32];
	char line[512];
	uint32_t addr = 0;
	if (pid < 0)
		snprintf(filename, sizeof(filename), "/proc/self/maps");
	else
		snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
	if ((fp = fopen(filename, "r")) == NULL) 
	{
		printf("[!]open %s failed!\n", filename);
		return 0;
	}
	while (fgets(line, sizeof(line), fp)) 
	{
		if (strstr(line, module_name))
		{
			pch = strtok(line, "-");
			addr = strtoul(pch, NULL, 16);
			break;
		}
	}
	fclose(fp);
	return addr;
}

void utils::_getselfProcName(char *procName, int nsize)
{
	FILE *fp = NULL;
	char path[128] = { 0 };
	snprintf(path, sizeof(path), "/proc/%d/cmdline", getpid());
	fp = fopen(path, "r");
	if (fp)
	{
		fgets(procName, nsize, fp);
	}
	fclose(fp);
	return;
}

void utils::_lookupMapsWithAddr(char *info,int nsize, unsigned addr,unsigned getOffset)
{
	//FILE *fp = NULL;
	//char pch_start[8] = {0};
	//char pch_end[8] = {0};
	//char path[128] = {0};
	//char line[512] = {0};
	//unsigned startaddr = 0;
	//unsigned endaddr = 0;
	//snprintf(path, sizeof(path), "/proc/%d/maps", getpid());
	//if ((fp = fopen(path, "r")) == NULL)
	//{
	//	printf("[!]maps open %s failed!\n", path);
	//	return ;
	//}
	//while (fgets(line, sizeof(line), fp))
	//{
	//	sscanf(line, "%[^-] % [^ ]", pch_start, pch_end);
	//	startaddr = strtoul(pch_start, NULL, 16);
	//	endaddr = strtoul(pch_end, NULL, 16);
	//	if ((int)(addr - startaddr)>0 && (int)(addr - endaddr)<0)
	//	{
	//		getOffset = addr - startaddr;//¼ÆËãÆ«ÒÆ
	//		strncpy(info, line, nsize);
	//		break;
	//	}
	//}
	//fclose(fp);
}

