#include "common.h"

void enumerate_loaded_drivers() {
    DWORD dwResult = ERROR_SUCCESS;
	SC_HANDLE scm_handle = NULL;
	unsigned long bytes_needed = 0;
	unsigned long services_returned = 0;
	PBYTE services = NULL;
	PWCHAR registry_path = NULL;
	HKEY key_handle = NULL;
	unsigned long length = MAX_PATH * 2;
	PWCHAR driver_path = NULL;


	// Allocate memory for registry path buffer.
	registry_path = (PWCHAR)intAlloc(MAX_PATH * 2);
	if (NULL == registry_path)
	{
	    INTALLOC_E;
		return;
	}

	if (registry_path) intFree(registry_path);
}

void coffee(char** argv, int argc, WCHAR** dispatch) {
    g_dispatch = dispatch;
    enumerate_loaded_drivers();
}
