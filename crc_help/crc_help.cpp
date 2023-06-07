
#include <iostream>
#include "crc_util.h"

int main()
{
	PVOID base = NULL;
	HANDLE access = NULL;

	auto proc_id = process_help::get_process_id(L"crc_vmp.exe");

	if (proc_id)
	{ 
		base = process_help::get_module_address(proc_id, L"crc_vmp.exe");

		access = OpenProcess(PROCESS_ALL_ACCESS, NULL, proc_id); 

		if (!access)
		{
			printf("Bad open handle!\n");
			getchar();
			return NULL;
		} 
		if (proc_crc::copy_secthion(access, base))
		{
			printf("Good!\n");
		}
		CloseHandle(access);
			
	}
	getchar();

	return NULL;
}
 