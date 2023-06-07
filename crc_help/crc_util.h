#ifndef CRC_PROCESS_UTIL
#define CRC_PROCESS_UTIL 1 
#include "process_util.h" 

namespace proc_crc
{
	namespace crt_wrapper
	{
		 
		INLINE auto malloc(size_t size) -> PVOID
		{
			return VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_READWRITE);
		}

		INLINE auto free(PVOID ptr) -> VOID
		{
			if (ptr)
				VirtualFree(ptr, NULL, MEM_RELEASE);
		}
		 
	}

	auto copy_secthion(HANDLE access,PVOID address_mod) -> bool
	{
		 
		WORD number_secthion = offsetof(IMAGE_NT_HEADERS, FileHeader) + offsetof(IMAGE_FILE_HEADER, NumberOfSections);
		WORD opthion_head = offsetof(IMAGE_NT_HEADERS, FileHeader) + offsetof(IMAGE_FILE_HEADER, SizeOfOptionalHeader);
		DWORD old_prot = NULL;
		DWORD virtual_size = NULL;
		DWORD virtual_address = NULL;
		LONG nt_header_offset = NULL ;

		PVOID headers = { NULL }; 
		PVOID sections = { NULL };
		PVOID sec_2 = { NULL };
		PVOID allocated_copy = { NULL };
		PVOID coped_mem = { NULL };
		MEMORY_BASIC_INFORMATION mbi = { NULL };

		if(!ReadProcessMemory(access, reinterpret_cast<CHAR*>(address_mod) + offsetof(IMAGE_DOS_HEADER, e_lfanew),&nt_header_offset,sizeof(nt_header_offset),NULL))
			return FALSE; 

		headers = reinterpret_cast<CHAR*>(address_mod) + nt_header_offset;
	 
		if (!ReadProcessMemory(access, reinterpret_cast<CHAR*>(headers) + opthion_head , &opthion_head, sizeof(opthion_head), NULL))
			return FALSE;

		if(!ReadProcessMemory(access, reinterpret_cast<CHAR*>(headers) + number_secthion, &number_secthion, sizeof(number_secthion), NULL))
			return FALSE;
		 
		sections = reinterpret_cast<CHAR*>(headers) + opthion_head + FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader);
		
		sec_2 = sections; 

		allocated_copy = VirtualAllocEx(access, NULL, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

		if (!allocated_copy)
		{
			return FALSE;
		}

		printf("Patch shell ->\t%p\n", allocated_copy);

		for (WORD i = NULL; i < number_secthion; i++)
		{ 
			if(!ReadProcessMemory(access, reinterpret_cast<CHAR*>(sec_2) + offsetof(IMAGE_SECTION_HEADER, VirtualAddress), &virtual_address, sizeof(virtual_address), NULL))
				return FALSE;  

			if (!ReadProcessMemory(access, reinterpret_cast<CHAR*>(sec_2) + offsetof(IMAGE_SECTION_HEADER, Misc), &virtual_size, sizeof(virtual_size), NULL))
				return FALSE;

			//page rounding(actually this code is not needed)
			virtual_size += (0x1000 - virtual_size % 0x1000);

			memset(&mbi, NULL, sizeof(mbi));
			if (!VirtualQueryEx(access, reinterpret_cast<CHAR*>(address_mod) + virtual_address, &mbi, sizeof(mbi)))
				return FALSE; 

			allocated_copy = VirtualAllocEx(access, NULL, virtual_size, MEM_COMMIT, PAGE_READWRITE);
			if (!allocated_copy)
				return FALSE; 
			coped_mem = crt_wrapper::malloc(virtual_size);
			if (!coped_mem)
				return FALSE;
			 
			if (mbi.Protect & PAGE_READONLY || mbi.Protect & PAGE_READWRITE ||
				mbi.Protect & PAGE_EXECUTE_READ || mbi.Protect & PAGE_EXECUTE_READWRITE
				)
			{ 
				if (!ReadProcessMemory(access, reinterpret_cast<CHAR*>(address_mod) + virtual_address, coped_mem, virtual_size, NULL))
					return FALSE; 
				if (!WriteProcessMemory(access, allocated_copy, coped_mem, virtual_size, NULL))
					return FALSE;
				if (!VirtualProtectEx(access, allocated_copy, virtual_size, mbi.Protect, &old_prot))
					return FALSE;
				printf("Address ->\t%p\t to %p\n", reinterpret_cast<CHAR*>(address_mod) + virtual_address, allocated_copy);
			}
			crt_wrapper::free(coped_mem);
			coped_mem = NULL;

			sec_2 = reinterpret_cast<CHAR*>(sec_2) + sizeof(IMAGE_SECTION_HEADER);
		} 
		 
		return TRUE;
		 
	}


 

}
#endif // !CRC_PROCESS_UTIL
