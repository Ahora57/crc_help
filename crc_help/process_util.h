#ifndef PROCESS_UTIL
#define PROCESS_UTIL 1 

#include "Struct.h"
#include "NtApiDef.h"
#include "lazy_importer.hpp"

 

namespace process_help
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

		INLINE auto wtolower(INT c) -> INT
		{
			if (c >= L'A' && c <= L'Z') return c - L'A' + L'a';
			return c;
		}

		INLINE auto wstricmp(CONST WCHAR* cs, CONST WCHAR* ct) -> INT
		{
			if (cs && ct)
			{
				while (wtolower(*cs) == wtolower(*ct))
				{
					if (*cs == NULL && *ct == NULL) return NULL;
					if (*cs == NULL || *ct == NULL) break;
					cs++;
					ct++;
				}
				return wtolower(*cs) - wtolower(*ct);
			}
			return -1;
		}

	}

	 

	auto get_process_id(CONST WCHAR* process_name) -> uint32_t
	{
		ULONG ret_lenght = NULL;
		uint32_t process_id = NULL;
		NTSTATUS nt_status = STATUS_UNSUCCESSFUL;
		PVOID buffer = NULL;
		PSYSTEM_PROCESS_INFORMATION process_info = NULL;


		if (!nt_query_system_information)
		{
			nt_query_system_information = reinterpret_cast<PVOID>(LI_FN(NtQuerySystemInformation).nt_cached());
		}

		nt_status = reinterpret_cast<decltype(&NtQuerySystemInformation)>(nt_query_system_information)(SystemProcessInformation, &ret_lenght, ret_lenght, &ret_lenght);

		while (nt_status == STATUS_INFO_LENGTH_MISMATCH)
		{
			if (buffer != NULL)
				crt_wrapper::free(buffer);

			buffer = crt_wrapper::malloc(ret_lenght);
			nt_status = reinterpret_cast<decltype(&NtQuerySystemInformation)>(nt_query_system_information)(SystemProcessInformation, buffer, ret_lenght, &ret_lenght);
		}

		if (!NT_SUCCESS(nt_status))
		{
			crt_wrapper::free(buffer);
			return NULL;
		}
		
		process_info = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(buffer);
		while (process_info->NextEntryOffset)
		{

			if (crt_wrapper::wstricmp(process_info->ImageName.Buffer, process_name) == NULL)
			{
				process_id = reinterpret_cast<uint32_t>(process_info->UniqueProcessId);
				break;
			}
			process_info = (PSYSTEM_PROCESS_INFORMATION)((LPBYTE)process_info + process_info->NextEntryOffset);
		}
		crt_wrapper::free(buffer);
		return process_id;

	}

	auto get_module_address(uint32_t proc_id, CONST WCHAR* modName) -> PVOID
	{
		PVOID  module_address = NULL;
		HANDLE snap_mod = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, proc_id);

		if (snap_mod != INVALID_HANDLE_VALUE)
		{
			MODULEENTRY32W mod_entry = { NULL };
			mod_entry.dwSize = sizeof(mod_entry);
			if (Module32FirstW(snap_mod, &mod_entry))
			{
				do
				{
					if (crt_wrapper::wstricmp(mod_entry.szModule, modName) == NULL)
					{
						module_address = mod_entry.modBaseAddr;
						break;
					}
				} while (Module32NextW(snap_mod, &mod_entry));
			}
		}
		CloseHandle(snap_mod);
		return module_address;
	}

	 
}


#endif // !PROCESS_UTIL
