#ifndef DEF_NTAPI
#define DEF_NTAPI 1

#include "Struct.h"
 

NTSTATUS
NTAPI
NtQuerySystemInformation
(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT PVOID               SystemInformation,
    IN ULONG                SystemInformationLength,
    OUT PULONG              ReturnLength OPTIONAL
);
 


#endif // !DEF_NTAPI
