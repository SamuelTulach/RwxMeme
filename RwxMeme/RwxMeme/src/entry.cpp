#include "general.h"

#define SIGNED_RWX_DLL_NAME E("cpprest.dll")

void MapDll(HMODULE rwxDll, DWORD tid, uint64_t targetSectionBase, DWORD targetSectionSize, PIMAGE_DOS_HEADER dosHeader, PIMAGE_NT_HEADERS64 ntHeaders)
{
	ProtectUltra();
	const int garbageSize = 0x1000; // has to be aligned
	console::Info(E("Copying random garbage"));
	memory_helper::WriteMemory(targetSectionBase, &NtQuerySystemTime, garbageSize);
	targetSectionBase += garbageSize;
	targetSectionSize -= garbageSize;
	console::Success(E("Garbage copied"));

	if (targetSectionSize < ntHeaders->OptionalHeader.SizeOfImage)
	{
		console::Error(E("Not enough space for dll"));
		global::ExitLoop();
	}

	console::Info(E("Allocating local memory"));
	void* localImageBase = malloc(ntHeaders->OptionalHeader.SizeOfImage);
	memset(localImageBase, 0, ntHeaders->OptionalHeader.SizeOfImage);
	if (!localImageBase)
	{
		console::Error(E("Failed to allocate local memory"));
		global::ExitLoop();
	}

	console::Success(E("Local image base: 0x%p"), localImageBase);

	console::Info(E("Copying headers"));
	memcpy(localImageBase, dosHeader, ntHeaders->OptionalHeader.SizeOfHeaders);
	console::Success(E("Headers copied"));

	console::Info(E("Copying sections"));
	const PIMAGE_SECTION_HEADER currentImageSection = IMAGE_FIRST_SECTION(ntHeaders);
	for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i)
	{
		console::Debug(E("Section: 0x%p (%u)"), currentImageSection[i].VirtualAddress, currentImageSection[i].SizeOfRawData);
		void* localSection = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(localImageBase) + currentImageSection[i].VirtualAddress);
		memcpy(localSection, reinterpret_cast<void*>(reinterpret_cast<uint64_t>(dosHeader) + currentImageSection[i].PointerToRawData), currentImageSection[i].SizeOfRawData);
	}

	console::Success(E("Sections copied"));

	console::Info(E("Resolving relocations"));
	executable::VecRelocs relocations = executable::GetRelocs(localImageBase);
	uint64_t delta = targetSectionBase - ntHeaders->OptionalHeader.ImageBase;
	for (const auto& currentReloc : relocations)
	{
		for (auto i = 0u; i < currentReloc.count; ++i)
		{
			const uint16_t type = currentReloc.item[i] >> 12;
			const uint16_t offset = currentReloc.item[i] & 0xFFF;

			if (type == IMAGE_REL_BASED_DIR64)
			{
				//console::Debug(E("Offset: %x"), static_cast<uint32_t>(offset));
				*reinterpret_cast<uint64_t*>(currentReloc.address + offset) += delta;
			}
		}
	}

	console::Success(E("Relocations resolved"));

	console::Info(E("Resolving imports"));
	executable::VecImports imports = executable::GetImports(localImageBase);
	for (const auto& currentImport : imports)
	{
		const wchar_t* moduleName = utils::GetWidechar(currentImport.module_name.c_str());
		ULONG64 moduleAddress = memory_helper::GetModuleAddress(moduleName);
		if (!moduleAddress)
		{
			console::Error(E("Module %s not found"), currentImport.module_name.c_str());
			global::ExitLoop();
		}

		HMODULE targetModule = LoadLibraryExA(currentImport.module_name.c_str(), nullptr, DONT_RESOLVE_DLL_REFERENCES);
		if (!targetModule)
		{
			console::Error(E("Fail to load %s locally"), currentImport.module_name.c_str());
			global::ExitLoop();
		}

		for (auto& currentFunctionData : currentImport.function_datas)
		{
			FARPROC functionAddressLocal = GetProcAddress(targetModule, currentFunctionData.name.c_str());
			if (!functionAddressLocal)
			{
				console::Error(E("Failed to resolve %s locally"), currentFunctionData.name.c_str());
				global::ExitLoop();
			}

			uint64_t functionAddress = moduleAddress + (reinterpret_cast<uint64_t>(functionAddressLocal) - reinterpret_cast<uint64_t>(targetModule));
			if (!functionAddress)
			{
				console::Error(E("Failed to resolve %s"), currentFunctionData.name.c_str());
				global::ExitLoop();
			}

			*currentFunctionData.address = functionAddress;
			console::Debug(E("Module: %s name: %s address: 0x%p"), currentImport.module_name.c_str(), currentFunctionData.name.c_str(), functionAddress);
		}
	}

	console::Success(E("Imports resolved"));

	// TODO: clear headers (cache size first idiot)

	console::Info(E("Copying image"));
	memory_helper::WriteMemory(targetSectionBase, localImageBase, ntHeaders->OptionalHeader.SizeOfImage);
	console::Success(E("Image copied"));

	console::Info(E("Verifying image integrity"));
	void* localCopy = malloc(ntHeaders->OptionalHeader.SizeOfImage);
	memory_helper::ReadMemory(targetSectionBase, localCopy, ntHeaders->OptionalHeader.SizeOfImage);
	if (memcmp(localImageBase, localCopy, ntHeaders->OptionalHeader.SizeOfImage) != 0)
	{
		console::Error(E("Failed to verify image"));
		global::ExitLoop();
	}

	console::Info(E("Wiping headers"));
	memory_helper::WriteMemory(targetSectionBase, &NtQuerySystemTime, ntHeaders->OptionalHeader.SizeOfHeaders);
	console::Success(E("Headers wiped"));

	console::Success(E("Image integrity verified"));

	console::Info(E("Copying shellcode"));
	const uint64_t addressOfEntryPoint = targetSectionBase + ntHeaders->OptionalHeader.AddressOfEntryPoint;
	/*
		lea rax, [rip]              # save next instruction address in rax
		mov rcx, [rax+100]          # save value of byte check
		cmp rcx, 0                  # check if byte is zero
		je  execute_dll             # if it is then call dll entry
		ret                         # if not then return
		execute_dll:
		mov rcx, 1                  # set byte to disable double execution
		mov [rax+100], rcx          # move it to the correct offset
		mov rdx, 0x1                # reason for call
		movabs rax,0xdeadfeeddead   # entry point address
		jmp    rax                  # let the fun begin
	 */
	BYTE shellcode[] = 
	{
		0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x48, 0x64, 0x48, 0x83, 0xF9,
		0x00, 0x74, 0x01, 0xC3, 0x48, 0xC7, 0xC1, 0x01, 0x00, 0x00, 0x00, 0x48, 0x89, 0x48,
		0x64, 0x48, 0xC7, 0xC2, 0x01, 0x00, 0x00, 0x00, 0x48, 0xB8, 0xAD, 0xDE, 0xED, 0xFE,
		0xAD, 0xDE, 0x00, 0x00, 0xFF, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};
	*reinterpret_cast<uint64_t*>(&shellcode[38]) = addressOfEntryPoint;
	const uint64_t targetShellcodeAddress = targetSectionBase - garbageSize / 2;
	memory_helper::WriteMemory(targetShellcodeAddress, shellcode, sizeof(shellcode));
	console::Debug(E("Real entry: 0x%p"), addressOfEntryPoint);
	console::Debug(E("Shellcode: 0x%p"), targetShellcodeAddress);
	console::Success(E("Shellcode copied"));

	console::Info(E("Setting window hook"));
	HMODULE dummyModule = GetModuleHandleA(E("kernel32.dll"));
	if (!dummyModule)
	{
		console::Error(E("kernel32.dll not loaded (???)"));
		global::ExitLoop();
	}

	//HHOOK handle = SetWindowsHookExA(WH_GETMESSAGE, reinterpret_cast<HOOKPROC>(targetShellcodeAddress), dummyModule, tid);
	HHOOK handle = SetWindowsHookExA(WH_KEYBOARD, reinterpret_cast<HOOKPROC>(targetShellcodeAddress), dummyModule, tid);
	if (!handle)
	{
		console::Error(E("Failed to set window hook"));
		global::ExitLoop();
	}

	console::Success(E("Window hook set"));

	/*console::Info(E("Forcing hook call"));
	PostThreadMessageA(tid, WM_NULL, NULL, NULL);
	console::Success(E("Hook called"));*/

	//console::Info(E("Removing hook"));
	console::Info(E("Press any key to unhook"));
	getchar();
	BOOL unhook = UnhookWindowsHookEx(handle);
	if (!unhook)
	{
		console::Error(E("Failed to remove window hook"));
		global::ExitLoop();
	}

	console::Success(E("Hook removed"));

	console::Info(E("Cleaning console"));
	Sleep(1000);
	console::OverwriteClear();

	ProtectEnd();
}

int main(int argc, char* argv[])
{
	ProtectUltra();
	//console::Clear();
	//console::Init();
	console::Title();

	if (argc != 4)
	{
		console::Error(E("Use this.exe <ProcessName> <WindowTitle> <DllPath>"));
		global::ExitLoop();
	}

	const char* dllPath = argv[3];
	if (!std::filesystem::exists(dllPath))
	{
		console::Error(E("Invalid input dll path"));
		global::ExitLoop();
	}

	if (!std::filesystem::exists(SIGNED_RWX_DLL_NAME))
	{
		console::Error(E("Cannot find dll %s"), SIGNED_RWX_DLL_NAME);
		global::ExitLoop();
	}

	if (!magic::Run())
		global::ExitLoop();

	const wchar_t* targetProcess = utils::GetWidechar(argv[1]);
	memory_helper::WaitAndOpenProcess(targetProcess);

	console::Info(E("Waiting for process to initialize"));
	Sleep(10000);
	console::Success(E("Wait completed"));

	console::Info(E("Reading dll"));
	const wchar_t* dllPathWide = utils::GetWidechar(dllPath);
	std::vector<uint8_t> dllBuffer;
	if (!utils::ReadFileToMemory(dllPathWide, &dllBuffer))
	{
		console::Error(E("Failed to read dll file"));
		global::ExitLoop();
	}

	PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(dllBuffer.data());
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		console::Error(E("Invalid DOS header"));
		global::ExitLoop();
	}

	PIMAGE_NT_HEADERS64 ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS64>(reinterpret_cast<uint64_t>(dllBuffer.data()) + dosHeader->e_lfanew);
	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
	{
		console::Error(E("Invalid NT headers"));
		global::ExitLoop();
	}

	console::Success(E("Dll with size %u loaded"), ntHeaders->OptionalHeader.SizeOfImage);

	console::Info(E("Searching for target window"));
	const char* windowName = argv[2];
	HWND hwnd = FindWindowA(NULL, windowName);
	if (!hwnd)
	{
		console::Error(E("Window does not seem to exist"));
		global::ExitLoop();
	}

	console::Success(E("HWND: 0x%p"), hwnd);

	console::Info(E("Getting target thread"));
	DWORD pid = 0;
	DWORD tid = GetWindowThreadProcessId(hwnd, &pid);
	if (!tid)
	{
		console::Error(E("Failed to get thread id"));
		global::ExitLoop();
	}

	if (pid != memory_helper::targetPid)
	{
		console::Error(E("Window PID and process PID does not match"));
		global::ExitLoop();
	}

	console::Success(E("TID: %u"), tid);

	console::Info(E("Loading rwx dll"));
	HMODULE rwxDll = LoadLibraryExA(SIGNED_RWX_DLL_NAME, nullptr, DONT_RESOLVE_DLL_REFERENCES);
	if (!rwxDll)
	{
		console::Error(E("Failed to load rwx dll"));
		global::ExitLoop();
	}

	console::Success(E("HMODULE: 0x%p"), rwxDll);

	console::Info(E("Getting dummy callback address"));
	HMODULE kernel32Dll = GetModuleHandleA(E("kernel32.dll"));
	if (!kernel32Dll)
	{
		console::Error(E("kernel32.dll not loaded (???)"));
		global::ExitLoop();
	}

	HOOKPROC dummyFunction = (HOOKPROC)GetProcAddress(kernel32Dll, E("GetTickCount64"));
	if (!dummyFunction)
	{
		console::Error(E("Cannot find dummy export"));
		global::ExitLoop();
	}

	console::Success(E("Callback: 0x%p"), dummyFunction);

	console::Info(E("Setting window hook"));
	HHOOK handle = SetWindowsHookExA(WH_GETMESSAGE, dummyFunction, rwxDll, tid);
	if (!handle)
	{
		console::Error(E("Failed to set window hook"));
		global::ExitLoop();
	}

	console::Success(E("Window hook set"));

	console::Info(E("Forcing hook call"));
	PostThreadMessageA(tid, WM_NULL, NULL, NULL);
	Sleep(3000);
	console::Success(E("Hook called"));

	const wchar_t* rwxDllName = utils::GetWidechar(SIGNED_RWX_DLL_NAME);
	uint64_t rwxRemoteBase = memory_helper::GetModuleAddress(rwxDllName);
	if (!rwxRemoteBase)
	{
		console::Error(E("Module was not loaded"));
		global::ExitLoop();
	}

	console::Info(E("Getting rwx section"));
	IMAGE_DOS_HEADER remoteDosHeader = memory_helper::Read<IMAGE_DOS_HEADER>(rwxRemoteBase);
	const uint64_t remoteNtHeadersBase = rwxRemoteBase + remoteDosHeader.e_lfanew;
	IMAGE_NT_HEADERS64 remoteNtHeaders = memory_helper::Read<IMAGE_NT_HEADERS64>(remoteNtHeadersBase);
	uint64_t sectionAddress = remoteNtHeadersBase + FIELD_OFFSET(IMAGE_NT_HEADERS64, OptionalHeader) + remoteNtHeaders.FileHeader.SizeOfOptionalHeader;
	for (WORD i = 0; i < remoteNtHeaders.FileHeader.NumberOfSections; ++i)
	{
		IMAGE_SECTION_HEADER section = memory_helper::Read<IMAGE_SECTION_HEADER>(sectionAddress + sizeof(IMAGE_SECTION_HEADER) * i);

		bool executable = ((section.Characteristics & 0x20000000) == 0x20000000);
		bool readable = ((section.Characteristics & 0x40000000) == 0x40000000);
		bool writeable = ((section.Characteristics & 0x80000000) == 0x80000000);

		if (executable && readable && writeable)
		{
			uint64_t rwxSection = rwxRemoteBase + section.VirtualAddress;
			console::Success(E("Found rwx section at 0x%p"), rwxSection);
			MapDll(rwxDll, tid, rwxSection, section.Misc.VirtualSize, dosHeader, ntHeaders);
			global::ExitLoop();
			return 0;
		}
	}

	console::Error(E("Section not found"));

	global::ExitLoop();
	ProtectEnd();
	return 0;
}
