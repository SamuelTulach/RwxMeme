#include "../general.h"

std::wstring utils::GetFullTempPath()
{
	ProtectMutate();
	wchar_t temp_directory[MAX_PATH + 1] = { 0 };
	const uint32_t get_temp_path_ret = GetTempPathW(sizeof(temp_directory) / 2, temp_directory);
	if (!get_temp_path_ret || get_temp_path_ret > MAX_PATH + 1) {
		console::Error(E("Failed to get temporary path"));
		return L"";
	}
	if (temp_directory[wcslen(temp_directory) - 1] == L'\\')
		temp_directory[wcslen(temp_directory) - 1] = 0x0;

	ProtectEnd();
	return std::wstring(temp_directory);
}

bool utils::ReadFileToMemory(const std::wstring& file_path, std::vector<uint8_t>* out_buffer)
{
	ProtectMutate();
	std::ifstream file_ifstream(file_path, std::ios::binary);

	if (!file_ifstream)
		return false;

	out_buffer->assign((std::istreambuf_iterator<char>(file_ifstream)), std::istreambuf_iterator<char>());
	file_ifstream.close();

	ProtectEnd();
	return true;
}

bool utils::CreateFileFromMemory(const std::wstring& desired_file_path, const char* address, size_t size)
{
	ProtectMutate();
	std::ofstream file_ofstream(desired_file_path.c_str(), std::ios_base::out | std::ios_base::binary);

	if (!file_ofstream.write(address, size)) 
	{
		file_ofstream.close();
		return false;
	}

	file_ofstream.close();
	ProtectEnd();
	return true;
}

uint64_t utils::GetKernelModuleAddress(const std::string& module_name)
{
	ProtectMutate();
	void* buffer = nullptr;
	DWORD buffer_size = 0;

	NTSTATUS status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(nt::SystemModuleInformation), buffer, buffer_size, &buffer_size);

	while (status == nt::STATUS_INFO_LENGTH_MISMATCH) 
	{
		if (buffer != nullptr)
			VirtualFree(buffer, 0, MEM_RELEASE);

		buffer = VirtualAlloc(nullptr, buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(nt::SystemModuleInformation), buffer, buffer_size, &buffer_size);
	}

	if (!NT_SUCCESS(status)) 
	{
		if (buffer != nullptr)
			VirtualFree(buffer, 0, MEM_RELEASE);
		return 0;
	}

	const auto modules = static_cast<nt::PRTL_PROCESS_MODULES>(buffer);
	if (!modules)
		return 0;

	for (auto i = 0u; i < modules->NumberOfModules; ++i) 
	{
		const std::string current_module_name = std::string(reinterpret_cast<char*>(modules->Modules[i].FullPathName) + modules->Modules[i].OffsetToFileName);

		if (!_stricmp(current_module_name.c_str(), module_name.c_str()))
		{
			const uint64_t result = reinterpret_cast<uint64_t>(modules->Modules[i].ImageBase);

			VirtualFree(buffer, 0, MEM_RELEASE);
			return result;
		}
	}

	VirtualFree(buffer, 0, MEM_RELEASE);
	ProtectEnd();
	return 0;
}

BOOLEAN utils::bDataCompare(const BYTE* pData, const BYTE* bMask, const char* szMask)
{
	for (; *szMask; ++szMask, ++pData, ++bMask)
		if (*szMask == 'x' && *pData != *bMask)
			return 0;
	return (*szMask) == 0;
}

uintptr_t utils::FindPattern(uintptr_t dwAddress, uintptr_t dwLen, BYTE* bMask, char* szMask)
{
	size_t max_len = dwLen - strlen(szMask);
	for (uintptr_t i = 0; i < max_len; i++)
		if (bDataCompare((BYTE*)(dwAddress + i), bMask, szMask))
			return (uintptr_t)(dwAddress + i);
	return 0;
}

PVOID utils::FindSection(char* sectionName, uintptr_t modulePtr, PULONG size)
{
	ProtectMutate();
	size_t namelength = strlen(sectionName);
	PIMAGE_NT_HEADERS headers = (PIMAGE_NT_HEADERS)(modulePtr + ((PIMAGE_DOS_HEADER)modulePtr)->e_lfanew);
	PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(headers);

	for (DWORD i = 0; i < headers->FileHeader.NumberOfSections; ++i) 
	{
		PIMAGE_SECTION_HEADER section = &sections[i];
		if (memcmp(section->Name, sectionName, namelength) == 0 &&
			namelength == strlen((char*)section->Name))
		{
			if (!section->VirtualAddress) 
				return 0;

			if (size)
				*size = section->Misc.VirtualSize;

			return (PVOID)(modulePtr + section->VirtualAddress);
		}
	}

	ProtectEnd();
	return 0;
}

const wchar_t* utils::GetWidechar(const char* input)
{
	const size_t size = strlen(input) + 1;
	wchar_t* wc = new wchar_t[size];
	mbstowcs(wc, input, size);
	return wc;
}