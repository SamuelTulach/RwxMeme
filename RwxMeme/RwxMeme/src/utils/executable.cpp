#include "../general.h"

PIMAGE_NT_HEADERS64 executable::GetNtHeaders(void* imageBase)
{
	ProtectUltra();
	const auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(imageBase);

	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return nullptr;

	const auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS64>(reinterpret_cast<uint64_t>(imageBase) + dosHeader->e_lfanew);

	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
		return nullptr;

	ProtectEnd();
	return ntHeaders;
}

executable::VecRelocs executable::GetRelocs(void* imageBase)
{
	ProtectUltra();
	const PIMAGE_NT_HEADERS64 ntHeaders = GetNtHeaders(imageBase);

	if (!ntHeaders)
		return {};

	VecRelocs relocs;
	DWORD relocVa = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;

	if (!relocVa)
		return {};

	auto currentBaseRelocation = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<uint64_t>(imageBase) + relocVa);
	const auto relocEnd = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<uint64_t>(currentBaseRelocation) + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);

	while (currentBaseRelocation < relocEnd && currentBaseRelocation->SizeOfBlock) 
	{
		RelocInfo relocInfo;

		relocInfo.address = reinterpret_cast<uint64_t>(imageBase) + currentBaseRelocation->VirtualAddress;
		relocInfo.item = reinterpret_cast<uint16_t*>(reinterpret_cast<uint64_t>(currentBaseRelocation) + sizeof(IMAGE_BASE_RELOCATION));
		relocInfo.count = (currentBaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t);

		relocs.push_back(relocInfo);

		currentBaseRelocation = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<uint64_t>(currentBaseRelocation) + currentBaseRelocation->SizeOfBlock);
	}

	ProtectEnd();
	return relocs;
}

executable::VecImports executable::GetImports(void* imageBase)
{
	ProtectUltra();
	const PIMAGE_NT_HEADERS64 ntHeaders = GetNtHeaders(imageBase);

	if (!ntHeaders)
		return {};

	DWORD importVa = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

	if (!importVa)
		return {};

	VecImports imports;

	auto currentImportDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(reinterpret_cast<uint64_t>(imageBase) + importVa);

	while (currentImportDescriptor->FirstThunk) 
	{
		ImportInfo importInfo;

		importInfo.module_name = std::string(reinterpret_cast<char*>(reinterpret_cast<uint64_t>(imageBase) + currentImportDescriptor->Name));

		auto currentFirstThunk = reinterpret_cast<PIMAGE_THUNK_DATA64>(reinterpret_cast<uint64_t>(imageBase) + currentImportDescriptor->FirstThunk);
		auto currentOriginalFirstThunk = reinterpret_cast<PIMAGE_THUNK_DATA64>(reinterpret_cast<uint64_t>(imageBase) + currentImportDescriptor->OriginalFirstThunk);

		while (currentOriginalFirstThunk->u1.Function) 
		{
			ImportFunctionInfo importFunctionData;

			auto thunkData = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(reinterpret_cast<uint64_t>(imageBase) + currentOriginalFirstThunk->u1.AddressOfData);

			importFunctionData.name = thunkData->Name;
			importFunctionData.address = &currentFirstThunk->u1.Function;

			importInfo.function_datas.push_back(importFunctionData);

			++currentOriginalFirstThunk;
			++currentFirstThunk;
		}

		imports.push_back(importInfo);
		++currentImportDescriptor;
	}

	ProtectEnd();
	return imports;
}