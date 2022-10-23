#pragma once

namespace executable
{
	struct RelocInfo
	{
		uint64_t address;
		uint16_t* item;
		uint32_t count;
	};

	struct ImportFunctionInfo
	{
		std::string name;
		uint64_t* address;
	};

	struct ImportInfo
	{
		std::string module_name;
		std::vector<ImportFunctionInfo> function_datas;
	};

	using VecSections = std::vector<IMAGE_SECTION_HEADER>;
	using VecRelocs = std::vector<RelocInfo>;
	using VecImports = std::vector<ImportInfo>;

	PIMAGE_NT_HEADERS64 GetNtHeaders(void* imageBase);
	VecRelocs GetRelocs(void* imageBase);
	VecImports GetImports(void* imageBase);
}