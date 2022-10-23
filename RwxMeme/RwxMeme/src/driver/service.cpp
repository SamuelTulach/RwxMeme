#include "../general.h"

bool service::RegisterAndStart(const std::wstring& driver_path)
{
	ProtectUltra();
	const static DWORD ServiceTypeKernel = 1;
	const std::wstring driver_name = intel_driver::GetDriverNameW();
	const std::wstring servicesPath = EW(L"SYSTEM\\CurrentControlSet\\Services\\") + driver_name;
	const std::wstring nPath = EW(L"\\??\\") + driver_path;

	HKEY dservice;
	LSTATUS status = RegCreateKeyW(HKEY_LOCAL_MACHINE, servicesPath.c_str(), &dservice); //Returns Ok if already exists
	if (status != ERROR_SUCCESS) 
		return false;

	status = RegSetKeyValueW(dservice, NULL, EW(L"ImagePath"), REG_EXPAND_SZ, nPath.c_str(), (DWORD)(nPath.size() * sizeof(wchar_t)));
	if (status != ERROR_SUCCESS) 
	{
		RegCloseKey(dservice);
		return false;
	}

	status = RegSetKeyValueW(dservice, NULL, EW(L"Type"), REG_DWORD, &ServiceTypeKernel, sizeof(DWORD));
	if (status != ERROR_SUCCESS) {
		RegCloseKey(dservice);
		return false;
	}

	RegCloseKey(dservice);

	HMODULE ntdll = GetModuleHandleA(EW("ntdll.dll"));
	if (!ntdll)
		return false;

	auto RtlAdjustPrivilege = (nt::RtlAdjustPrivilege)GetProcAddress(ntdll, E("RtlAdjustPrivilege"));
	auto NtLoadDriver = (nt::NtLoadDriver)GetProcAddress(ntdll, E("NtLoadDriver"));

	ULONG SE_LOAD_DRIVER_PRIVILEGE = 10UL;
	BOOLEAN SeLoadDriverWasEnabled;
	NTSTATUS Status = RtlAdjustPrivilege(SE_LOAD_DRIVER_PRIVILEGE, TRUE, FALSE, &SeLoadDriverWasEnabled);
	if (!NT_SUCCESS(Status)) 
	{
		console::Error(E("Unable to set SE_LOAD_DRIVER_PRIVILEGE. Make sure you are running as administrator."));
		return false;
	}

	std::wstring wdriver_reg_path = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" + driver_name;
	UNICODE_STRING serviceStr;
	RtlInitUnicodeString(&serviceStr, wdriver_reg_path.c_str());

	Status = NtLoadDriver(&serviceStr);

	if (Status == 0xC000010E)
		return true;

	ProtectEnd();
	return NT_SUCCESS(Status);
}

bool service::StopAndRemove(const std::wstring& driver_name)
{
	ProtectUltra();
	HMODULE ntdll = GetModuleHandleA(E("ntdll.dll"));
	if (!ntdll)
		return false;

	std::wstring wdriver_reg_path = EW(L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\") + driver_name;
	UNICODE_STRING serviceStr;
	RtlInitUnicodeString(&serviceStr, wdriver_reg_path.c_str());

	HKEY driver_service;
	std::wstring servicesPath = EW(L"SYSTEM\\CurrentControlSet\\Services\\") + driver_name;
	LSTATUS status = RegOpenKeyW(HKEY_LOCAL_MACHINE, servicesPath.c_str(), &driver_service);
	if (status != ERROR_SUCCESS) 
	{
		if (status == ERROR_FILE_NOT_FOUND) 
			return true;

		return false;
	}

	RegCloseKey(driver_service);

	auto NtUnloadDriver = (nt::NtUnloadDriver)GetProcAddress(ntdll, E("NtUnloadDriver"));
	NTSTATUS st = NtUnloadDriver(&serviceStr);
	if (st != 0x0) 
	{
		RegDeleteKeyW(HKEY_LOCAL_MACHINE, servicesPath.c_str());
		return false;
	}

	status = RegDeleteKeyW(HKEY_LOCAL_MACHINE, servicesPath.c_str());
	if (status != ERROR_SUCCESS)
		return false;

	ProtectEnd();
	return true;
}
