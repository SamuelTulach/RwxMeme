#ifndef MEMORY_H
#define MEMORY_H

namespace memory
{
	enum ActionType
	{
		ActionUnknown,
		ActionOpenProcess,
		ActionReadMemory,
		ActionWriteMemory,
		ActionModuleQuery
	};

	enum ActionStatus
	{
		StatusInvalid,
		StatusPending,
		StatusError,
		StatusDone
	};

	typedef struct _ControlData
	{
		ActionType Action;
		ActionStatus Status;
		uint64_t Data[5];
	} ControlData;

	void HandleOpenProcess(volatile ControlData* data);
	void HandleReadMemory(volatile ControlData* data);
	void HandleWriteMemory(volatile ControlData* data);
	void HandleModuleQuery(volatile ControlData* data);
	ActionStatus PerformAction(ActionType type, uint64_t data1 = 0, uint64_t data2 = 0, uint64_t data3 = 0, uint64_t data4 = 0, uint64_t data5 = 0);
	void Loop();
}

namespace memory_helper
{
	inline DWORD targetPid = 0;

	DWORD GetProcessPID(const wchar_t* processName);
	uint64_t GetModuleAddress(const wchar_t* moduleName);
	void WaitAndOpenProcess(const wchar_t* processName);
	bool ReadMemory(uint64_t address, void* buffer, size_t size);
	bool WriteMemory(uint64_t address, void* buffer, size_t size);

	template<typename T>
	T Read(uint64_t address)
	{
		T val = T();
		ReadMemory(address, &val, sizeof(T));
		return val;
	}

	template<typename T>
	void Write(DWORD64 address, T value)
	{
		WriteMemory(address, &value, sizeof(T));
	}
}

#endif