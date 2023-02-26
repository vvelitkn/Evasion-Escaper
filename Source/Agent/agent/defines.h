#include "windef.h"
#include "winternl.h"
#include "oaidl.h"
#include "setupapi.h"
#include "mmsystem.h"
#include "Iphlpapi.h"
#pragma comment(lib, "iphlpapi.lib")

#define DLL_PROCESS_VERIFIER 4

typedef VOID ( NTAPI* RTL_VERIFIER_NTDLLHEAPFREE_CALLBACK )	( PVOID lpAllocationBase, SIZE_T size );
typedef VOID ( NTAPI* RTL_VERIFIER_DLL_LOAD_CALLBACK )		( PWSTR lpDLLName, PVOID lpDLLBase, SIZE_T size, PVOID lpReserved );
typedef VOID ( NTAPI* RTL_VERIFIER_DLL_UNLOAD_CALLBACK )	( PWSTR lpDLLName, PVOID lpDLLBase, SIZE_T size, PVOID lpReserved );

typedef struct _RTL_VERIFIER_THUNK_DESCRIPTOR {
   PCHAR ThunkName;
   PVOID ThunkOldAddress;
   PVOID ThunkNewAddress;
} RTL_VERIFIER_THUNK_DESCRIPTOR, *PRTL_VERIFIER_THUNK_DESCRIPTOR;

typedef struct _RTL_VERIFIER_DLL_DESCRIPTOR {
   PWCHAR DllName;
   DWORD DllFlags;
   PVOID DllAddress;
   PRTL_VERIFIER_THUNK_DESCRIPTOR DllThunks;
} RTL_VERIFIER_DLL_DESCRIPTOR, *PRTL_VERIFIER_DLL_DESCRIPTOR;

typedef struct _RTL_VERIFIER_PROVIDER_DESCRIPTOR {
   DWORD Length;
   PRTL_VERIFIER_DLL_DESCRIPTOR ProviderDlls;
   RTL_VERIFIER_DLL_LOAD_CALLBACK ProviderDllLoadCallback;
   RTL_VERIFIER_DLL_UNLOAD_CALLBACK ProviderDllUnloadCallback;
   PWSTR VerifierImage;
   DWORD VerifierFlags;
   DWORD VerifierDebug;
   PVOID RtlpGetStackTraceAddress;
   PVOID RtlpDebugPageHeapCreate;
   PVOID RtlpDebugPageHeapDestroy;
   RTL_VERIFIER_NTDLLHEAPFREE_CALLBACK ProviderNtdllHeapFreeCallback;
} RTL_VERIFIER_PROVIDER_DESCRIPTOR, *PRTL_VERIFIER_PROVIDER_DESCRIPTOR;

static RTL_VERIFIER_THUNK_DESCRIPTOR		AVRFThunks[1];
static RTL_VERIFIER_DLL_DESCRIPTOR			AVRFDlls[1]; 
static RTL_VERIFIER_PROVIDER_DESCRIPTOR		g_AVRFProvider;

typedef NTSTATUS ( NTAPI* tNtQuerySystemInformation )
(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT OPTIONAL PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT OPTIONAL PULONG ReturnLength
);

tNtQuerySystemInformation lpNtQuerySystemInformation;

typedef enum _SYSDBG_COMMAND
{
	SysDbgQueryModuleInformation,
	SysDbgQueryTraceInformation,
	SysDbgSetTracepoint,
	SysDbgSetSpecialCall,
	SysDbgClearSpecialCalls,
	SysDbgQuerySpecialCalls,
	SysDbgBreakPoint,
	SysDbgQueryVersion,
	SysDbgReadVirtual,
	SysDbgWriteVirtual,
	SysDbgReadPhysical,
	SysDbgWritePhysical,
	SysDbgReadControlSpace,
	SysDbgWriteControlSpace,
	SysDbgReadIoSpace,
	SysDbgWriteIoSpace,
	SysDbgReadMsr,
	SysDbgWriteMsr,
	SysDbgReadBusData,
	SysDbgWriteBusData,
	SysDbgCheckLowMemory,
	SysDbgEnableKernelDebugger,
	SysDbgDisableKernelDebugger,
	SysDbgGetAutoKdEnable,
	SysDbgSetAutoKdEnable,
	SysDbgGetPrintBufferSize,
	SysDbgSetPrintBufferSize,
	SysDbgGetKdUmExceptionEnable,
	SysDbgSetKdUmExceptionEnable,
	SysDbgGetTriageDump,
	SysDbgGetKdBlockEnable,
	SysDbgSetKdBlockEnable,
	SysDbgRegisterForUmBreakInfo,
	SysDbgGetUmBreakPid,
	SysDbgClearUmBreakPid,
	SysDbgGetUmAttachPid,
	SysDbgClearUmAttachPid,
	SysDbgGetLiveKernelDump,
	SysDbgKdPullRemoteFile
} SYSDBG_COMMAND, * PSYSDBG_COMMAND;

typedef HRESULT ( __stdcall* tExecQueryFunc)(void* pThis,  BSTR ,  BSTR , long , IWbemContext* , IEnumWbemClassObject** );
tExecQueryFunc oExecQueryFunc = NULL;

typedef HRESULT(__stdcall* tGetFunc)(void* pThis, LPCWSTR, LONG, PVOID, LONG, LONG);
tGetFunc oGetFunc = NULL;

typedef HMODULE (WINAPI* tGetModuleHandleW)(LPCWSTR);
tGetModuleHandleW oGetModuleHandleW = NULL;

typedef BOOL(WINAPI* tGetUserNameW)(LPWSTR, LPDWORD);
tGetUserNameW  oGetUserNameW = NULL;

typedef BOOL(WINAPI* tGetComputerNameW)(LPWSTR, LPDWORD);
tGetComputerNameW  oGetComputerNameW = NULL;

typedef BOOL(WINAPI* tGetComputerNameA)(LPWSTR, LPDWORD);
tGetComputerNameA  oGetComputerNameA = NULL;

typedef BOOL(WINAPI* tGetComputerNameExW)(COMPUTER_NAME_FORMAT,LPWSTR, LPDWORD);
tGetComputerNameExW  oGetComputerNameExW = NULL;

typedef DWORD(WINAPI* tGetFileAttributesW)(LPCWSTR);
tGetFileAttributesW  oGetFileAttributesW = NULL;

typedef PWSTR(WINAPI* tPathFindFileNameW)(LPCWSTR);
tPathFindFileNameW  oPathFindFileNameW = NULL;

typedef NTSTATUS(NTAPI* tNtSystemDebugControl)(SYSDBG_COMMAND, PVOID, ULONG, PVOID, ULONG, PULONG);
tNtSystemDebugControl oNtSystemDebugControl = NULL;

typedef NTSTATUS(NTAPI* tNtYieldExecution)();
tNtYieldExecution oNtYieldExecution = NULL;

typedef BOOL(WINAPI* tSetHandleInformation)(HANDLE, DWORD, DWORD);
tSetHandleInformation  oSetHandleInformation = NULL;

typedef BOOL(WINAPI* tSetupDiGetDeviceRegistryPropertyW)(HDEVINFO, PSP_DEVINFO_DATA, DWORD, PDWORD, PBYTE, DWORD, PDWORD);
tSetupDiGetDeviceRegistryPropertyW  oSetupDiGetDeviceRegistryPropertyW = NULL;

typedef BOOL(WINAPI* tEnumServicesStatusExW)(SC_HANDLE, SC_ENUM_TYPE, DWORD, DWORD, LPBYTE, DWORD, LPDWORD, LPDWORD, LPDWORD, LPCWSTR);
tEnumServicesStatusExW  oEnumServicesStatusExW = NULL;

typedef BOOL(WINAPI* tGetDiskFreeSpaceExW)(LPCWSTR, PULARGE_INTEGER, PULARGE_INTEGER, PULARGE_INTEGER);
tGetDiskFreeSpaceExW  oGetDiskFreeSpaceExW = NULL;

typedef LSTATUS(WINAPI* tRegQueryValueExW)(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
tRegQueryValueExW  oRegQueryValueExW = NULL;

typedef LSTATUS(WINAPI* tRegEnumKeyExW)(HKEY, DWORD, LPWSTR, LPDWORD, LPDWORD, LPWSTR, LPDWORD, PFILETIME);
tRegEnumKeyExW  oRegEnumKeyExW = NULL;

typedef NTSTATUS(NTAPI* tNtDelayExecution)(BOOLEAN, PLARGE_INTEGER);
tNtDelayExecution oNtDelayExecution = NULL;

typedef UINT(WINAPI* tSetTimer)(HWND hWnd, UINT_PTR nIDEvent, UINT uElapse, TIMERPROC lpTimerFunc);
tSetTimer oSetTimer = NULL;

typedef void (CALLBACK* LPTIMECALLBACK)(UINT, UINT, DWORD_PTR, DWORD_PTR, DWORD_PTR);
typedef MMRESULT(WINAPI* tTimeSetEvent)(UINT uDelay, UINT uResolution, LPTIMECALLBACK lpTimeProc, DWORD_PTR dwUser, UINT fuEvent);
tTimeSetEvent oTimeSetEvent = NULL;

typedef DWORD(WINAPI* tWaitForSingleObject)(HANDLE, DWORD);
tWaitForSingleObject oWaitForSingleObject = NULL;

typedef DWORD(WINAPI* tIcmpSendEcho)(HANDLE, IPAddr, LPVOID, WORD, PIP_OPTION_INFORMATION, LPVOID, DWORD, DWORD);
tIcmpSendEcho oIcmpSendEcho = NULL;

typedef BOOL(WINAPI* tSetWaitableTimer)(HANDLE, LARGE_INTEGER*, LONG, PTIMERAPCROUTINE, LPVOID, BOOL);
tSetWaitableTimer oSetWaitableTimer = NULL;

typedef BOOL(WINAPI* tCreateTimerQueueTimer)(HANDLE*, HANDLE, WAITORTIMERCALLBACK, PVOID, DWORD, DWORD, ULONG);
tCreateTimerQueueTimer oCreateTimerQueueTimer = NULL;

typedef HANDLE(WINAPI* tCreateToolhelp32Snapshot)(DWORD, DWORD);
tCreateToolhelp32Snapshot oCreateToolhelp32Snapshot = NULL;

typedef LSTATUS(WINAPI* tRegOpenKeyExW)(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
tRegOpenKeyExW oRegOpenKeyExW = NULL;

typedef ULONG(WINAPI* tGetSystemFirmwareTable)(DWORD, DWORD, PVOID, DWORD);
tGetSystemFirmwareTable oGetSystemFirmwareTable = NULL;

typedef struct _FIRMWARE_TABLE_ENTRY {
	GUID FirmwareTableProviderSignature;
	DWORD FirmwareTableID;
} FIRMWARE_TABLE_ENTRY, * PFIRMWARE_TABLE_ENTRY;


typedef UINT(WINAPI* tEnumSystemFirmwareTables)(DWORD, PVOID, DWORD);
tEnumSystemFirmwareTables oEnumSystemFirmwareTables = NULL;