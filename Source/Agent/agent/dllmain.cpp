#include "stdafx.h"
#include <windows.h>
#include "windef.h"
#include "winternl.h"
#include "stdio.h"
#include "time.h"
#include <comdef.h>
#include <wbemidl.h>
#include <string>
#include <iostream>
#include <sstream>
#include <wbemidl.h>
#include <Shlwapi.h>
#pragma comment(lib, "shlwapi.lib")
#include "detours.h"
#pragma comment(lib, "detours.lib")
#include "defines.h"
#include <tlhelp32.h>
#include <fstream>
#include <vector>
#include <algorithm>
#include <DbgHelp.h>
#include <locale>
#include <codecvt>
#include <Windows.h>
#include <WinBase.h>
#include <TlHelp32.h>
#include <psapi.h>
#include <fstream>
#include <chrono>
#include <ctime>
#include <filesystem>


std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;

//#include "json.hpp"
// 
// declarations for the rules arrays
const int MAX_RULES = 100;
//std::wstring random_strings[MAX_RULES];
std::vector<std::vector<std::wstring>> rules_avoid;
std::vector<std::vector<std::wstring>> rules_GetFileAttributesW;
std::vector<std::vector<std::wstring>> rules_ExecQuery;
std::vector<std::vector<std::wstring>> rules_Get;
std::vector<std::vector<std::wstring>> rules_PathFindFileNameW;
std::vector<std::vector<std::wstring>> rules_SetupDiGetDeviceRegistryPropertyW;
std::vector<std::vector<std::wstring>> rules_EnumServicesStatusExW;
std::vector<std::vector<std::wstring>> rules_RegQueryValueExW;
std::vector<std::vector<std::wstring>> rules_GetComputerNameExW;
std::vector<std::vector<std::wstring>> rules_GetModuleHandleW;
std::vector<std::vector<std::wstring>> rules_RegEnumKeyExW;
std::vector<std::vector<std::wstring>> rules_CreateToolhelp32Snapshot;
std::vector<std::vector<std::wstring>> rules_RegOpenKeyEx;
std::vector<std::vector<std::wstring>> rules_GetAdaptersInfo;
std::vector<std::vector<std::wstring>> rules_GetSystemFirmwareTable;
std::wstring random_strings[] = {
	L"wibkmadsfds"
};

const int MAX_LEN = 10;
const int NUM_STRINGS = 5;

// Convert UTF-8 (std::string) to UTF-16 (std::wstring)
std::wstring stringToWString(const std::string& str) {
	if (str.empty()) return std::wstring();
	int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
	std::wstring wstrTo(size_needed, 0);
	MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
	return wstrTo;
}

BOOL parse_ruleset(std::string file_name) {
	std::ifstream file(file_name);
	std::string line;
	while (std::getline(file, line)) {
		std::istringstream iss(line);
		std::string rulePart;
		std::vector<std::string> rule;

		while (std::getline(iss, rulePart, ',')) {
			rule.push_back(rulePart);
		}
		if (rule[0] == "avoid") {
			rules_avoid.push_back({
			std::wstring(rule[1].begin(), rule[1].end()),
				});
		}
		else if (rule[0] == "Get") {
			rules_Get.push_back({
			std::wstring(rule[1].begin(), rule[1].end()),
			std::wstring(rule[2].begin(), rule[2].end()),
			std::wstring(rule[3].begin(), rule[3].end())
				});

		}
		else if (rule[0] == "GetFileAttributesW") {
			rules_GetFileAttributesW.push_back({
			std::wstring(rule[1].begin(), rule[1].end()),
				});
		}
		else if (rule[0] == "ExecQuery") {
			rules_ExecQuery.push_back({
			std::wstring(rule[1].begin(), rule[1].end()),
			std::wstring(rule[2].begin(), rule[2].end())
				});
		}
		else if (rule[0] == "PathFindFileNameW") {
			rules_PathFindFileNameW.push_back({
			std::wstring(rule[1].begin(), rule[1].end()),
				});
		}
		else if (rule[0] == "SetupDiGetDeviceRegistryPropertyW") {
			rules_SetupDiGetDeviceRegistryPropertyW.push_back({
			std::wstring(rule[1].begin(), rule[1].end()),
				});
		}
		else if (rule[0] == "EnumServicesStatusExW") {
			rules_EnumServicesStatusExW.push_back({
			std::wstring(rule[1].begin(), rule[1].end()),
				});
		}
		else if (rule[0] == "RegQueryValueExW") {
			rules_RegQueryValueExW.push_back({
			std::wstring(rule[1].begin(), rule[1].end()),
				});
		}
		else if (rule[0] == "GetComputerNameExW") {
			rules_GetComputerNameExW.push_back({
			std::wstring(rule[1].begin(), rule[1].end()),
				});
		}
		else if (rule[0] == "GetModuleHandleW") {
			rules_GetModuleHandleW.push_back({
			std::wstring(rule[1].begin(), rule[1].end()),
				});
		}
		else if (rule[0] == "RegEnumKeyExW") {
			rules_RegEnumKeyExW.push_back({
			std::wstring(rule[1].begin(), rule[1].end()),
				});
		}
		else if (rule[0] == "CreateToolhelp32Snapshot") {
			rules_CreateToolhelp32Snapshot.push_back({
			std::wstring(rule[1].begin(), rule[1].end()),
				});
		}
		else if (rule[0] == "RegOpenKeyEx") {
			rules_RegOpenKeyEx.push_back({
			std::wstring(rule[1].begin(), rule[1].end()),
				});
		}
		else if (rule[0] == "GetAdaptersInfo") {
			rules_GetAdaptersInfo.push_back({
			std::wstring(rule[1].begin(), rule[1].end()),
				});
		}
		else if (rule[0] == "GetSystemFirmwareTable") {
			rules_GetSystemFirmwareTable.push_back({
			std::wstring(rule[1].begin(), rule[1].end()),
				});
		}
	}
	return true;
}

// Log entry struct
struct LogEntry {
	std::wstring timestamp;
	std::wstring functionName;
	std::wstring requestData;
	std::wstring operation;
};

//-----------------------------------------------
// Logger Function
//-----------------------------------------------

void addLogEntry(std::wstring functionName, std::wstring requestData, std::wstring operation) {
	// Create new log entry
	LogEntry entry = { functionName, requestData, operation };

	// Prevent duplicate entries
	static LogEntry previousEntry = { L"", L"", L"" };
	if (entry.functionName != previousEntry.functionName ||
		entry.requestData != previousEntry.requestData ||
		entry.operation != previousEntry.operation) {

		previousEntry = entry; // Update previous entry

		// Get current time
		std::time_t currentTime = std::time(nullptr);
		std::tm localTime;
		localtime_s(&localTime, &currentTime);

		// Format timestamp
		wchar_t timestampBuffer[20];
		wcsftime(timestampBuffer, 20, L"%Y-%m-%d %H_%M", &localTime);

		// Append filename to path
		std::wstring filename = L"Event_Log_" + std::wstring(timestampBuffer) + L".txt";
		std::wstring fullpath = L"..\\Logs\\" + filename;

		// Create Logs folder if it doesn't exist (Fixed: Wide string)
		CreateDirectory("..\\Logs\\", NULL);

		// Open file for writing (Fixed: Use wofstream for wide strings)
		std::wofstream file(fullpath, std::ios_base::app);
		if (file.is_open()) {
			file << L"functionName: \"" << functionName << L"\"\n{\n"
				<< L"\trequestData: \"" << requestData << L"\",\n"
				<< L"\toperation: \"" << operation << L"\"\n"
				<< L"}\n";

			file.close();
		}
	}
}

//-----------------------------------------------
// ProcessID Finder
//-----------------------------------------------

int findMyProc(const char* procname) {
	HANDLE hSnapshot;
	PROCESSENTRY32W pe;
	int pid = 0;
	BOOL hResult;
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hSnapshot) return 0;

	pe.dwSize = sizeof(PROCESSENTRY32W);
	hResult = Process32FirstW(hSnapshot, &pe);
	while (hResult) {
		wchar_t wideProcName[MAX_PATH];
		MultiByteToWideChar(CP_ACP, 0, procname, -1, wideProcName, MAX_PATH);

		if (wcscmp(wideProcName, pe.szExeFile) == 0) {
			pid = pe.th32ProcessID;
			break;
		}
		hResult = Process32NextW(hSnapshot, &pe);
	}
	CloseHandle(hSnapshot);
	return pid;
}

//-----------------------------------------------
// Modified Functions
//-----------------------------------------------

BOOL WINAPI hGetUserNameW(LPWSTR lpBuffer, LPDWORD pcbBuffer)
{
	std::wstring randomstring = random_strings[0];
	addLogEntry(std::wstring(converter.from_bytes(__FUNCTION__)).substr(1), lpBuffer, L"Changed to" + randomstring);
	wcscpy_s(lpBuffer, wcslen(randomstring.c_str()) + 1, randomstring.c_str());
	*pcbBuffer = (DWORD)wcslen(randomstring.c_str()) + 1;
	return TRUE;
}

DWORD WINAPI hGetFileAttributesW(LPWSTR lpFileName)
{
	DWORD result = oGetFileAttributesW(lpFileName);
	if (lpFileName != NULL) {
		for (const auto& rule : rules_GetFileAttributesW)
		{
			if (StrStrIW(lpFileName, rule[0].c_str()))
			{
				addLogEntry(std::wstring(converter.from_bytes(__FUNCTION__)).substr(1), lpFileName, L"Returned INVALID_FILE_ATTRIBUTES");
				return INVALID_FILE_ATTRIBUTES;
				break;
			}
		}
	}
	return result;
}

// from Al-Khaser project
BOOL IsHexString(WCHAR* szStr) {
	std::wstring s(szStr);
	if (std::find_if(s.begin(), s.end(), [](wchar_t c) {return !std::isxdigit(static_cast<unsigned char>(c)); }) == s.end())
		return TRUE;
	else
		return FALSE;
}

PWSTR WINAPI hPathFindFileNameW(LPWSTR pszPath)
{
	PWSTR pwResult = oPathFindFileNameW(pszPath);
	PWSTR clean_pwResult = pwResult;
	PathRemoveExtensionW(clean_pwResult);

	std::wstring randomstring = random_strings[0];
	
	if (pwResult != NULL) {
		for (const auto& rule : rules_Get) 
		{
			PWSTR match = wcsstr(pwResult, rule[0].c_str());
			if (match != nullptr) {

				wcscpy_s(pwResult, wcslen(randomstring.c_str()) + 1, randomstring.c_str());

				addLogEntry(std::wstring(converter.from_bytes(__FUNCTION__)).substr(1), pwResult, L"Changed to " + randomstring);
				
				break;
			}
			if ((wcslen(clean_pwResult) == 32 || wcslen(clean_pwResult) == 40 || wcslen(clean_pwResult) == 64) && IsHexString(clean_pwResult))
			{
				wcscpy_s(pwResult, wcslen(randomstring.c_str()) + 1, randomstring.c_str());

				addLogEntry(std::wstring(converter.from_bytes(__FUNCTION__)).substr(1), pwResult, L"Changed to " + randomstring);

				break;
			}
		}
	}
	return pwResult;
}

BOOL WINAPI hGetComputerNameW(LPWSTR lpBuffer, LPDWORD nSize)
{
	std::wstring randomstring = random_strings[0];
	wcscpy_s(lpBuffer, wcslen(randomstring.c_str()) + 1, randomstring.c_str());
	*nSize = (DWORD)wcslen(randomstring.c_str()) + 1;
	addLogEntry(std::wstring(converter.from_bytes(__FUNCTION__)).substr(1), lpBuffer, L"Changed to " + randomstring);
	return TRUE;
}

NTSTATUS NTAPI hNtSystemDebugControl(SYSDBG_COMMAND Command, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, PULONG ReturnLength)
{
	if (Command == SYSDBG_COMMAND::SysDbgCheckLowMemory)
	{
		addLogEntry(std::wstring(converter.from_bytes(__FUNCTION__)).substr(1), L"SysDbgCheckLowMemory", L"RETURN 0xC0000354L");
		return 0xC0000354L;
	}
	NTSTATUS result = oNtSystemDebugControl(Command, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength, ReturnLength);
	return result;
}

NTSTATUS NTAPI hNtYieldExecution()
{
	// This function's log appears too many times, to keep the log file clear it is commented
	//addLogEntry(std::wstring(converter.from_bytes(__FUNCTION__)).substr(1), L"NTSTATUS", L"RETURN 0x40000024");
	return 0x40000024;
}

NTSTATUS WINAPI hNtDelayExecution(BOOL Alertable, PLARGE_INTEGER DelayInterval)
{
	addLogEntry(std::wstring(converter.from_bytes(__FUNCTION__)).substr(1), std::to_wstring(DelayInterval->QuadPart), L"Changed to 1");
	DelayInterval->QuadPart = 1;
	NTSTATUS result = oNtDelayExecution(Alertable, DelayInterval);
	
	return result;
}

UINT WINAPI hSetTimer(HWND hWnd, UINT_PTR nIDEvent, UINT uElapse, TIMERPROC lpTimerFunc)
{
	if (uElapse > 100) 
	{
	addLogEntry(std::wstring(converter.from_bytes(__FUNCTION__)).substr(1), std::to_wstring(uElapse), L"Changed to 100");
	uElapse = 100;
	}
		
	UINT result = oSetTimer(hWnd, nIDEvent, uElapse, lpTimerFunc);
	return result;
}

MMRESULT WINAPI hTimeSetEvent(UINT uDelay, UINT uResolution, LPTIMECALLBACK lpTimeProc, DWORD_PTR dwUser, UINT fuEvent)
{
	if (uDelay > 100) {
		addLogEntry(std::wstring(converter.from_bytes(__FUNCTION__)).substr(1), std::to_wstring(uDelay), L"Changed to 100");
		uDelay = 100;
	}

	MMRESULT result = oTimeSetEvent(uDelay, uResolution, lpTimeProc, dwUser, fuEvent);
	return result;
}

BOOL called_SetWaitableTimer = FALSE;
DWORD WINAPI hWaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds)
{
	if (dwMilliseconds > 100 && dwMilliseconds != INFINITE) {
		addLogEntry(std::wstring(converter.from_bytes(__FUNCTION__)).substr(1), std::to_wstring(dwMilliseconds), L"Changed to 100");
		dwMilliseconds = 100;
	}
		

	// If WaitForSingleObject called after SetWaitableTimer, dwMilliseconds will be INFINITE,
	// else INFINITE could be set by other functions, we should not touch to reduce errors
	// As a solution a bool created and checked -> called_SetWaitableTimer
	// called_SetWaitableTimer checks if SetWaitableTimer called before, if it called we return WAIT_OBJECT_0
	if (dwMilliseconds == INFINITE && called_SetWaitableTimer == TRUE) {
		addLogEntry(std::wstring(converter.from_bytes(__FUNCTION__)).substr(1), L"after SetWaitableTimer with INFINITE", L"Changed to 100");
		DWORD result = oWaitForSingleObject(hHandle, 1000);
		called_SetWaitableTimer = FALSE;
		return WAIT_OBJECT_0;
	}

	DWORD result = oWaitForSingleObject(hHandle, dwMilliseconds);
	return result;
}

DWORD WINAPI hIcmpSendEcho(HANDLE IcmpHandle, IPAddr DestinationAddress, LPVOID RequestData, WORD RequestSize, PIP_OPTION_INFORMATION RequestOptions, LPVOID ReplyBuffer, DWORD ReplySize, DWORD Timeout)
{
	if (Timeout > 100) 
	{
		addLogEntry(std::wstring(converter.from_bytes(__FUNCTION__)).substr(1), std::to_wstring(Timeout), L"Changed to 100");
		Timeout = 100;
	}
		

	DWORD result = oIcmpSendEcho(IcmpHandle, DestinationAddress, RequestData, RequestSize, RequestOptions, ReplyBuffer, ReplySize, Timeout);
	return result;
}

BOOL WINAPI hSetWaitableTimer(HANDLE hTimer, LARGE_INTEGER* pDueTime, LONG lPeriod, PTIMERAPCROUTINE pfnCompletionRoutine, LPVOID lpArgToCompletionRoutine, BOOL fResume)
{
	LARGE_INTEGER correctedDueTime;
	correctedDueTime.QuadPart = pDueTime->QuadPart;

	// if due time is greater than 1 second
	if (correctedDueTime.QuadPart > -1000000LL) {
		addLogEntry(std::wstring(converter.from_bytes(__FUNCTION__)).substr(1), std::to_wstring(pDueTime->QuadPart), L"Changed to -1000000LL, 1 second");
		correctedDueTime.QuadPart = -1000000LL;
	}
		
	BOOL result = oSetWaitableTimer(hTimer, &correctedDueTime, lPeriod, pfnCompletionRoutine, lpArgToCompletionRoutine, fResume);
	called_SetWaitableTimer = TRUE;
	return result;
}

BOOL WINAPI hCreateTimerQueueTimer(PHANDLE phNewTimer, HANDLE TimerQueue, WAITORTIMERCALLBACK Callback, PVOID Parameter, DWORD DueTime, DWORD Period, ULONG Flags)
{
	if (DueTime > 100)
	{
		addLogEntry(std::wstring(converter.from_bytes(__FUNCTION__)).substr(1), std::to_wstring(DueTime), L"Changed to 100");
		DueTime = 100;
	}
		
	BOOL result = oCreateTimerQueueTimer(phNewTimer, TimerQueue, Callback, Parameter, DueTime, Period, Flags);
	return result;
}


BOOL WINAPI hGetComputerNameA(LPWSTR lpBuffer, LPDWORD nSize)
{
	std::wstring randomstring = random_strings[0];
	addLogEntry(std::wstring(converter.from_bytes(__FUNCTION__)).substr(1), lpBuffer, L"Changed to "+ randomstring);
	wcscpy_s(lpBuffer, wcslen(randomstring.c_str()) + 1, randomstring.c_str());
	*nSize = (DWORD)wcslen(randomstring.c_str()) + 1;

	return TRUE;
}

BOOL WINAPI hSetHandleInformation(HANDLE hObject, DWORD  dwMask, DWORD  dwFlags)
{
	// If the dwMask parameter and the dwFlags parameter are  HANDLE_FLAG_PROTECT_FROM_CLOSE,
	// malware tries calling to SetHandleInformation that is trying to protect a handle from being closed
	if (dwMask == HANDLE_FLAG_PROTECT_FROM_CLOSE && dwFlags == HANDLE_FLAG_PROTECT_FROM_CLOSE)
	{
		addLogEntry(std::wstring(converter.from_bytes(__FUNCTION__)).substr(1), L"HANDLE_FLAG_PROTECT_FROM_CLOSE", L"Changed to 0");
		// Now that the handle is no longer protected, it can be closed without triggering an exception
		return oSetHandleInformation(hObject, HANDLE_FLAG_PROTECT_FROM_CLOSE, 0);
	}
	else
	{
		return oSetHandleInformation(hObject, dwMask, dwFlags);
	}
}

BOOL WINAPI hSetupDiGetDeviceRegistryPropertyW(HDEVINFO DeviceInfoSet, PSP_DEVINFO_DATA DeviceInfoData, DWORD Property, PDWORD PropertyRegDataType, PBYTE PropertyBuffer, DWORD PropertyBufferSize, PDWORD RequiredSize)
{
	BOOL result = oSetupDiGetDeviceRegistryPropertyW(DeviceInfoSet, DeviceInfoData, Property, PropertyRegDataType, PropertyBuffer, PropertyBufferSize, RequiredSize);

	if (PropertyBuffer != NULL) {

		WCHAR* pBuffer = reinterpret_cast<WCHAR*>(PropertyBuffer);

		for (const auto& rule : rules_SetupDiGetDeviceRegistryPropertyW)
		{
			if (StrStrIW(pBuffer, rule[0].c_str())) {
				std::wstring randomstring = random_strings[0];
				addLogEntry(std::wstring(converter.from_bytes(__FUNCTION__)).substr(1), pBuffer, L"Changed to " + randomstring);
				wcscpy_s(pBuffer, wcslen(randomstring.c_str()) + 1, randomstring.c_str());
				return result;
			}
		}
	}
	return result;
}

BOOL WINAPI hEnumServicesStatusExW(SC_HANDLE hSCManager, SC_ENUM_TYPE InfoLevel, DWORD dwServiceType, DWORD dwServiceState, LPBYTE lpServices, DWORD cbBufSize, LPDWORD pcbBytesNeeded, LPDWORD lpServicesReturned, LPDWORD lpResumeHandle, LPCWSTR pszGroupName)
{
	LPBYTE lpNewServices = new BYTE[cbBufSize];
	ZeroMemory(lpNewServices, cbBufSize);

	DWORD dwNewServicesReturned = 0;
	DWORD dwBytesNeeded = 0;
	LPENUM_SERVICE_STATUS_PROCESSW newServices = reinterpret_cast<LPENUM_SERVICE_STATUS_PROCESSW>(lpNewServices);
	
	// Copy the service information from the original buffer to the new buffer, somehow original buffer resisted to changes
	CopyMemory(lpNewServices, lpServices, cbBufSize);

	BOOL result = oEnumServicesStatusExW(hSCManager, InfoLevel, dwServiceType, dwServiceState, lpNewServices, cbBufSize, pcbBytesNeeded, lpServicesReturned, lpResumeHandle, pszGroupName);

	if (result && lpNewServices && *lpServicesReturned > 0)
	{
		LPENUM_SERVICE_STATUS_PROCESSW services = reinterpret_cast<LPENUM_SERVICE_STATUS_PROCESSW>(lpServices);
		
		for (DWORD i = 0; i < *lpServicesReturned; i++)
		{
			for (const auto& rule : rules_EnumServicesStatusExW)
			{
				if (StrStrIW(newServices[i].lpServiceName, rule[0].c_str()))
				{
					// To reduce the errors we set randomstring length to actual string
					std::wstring randomstring = random_strings[0].substr(0, wcslen(newServices[i].lpServiceName));
					addLogEntry(std::wstring(converter.from_bytes(__FUNCTION__)).substr(1), newServices[i].lpServiceName, L"Changed to " + randomstring);
					wcscpy_s(newServices[i].lpServiceName, wcslen(randomstring.c_str()) + 1, randomstring.c_str());
					wcscpy_s(newServices[i].lpDisplayName, wcslen(randomstring.c_str()) + 1, randomstring.c_str());
					break;
				}
			}
		}
	}

	return result;
}


ULONG WINAPI hGetSystemFirmwareTable(DWORD FirmwareTableProviderSignature, DWORD FirmwareTableID, PVOID pFirmwareTableBuffer, DWORD BufferSize)
{
	ULONG result = oGetSystemFirmwareTable(FirmwareTableProviderSignature, FirmwareTableID, pFirmwareTableBuffer, BufferSize);
	PBYTE firmwareTable = reinterpret_cast<PBYTE>(pFirmwareTableBuffer);
	size_t firmwareTableSize = static_cast<size_t>(result);

	for (const auto& rule : rules_GetSystemFirmwareTable)
	{
		std::string needle = converter.to_bytes(rule[0].c_str());
		size_t needleLen = needle.length();

		std::string randomChars = converter.to_bytes(random_strings[0].c_str());

		for (size_t i = 0; i < firmwareTableSize - needleLen; i++)
		{
			if (memcmp(&firmwareTable[i], reinterpret_cast<PBYTE>(&needle), needleLen) == 0)
			{
				addLogEntry(std::wstring(converter.from_bytes(__FUNCTION__)).substr(1), converter.from_bytes(firmwareTable[i]), L"Changed to " + converter.from_bytes(randomChars.substr(0, needleLen)));
				memcpy(&firmwareTable[i], &randomChars[0], needleLen);
			}
		}
	}
	return result;
}

DWORD WINAPI hGetAdaptersInfo(PIP_ADAPTER_INFO pAdapterInfo, PULONG pOutBufLen)
{
	DWORD dwResult = oGetAdaptersInfo(pAdapterInfo, pOutBufLen);

	if (dwResult == ERROR_SUCCESS && pAdapterInfo != NULL)
	{
		PIP_ADAPTER_INFO pAdapter = pAdapterInfo;

		while (pAdapter)
		{
			// Realtek PCIe GbE Family Controller -> 7C:8A:E1
			pAdapter->Address[0] = 0x7C;
			pAdapter->Address[1] = 0x8A;
			pAdapter->Address[2] = 0xE1;

			pAdapter = pAdapter->Next;
		}
	}

	return dwResult;
}

UINT WINAPI hEnumSystemFirmwareTables(DWORD FirmwareTableProviderSignature, PVOID pFirmwareTableEnumBuffer, DWORD BufferSize)
{
	UINT result = oEnumSystemFirmwareTables(FirmwareTableProviderSignature, pFirmwareTableEnumBuffer, BufferSize);

	PBYTE firmwareTable = reinterpret_cast<PBYTE>(pFirmwareTableEnumBuffer);
	size_t firmwareTableSize = static_cast<size_t>(result);

	if ((BufferSize / sizeof(FIRMWARE_TABLE_ENTRY)) < 4)
	{
		
		int numAdditionalTables = 4 - (BufferSize / sizeof(FIRMWARE_TABLE_ENTRY));
		addLogEntry(std::wstring(converter.from_bytes(__FUNCTION__)).substr(1), L"Less than 4 firmware table: "+ std::to_wstring(BufferSize / sizeof(FIRMWARE_TABLE_ENTRY)), L"Created " + std::to_wstring(numAdditionalTables) + L" more");
		// Create dummmy firmware table data to bypass count condition
		std::vector<BYTE> randomData(256);
		for (int i = 0; i < numAdditionalTables; i++)
		{
			// Create random GUID and FirmwareTableID for the new firmware table
			GUID randomGuid = {0x00112233, 0x4455, 0x6677, { 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF }};
			DWORD randomFirmwareTableID = 93454353 % 0xFFFF;

			// Add the new firmware table to the buffer
			PFIRMWARE_TABLE_ENTRY pNewTable = reinterpret_cast<PFIRMWARE_TABLE_ENTRY>(reinterpret_cast<PBYTE>(pFirmwareTableEnumBuffer) + (result * sizeof(FIRMWARE_TABLE_ENTRY)));
			pNewTable->FirmwareTableProviderSignature = randomGuid;
			pNewTable->FirmwareTableID = randomFirmwareTableID;

			memset(randomData.data(), 93454353, randomData.size());
			memcpy(reinterpret_cast<PBYTE>(pNewTable) + sizeof(FIRMWARE_TABLE_ENTRY), randomData.data(), randomData.size());

			result++;
		}
	}
	return result;
}



BOOL WINAPI hGetDiskFreeSpaceExW(LPCWSTR lpDirectoryName, PULARGE_INTEGER lpFreeBytesAvailableToCaller, PULARGE_INTEGER lpTotalNumberOfBytes, PULARGE_INTEGER lpTotalNumberOfFreeBytes)
{
	BOOL result = oGetDiskFreeSpaceExW(lpDirectoryName, lpFreeBytesAvailableToCaller, lpTotalNumberOfBytes, lpTotalNumberOfFreeBytes);

	// Modify the free disk space to 490 GB
	if (lpTotalNumberOfBytes != NULL)
	{
		addLogEntry(std::wstring(converter.from_bytes(__FUNCTION__)).substr(1), L"lpTotalNumberOfBytes < 490GB", L"Changed to 490GB");

		ULARGE_INTEGER newSize;
		newSize.QuadPart = 490LL * 1024LL * 1024LL * 1024LL;  // Set new size to 490 GB
		*lpTotalNumberOfBytes = newSize;
	}

	return result;
}

LSTATUS WINAPI hRegQueryValueExW(HKEY hKey, LPCWSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)
{
	LSTATUS result = oRegQueryValueExW(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);
	WCHAR* pData = reinterpret_cast<WCHAR*>(lpData);
	for (const auto& rule : rules_RegQueryValueExW)
	{
		if (StrStrIW(pData, rule[0].c_str())) {
			addLogEntry(std::wstring(converter.from_bytes(__FUNCTION__)).substr(1), pData, L"RETURN ERROR_FILE_NOT_FOUND");
			// The buffer contains, so we return an error code
			return ERROR_FILE_NOT_FOUND;
		}
	}
	return result;
}

LSTATUS WINAPI hRegEnumKeyExW(HKEY hKey, DWORD dwIndex, LPWSTR lpName, LPDWORD lpcchName, LPDWORD lpReserved, LPWSTR lpClass, LPDWORD lpcchClass, PFILETIME lpftLastWriteTime)
{
	LSTATUS result = oRegEnumKeyExW(hKey, dwIndex, lpName, lpcchName, lpReserved, lpClass, lpcchClass, lpftLastWriteTime);
	for (const auto& rule : rules_RegEnumKeyExW)
	{
		if (StrStrIW(lpName, rule[0].c_str())) {
			addLogEntry(std::wstring(converter.from_bytes(__FUNCTION__)).substr(1), lpName, L"RETURN ERROR_FILE_NOT_FOUND");
			// The buffer contains, so we return an error code
			return ERROR_FILE_NOT_FOUND;
		}
	}
	return result;
}

LSTATUS WINAPI hRegOpenKeyExW(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult)
{
	LSTATUS result = oRegOpenKeyExW(hKey, lpSubKey, ulOptions, samDesired, phkResult);

	for (const auto& rule : rules_RegOpenKeyEx)
	{
		if (StrStrIW(converter.from_bytes(lpSubKey).c_str(), rule[0].c_str()))
		{
			addLogEntry(std::wstring(converter.from_bytes(__FUNCTION__)).substr(1), converter.from_bytes(lpSubKey).c_str(), L"RETURN ERROR_FILE_NOT_FOUND");
			result = ERROR_FILE_NOT_FOUND;
			break;
		}
	}
	return result;
}

HANDLE WINAPI hCreateFile(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
	DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
	if (wcsstr(lpFileName, L"HGFS") || wcsstr(lpFileName, L"vmci")) {
		// Return a valid handle instead of calling CreateFile
		// This bypasses the check (for VMware devices)
		addLogEntry(std::wstring(converter.from_bytes(__FUNCTION__)).substr(1), lpFileName, L"Returned INVALID_HANDLE_VALUE");
		return INVALID_HANDLE_VALUE;
	}

	// Call the original CreateFileW for all other cases
	return oCreateFile(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes,
		dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}


BOOL WINAPI hGetComputerNameExW(COMPUTER_NAME_FORMAT NameType, LPWSTR lpBuffer, LPDWORD nSize)
{
	if (lpBuffer != NULL) {
		for (const auto& rule : rules_GetComputerNameExW)
		{
			if (StrStrIW(lpBuffer, rule[0].c_str())) {
				std::wstring randomstring = random_strings[0];
				addLogEntry(std::wstring(converter.from_bytes(__FUNCTION__)).substr(1), lpBuffer, L"Changed to "+ randomstring);
				wcscpy_s(lpBuffer, wcslen(randomstring.c_str()) + 1, randomstring.c_str());
				*nSize = (DWORD)wcslen(randomstring.c_str()) + 1;
				return TRUE;
			}
		}
	}
	return TRUE;
}

HMODULE WINAPI hGetModuleHandleW(const LPCWSTR lpModuleName)
{
	for (const auto& rule : rules_GetModuleHandleW)
	{
		if (StrStrIW(rule[0].c_str(), lpModuleName))
			// FIX NEEDED
			//addLogEntry(std::wstring(converter.from_bytes(__FUNCTION__)).substr(1), lpModuleName, L"RETURN NULL");
			return NULL;
	}
	return oGetModuleHandleW(lpModuleName);
}

std::wstring queryFrom;

HRESULT __stdcall hExecQueryFunc(void* pThis, const BSTR strQueryLanguage, BSTR strQuery, long lFlags, IWbemContext* pCtx, IEnumWbemClassObject** ppEnum)
{
    std::wstring EQ = L"ExecQuery";
    std::wstring Get = L"Get";
    std::wstring queryStr = strQuery;

    int fromPos = queryStr.find(L"FROM");
    if (fromPos != std::wstring::npos) {
        queryFrom = queryStr.substr(fromPos + 5);
    }

    for (const auto& rule : rules_ExecQuery) {
        std::wstring loc_ruleFrom = rule[0];

        if (StrStrIW(queryFrom.c_str(), loc_ruleFrom.c_str()) != NULL) {
            // Create a BSTR and a wstring to concat
            BSTR bstr = SysAllocString(L"Select * From ");
            std::wstring wstr = rule[1];

            // Allocate memory for BSTRs
            BSTR combinedBstr = SysAllocStringLen(bstr, SysStringLen(bstr) + wstr.length());
			addLogEntry(std::wstring(converter.from_bytes(__FUNCTION__)).substr(1), queryStr, L"Changed to Select * From " + wstr);
            // Concatenate BSTR and wstr 
            wcscat_s(combinedBstr, MAX_PATH, wstr.c_str());
            strQuery = combinedBstr;
        }
    }

    HRESULT hResult = oExecQueryFunc(pThis, strQueryLanguage, strQuery, lFlags, pCtx, ppEnum);
    return hResult;
}

HANDLE WINAPI hCreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID) {
	HANDLE hSnapshot = oCreateToolhelp32Snapshot(dwFlags, th32ProcessID);
	if (hSnapshot != INVALID_HANDLE_VALUE) {
		PROCESSENTRY32W pe32 = { 0 };
		pe32.dwSize = sizeof(PROCESSENTRY32W);
		BOOL bSuccess = Process32FirstW(hSnapshot, &pe32);

		while (bSuccess) {
			for (const auto& rule : rules_CreateToolhelp32Snapshot) {
				// Assuming rule[0] is already a wide string. If not, please let me know the type
				const std::wstring& ruleWstr = rule[0];

				if (!StrCmpIW(pe32.szExeFile, ruleWstr.c_str())) {
					// Use random_strings directly since it's already std::wstring
					std::wstring random_string = random_strings[0].substr(0, wcslen(pe32.szExeFile) - 4) + L".exe";

					// Ensure buffer size is sufficient
					if (random_string.length() < MAX_PATH) {
						wcscpy_s(pe32.szExeFile, MAX_PATH, random_string.c_str());
						addLogEntry(std::wstring(converter.from_bytes(__FUNCTION__)).substr(1),
							ruleWstr.c_str(),
							L"Changed to " + random_string);
					}
					break;
				}
			}
			bSuccess = Process32NextW(hSnapshot, &pe32);
		}
	}
	return hSnapshot;
}

HRESULT __stdcall hGetFunc(void* pThis, LPCWSTR wszName, LONG lFlags, VARIANTARG* pValue, LONG type, LONG plFlavor)
{
	HRESULT hResult = oGetFunc(pThis, wszName, lFlags, pValue, type, plFlavor);

	for (const auto& rule : rules_Get)
    {
	    LPCWSTR rule_queryFrom = rule[0].c_str();
	    LPCWSTR queryGet = rule[1].c_str();
    
	    if (StrStrIW(wszName, queryGet) && StrStrIW(queryFrom.c_str(), rule_queryFrom))
	    {
			addLogEntry(std::wstring(converter.from_bytes(__FUNCTION__)).substr(1), L"From " + queryFrom + L" "+ wszName, L"Changed to " + rule[2]);
	    	VariantClear(pValue);
	    	pValue->vt = VT_BSTR;
	    	pValue->bstrVal = SysAllocString(rule[2].c_str());
	    }
		else
		{
			addLogEntry(std::wstring(converter.from_bytes(__FUNCTION__)).substr(1), L"From " + queryFrom + L" " + wszName, L"Changed to same");
		}
    }

return hResult;

}


// Structure for hook configuration
struct HookInfo {
	const wchar_t* dllName;    // DLL containing the target function
	const char* functionName;   // Name of function to hook
	HMODULE* hModule;          // Module handle
	LPVOID* lpFunction;        // Original function pointer
	LPVOID hookFunction;       // Hook function pointer
	LPVOID* originalFunction;  // Storage for original function
};

namespace {
	// Module handles
	HMODULE hKernel32 = nullptr;
	HMODULE hAdvapi32 = nullptr;
	HMODULE hNtdll = nullptr;
	HMODULE hUser32 = nullptr;
	HMODULE hWinmm = nullptr;
	HMODULE hIphlpapi = nullptr;
	HMODULE hSetupapi = nullptr;
	HMODULE hShlwapi = nullptr;

	// Function pointers and originals
	LPVOID lpGetModuleHandleW = NULL;
	LPVOID lpGetUserNameW = NULL;
	LPVOID lpGetComputerNameW = NULL;
	LPVOID lpGetComputerNameA = NULL;
	LPVOID lpGetComputerNameExW = NULL;
	LPVOID lpGetFileAttributesW = NULL;
	LPVOID lpPathFindFileNameW = NULL;
	LPVOID lpNtSystemDebugControl = NULL;
	LPVOID lpNtYieldExecution = NULL;
	LPVOID lpSetHandleInformation = NULL;
	LPVOID lpSetupDiGetDeviceRegistryPropertyW = NULL;
	LPVOID lpEnumServicesStatusExW = NULL;
	LPVOID lpGetDiskFreeSpaceExW = NULL;
	LPVOID lpRegQueryValueExW = NULL;
	LPVOID lpRegEnumKeyExW = NULL;
	LPVOID lpNtDelayExecution = NULL;
	LPVOID lpSetTimer = NULL;
	LPVOID lpTimeSetEvent = NULL;
	LPVOID lpWaitForSingleObject = NULL;
	LPVOID lpIcmpSendEcho = NULL;
	LPVOID lpSetWaitableTimer = NULL;
	LPVOID lpCreateTimerQueueTimer = NULL;
	LPVOID lpCreateToolhelp32Snapshot = NULL;
	LPVOID lpRegOpenKeyExW = NULL;
	LPVOID lpGetSystemFirmwareTable = NULL;
	LPVOID lpEnumSystemFirmwareTables = NULL;
	LPVOID lpCreateFile = NULL;
	LPVOID lpGetAdaptersInfo = NULL;

	// Debug logging helper
#ifdef DEBUG
	void DebugLog(const wchar_t* format, ...) {
		wchar_t buffer[512];
		va_list args;
		va_start(args, format);
		vswprintf_s(buffer, format, args);
		va_end(args);
		OutputDebugStringW(buffer);
	}
#define DEBUG_LOG(...) DebugLog(__VA_ARGS__)
#else
#define DEBUG_LOG(...)
#endif

	// Hook installation helper
	bool InstallHook(const HookInfo& hook) {
		if (*hook.lpFunction != nullptr) {
			return true;  // Hook already installed
		}

		if (*hook.hModule == nullptr) {
			*hook.hModule = GetModuleHandleW(hook.dllName);
			if (*hook.hModule == nullptr) {
				DEBUG_LOG(L"Failed to get handle for %s\n", hook.dllName);
				return false;
			}
		}

		*hook.lpFunction = GetProcAddress(*hook.hModule, hook.functionName);
		if (*hook.lpFunction == nullptr) {
			DEBUG_LOG(L"Failed to get address for %S in %s\n",
				hook.functionName, hook.dllName);
			return false;
		}

		*hook.originalFunction = DetourFunction(
			reinterpret_cast<PBYTE>(*hook.lpFunction),
			reinterpret_cast<PBYTE>(hook.hookFunction)
		);

		DEBUG_LOG(L"Successfully hooked %S in %s\n",
			hook.functionName, hook.dllName);
		return true;
	}

	// WMI hook installation
	bool InstallWMIQueryHooks(HANDLE proc, DWORD64 baseAddr, PVOID lpDLLBase) {
		SYMBOL_INFO symbolInfo = { 0 };
		symbolInfo.SizeOfStruct = sizeof(SYMBOL_INFO);
		symbolInfo.MaxNameLen = MAX_SYM_NAME;

		if (!SymFromName(proc, "CWbemSvcWrapper::XWbemServices::ExecQuery", &symbolInfo)) {
			DEBUG_LOG(L"Failed to find ExecQuery symbol\n");
#ifdef DEBUG
			// Troubleshooting steps for symbol loading issues:
			// 1. Use x32dbg to locate fastprox.dll in exports section
			// 2. Download symbols through x32dbg (right-click -> download symbols)
			// 3. Copy PDB from x32dbg symbols folder to project's Bin folder
			//    Example path: x32dbg_dir/release/x32/symbols/fastprox.pdb/{hash}/fastprox.pdb
			// 4. Below code will enumerate all ExecQuery-related symbols for verification
			if (!SymEnumSymbols(proc, baseAddr, "*ExecQuery*",
				[](PSYMBOL_INFO pSymInfo, ULONG SymbolSize, PVOID UserContext) {
					std::cout << "Symbol found: " << pSymInfo->Name
						<< " at address: " << (void*)pSymInfo->Address << std::endl;
					return TRUE;
				}, NULL)) {
				std::cout << "Error enumerating symbols: " << GetLastError() << std::endl;
			}
			// 5. Cross-reference addresses with x32dbg exports view
			// 6. For assistance: vvelitkn@gmail.com or open GitHub issue
#endif // DEBUG
			return false;
		}

		// Install ExecQuery hook
		LPVOID lpExecQueryFunc = reinterpret_cast<LPVOID>(symbolInfo.Address);
		oExecQueryFunc = reinterpret_cast<tExecQueryFunc>(DetourFunction(
			reinterpret_cast<PBYTE>(lpExecQueryFunc),
			reinterpret_cast<PBYTE>(hExecQueryFunc)));

		// Install Get hook
		LPVOID lpGetFunc = GetProcAddress(reinterpret_cast<HMODULE>(lpDLLBase),
			"?Get@CWbemObject@@UAGJPBGJPAUtagVARIANT@@PAJ2@Z");

		if (lpGetFunc == nullptr) {
			DEBUG_LOG(L"Failed to get Get function address\n");
			return false;
		}

		oGetFunc = reinterpret_cast<tGetFunc>(DetourFunction(
			reinterpret_cast<PBYTE>(lpGetFunc),
			reinterpret_cast<PBYTE>(hGetFunc)));

		return true;
	}

	// WMI hooks setup
	bool InstallWMIHooks(PWSTR lpDLLName, PVOID lpDLLBase) {
		DWORD procID = findMyProc("target.exe");
		HANDLE proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procID);
		if (!proc) {
			DEBUG_LOG(L"Failed to open target process\n");
			return false;
		}

		// Configure and initialize symbol handler
		SymSetOptions(SYMOPT_DEBUG | SYMOPT_LOAD_LINES | SYMOPT_DEFERRED_LOADS |
			SYMOPT_UNDNAME | SYMOPT_LOAD_ANYTHING);

		if (!SymInitialize(proc, NULL, TRUE)) {
			DEBUG_LOG(L"Symbol initialization failed\n");
			CloseHandle(proc);
			return false;
		}

		// Load module symbols
		DWORD64 baseAddr = SymLoadModuleEx(proc, NULL, "fastprox.dll", NULL,
			(DWORD64)lpDLLBase, 0, NULL, 0);
		if (baseAddr == 0) {
			DEBUG_LOG(L"Failed to load module symbols\n");
			SymCleanup(proc);
			CloseHandle(proc);
			return false;
		}

		bool success = InstallWMIQueryHooks(proc, baseAddr, lpDLLBase);

		SymCleanup(proc);
		CloseHandle(proc);
		return success;
	}
}

// Main callback function
VOID NTAPI DllLoadCallback(PWSTR lpDLLName, PVOID lpDLLBase, SIZE_T size, PVOID lpReserved) {
	// Initialize ruleset once
	static bool rulesInitialized = false;
	if (!rulesInitialized) {
		if (!parse_ruleset("ruleset.txt")) {
			DEBUG_LOG(L"Failed to parse ruleset.txt\n");
			return;
		}
		rulesInitialized = true;
	}

	DEBUG_LOG(L"Processing DLL: %s\n", lpDLLName);

	// Define all hooks
	const HookInfo hooks[] = {
		// Kernel32 hooks
		{L"kernel32.dll", "GetModuleHandleW", &hKernel32, &lpGetModuleHandleW,
		 (LPVOID)hGetModuleHandleW, (LPVOID*)&oGetModuleHandleW},
		{L"kernel32.dll", "GetComputerNameW", &hKernel32, &lpGetComputerNameW,
		 (LPVOID)hGetComputerNameW, (LPVOID*)&oGetComputerNameW},
		{L"kernel32.dll", "GetComputerNameA", &hKernel32, &lpGetComputerNameA,
		 (LPVOID)hGetComputerNameA, (LPVOID*)&oGetComputerNameA},
		{L"kernel32.dll", "GetFileAttributesW", &hKernel32, &lpGetFileAttributesW,
		 (LPVOID)hGetFileAttributesW, (LPVOID*)&oGetFileAttributesW},
		{L"kernel32.dll", "PathFindFileNameW", &hKernel32, &lpPathFindFileNameW,
		 (LPVOID)hPathFindFileNameW, (LPVOID*)&oPathFindFileNameW},
		{L"kernel32.dll", "WaitForSingleObject", &hKernel32, &lpWaitForSingleObject,
		 (LPVOID)hWaitForSingleObject, (LPVOID*)&oWaitForSingleObject},
		{L"kernel32.dll", "SetWaitableTimer", &hKernel32, &lpSetWaitableTimer,
		 (LPVOID)hSetWaitableTimer, (LPVOID*)&oSetWaitableTimer},
		{L"kernel32.dll", "CreateTimerQueueTimer", &hKernel32, &lpCreateTimerQueueTimer,
		 (LPVOID)hCreateTimerQueueTimer, (LPVOID*)&oCreateTimerQueueTimer},
		{L"kernel32.dll", "CreateToolhelp32Snapshot", &hKernel32, &lpCreateToolhelp32Snapshot,
		 (LPVOID)hCreateToolhelp32Snapshot, (LPVOID*)&oCreateToolhelp32Snapshot},
		{L"kernel32.dll", "CreateFileW", &hKernel32, &lpCreateFile,
		 (LPVOID)hCreateFile, (LPVOID*)&oCreateFile },
		{L"kernel32.dll", "GetSystemFirmwareTable", &hKernel32, &lpGetSystemFirmwareTable,
		 (LPVOID)hGetSystemFirmwareTable, (LPVOID*)&oGetSystemFirmwareTable },

		// Advapi32 hooks
		{L"advapi32.dll", "GetUserNameW", &hAdvapi32, &lpGetUserNameW,
		 (LPVOID)hGetUserNameW, (LPVOID*)&oGetUserNameW},
		{L"advapi32.dll", "EnumServicesStatusExW", &hAdvapi32, &lpEnumServicesStatusExW,
		 (LPVOID)hEnumServicesStatusExW, (LPVOID*)&oEnumServicesStatusExW},
		{L"advapi32.dll", "RegQueryValueExW", &hAdvapi32, &lpRegQueryValueExW,
		 (LPVOID)hRegQueryValueExW, (LPVOID*)&oRegQueryValueExW},
		{L"advapi32.dll", "RegEnumKeyExW", &hAdvapi32, &lpRegEnumKeyExW,
		 (LPVOID)hRegEnumKeyExW, (LPVOID*)&oRegEnumKeyExW},
		{L"advapi32.dll", "RegOpenKeyExW", &hAdvapi32, &lpRegOpenKeyExW,
		 (LPVOID)hRegOpenKeyExW, (LPVOID*)&oRegOpenKeyExW},

		// Ntdll hooks
		{L"ntdll.dll", "NtSystemDebugControl", &hNtdll, &lpNtSystemDebugControl,
		 (LPVOID)hNtSystemDebugControl, (LPVOID*)&oNtSystemDebugControl},
		{L"ntdll.dll", "NtYieldExecution", &hNtdll, &lpNtYieldExecution,
		 (LPVOID)hNtYieldExecution, (LPVOID*)&oNtYieldExecution},
		{L"ntdll.dll", "NtDelayExecution", &hNtdll, &lpNtDelayExecution,
		 (LPVOID)hNtDelayExecution, (LPVOID*)&oNtDelayExecution},
		
		// Iphlpapi hooks
		{L"Iphlpapi.dll", "IcmpSendEcho", &hIphlpapi, &lpIcmpSendEcho,
		 (LPVOID)hIcmpSendEcho, (LPVOID*)&oIcmpSendEcho},
		 {L"Iphlpapi.dll", "GetAdaptersInfo", &hIphlpapi, &lpGetAdaptersInfo,
		 (LPVOID)hGetAdaptersInfo, (LPVOID*)&oGetAdaptersInfo},

		// User32 hooks
		{L"user32.dll", "SetTimer", &hUser32, &lpSetTimer,
		 (LPVOID)hSetTimer, (LPVOID*)&oSetTimer},

		// Winmm hooks
		{L"winmm.dll", "timeSetEvent", &hWinmm, &lpTimeSetEvent,
		 (LPVOID)hTimeSetEvent, (LPVOID*)&oTimeSetEvent},

		// Setupapi hooks
		{L"setupapi.dll", "SetupDiGetDeviceRegistryPropertyW", &hSetupapi, &lpSetupDiGetDeviceRegistryPropertyW,
		 (LPVOID)hSetupDiGetDeviceRegistryPropertyW, (LPVOID*)&oSetupDiGetDeviceRegistryPropertyW},
	};


	// Install standard hooks
	for (const auto& hook : hooks) {
		InstallHook(hook);
	}

	// Handle WMI hooks separately
	if (wcscmp(lpDLLName, L"fastprox.dll") == 0) {
		if (!InstallWMIHooks(lpDLLName, lpDLLBase)) {
			DEBUG_LOG(L"WMI hook installation failed\n");
		}
	}
}

VOID RegisterProvider(VOID)
{
	RtlSecureZeroMemory(&g_AVRFProvider, sizeof(RTL_VERIFIER_PROVIDER_DESCRIPTOR));
	g_AVRFProvider.Length = sizeof(RTL_VERIFIER_PROVIDER_DESCRIPTOR);
	g_AVRFProvider.ProviderDlls = AVRFDlls;
	g_AVRFProvider.ProviderDllLoadCallback = reinterpret_cast<RTL_VERIFIER_DLL_LOAD_CALLBACK>(&DllLoadCallback);
}

BOOL WINAPI DllMain(PVOID DllHandle, DWORD fdwReason, PRTL_VERIFIER_PROVIDER_DESCRIPTOR* lpDescriptor)
{

	switch (fdwReason)
	{
	case DLL_PROCESS_VERIFIER:
		RegisterProvider();
		*lpDescriptor = &g_AVRFProvider;
		break;
	case DLL_PROCESS_ATTACH:
	case DLL_PROCESS_DETACH:
	default:
		break;
	}

	return TRUE;
}
