#include <iostream>
#include <string>
#include <cstring>
#include <iomanip>
#include <bitset>

#ifdef _WIN32
#include <windows.h>
#include <intrin.h>
#include <winternl.h>
#include <sysinfoapi.h>
#pragma comment(lib, "ntdll.lib")
#else
#include <cpuid.h>
#include <fstream>
#include <unistd.h>
#include <sys/utsname.h>
#endif

#ifdef _WIN32

#pragma pack(push, 1)
struct KSYSTEM_TIME {
    ULONG LowPart;
    LONG  High1Time;
    LONG  High2Time;
};

struct KUSD_MAP {
    ULONG         TickCountLowDeprecated;       // 0x000
    ULONG         TickCountMultiplier;          // 0x004
    KSYSTEM_TIME  InterruptTime;                // 0x008
    KSYSTEM_TIME  SystemTime;                   // 0x014
    KSYSTEM_TIME  TimeZoneBias;                 // 0x020
    USHORT        ImageNumberLow;               // 0x02C
    USHORT        ImageNumberHigh;              // 0x02E
    WCHAR         NtSystemRoot[260];            // 0x030
    ULONG         MaxStackTraceDepth;           // 0x238
    ULONG         CryptoExponent;               // 0x23C
    ULONG         TimeZoneId;                   // 0x240
    ULONG         LargePageMinimum;             // 0x244
    ULONG         AitSamplingValue;             // 0x248
    ULONG         AppCompatFlag;                // 0x24C
    ULONGLONG     RNGSeedVersion;               // 0x250
    ULONG         GlobalValidationRunlevel;     // 0x258
    LONG          TimeZoneBiasStamp;            // 0x25C
    ULONG         NtBuildNumber;                // 0x260
    ULONG         NtProductType;               // 0x264
    BOOLEAN       ProductTypeIsValid;           // 0x268
    UCHAR         Reserved0[3];                 // 0x269
    USHORT        NativeCpuArchitecture;        // 0x26C
    USHORT        NativeCpuRevision;            // 0x26E
    ULONG         MajorVersion;                 // 0x270  (NtMajorVersion)
    ULONG         MinorVersion;                 // 0x274  (NtMinorVersion)
    BOOLEAN       ProcessorFeatures[64];        // 0x278
    ULONG         Reserved1;                    // 0x2B8
    ULONG         Reserved3;                    // 0x2BC
    ULONG         TimeSlip;                     // 0x2C0
    ULONG         AlternativeArchitecture;      // 0x2C4
    ULONG         BootId;                       // 0x2C8
    LARGE_INTEGER SystemExpirationDate;         // 0x2D0  (was SystemExpirationDate)
    ULONG         SuiteMask;                    // 0x2D8
    BOOLEAN       KdDebuggerEnabled;            // 0x2DC
    UCHAR         MitigationPolicies;           // 0x2DD
    USHORT        CyclesPerYield;               // 0x2DE
    ULONG         ActiveConsoleId;              // 0x2E0
    ULONG         DismountCount;                // 0x2E4
    ULONG         ComPlusPackage;               // 0x2E8
    ULONG         LastSystemRITEventTickCount;  // 0x2EC
    ULONG         NumberOfPhysicalPages;        // 0x2F0
    BOOLEAN       SafeBootMode;                 // 0x2F4
    UCHAR         VirtualizationFlags;          // 0x2F5
    UCHAR         Reserved12[2];                // 0x2F6
    ULONG         SharedDataFlags;              // 0x2F8
};
#pragma pack(pop)

struct PEB_MAP {
    BOOLEAN   InheritedAddressSpace;
    BOOLEAN   ReadImageFileExecOptions;
    BOOLEAN   BeingDebugged;
    BOOLEAN   BitField;
    ULONG_PTR Mutant;
    PVOID     ImageBaseAddress;
    PVOID     Ldr;
    PVOID     ProcessParameters;
    PVOID     SubSystemData;
    PVOID     ProcessHeap;
    PVOID     FastPebLock;
    PVOID     AtlThunkSListPtr;
    PVOID     IFEOKey;
    ULONG     CrossProcessFlags;
    PVOID     KernelCallbackTable;
    ULONG     SystemReserved;
    ULONG     AtlThunkSListPtr32;
    PVOID     ApiSetMap;
    ULONG     TlsExpansionCounter;
    PVOID     TlsBitmap;
    ULONG     TlsBitmapBits[2];
    PVOID     ReadOnlySharedMemoryBase;
    PVOID     SharedData;
    PVOID     ReadOnlyStaticServerData;
    PVOID     AnsiCodePageData;
    PVOID     OemCodePageData;
    PVOID     UnicodeCaseTableData;
    ULONG     NumberOfProcessors;
    ULONG     NtGlobalFlag;
    LARGE_INTEGER CriticalSectionTimeout;
    SIZE_T    HeapSegmentReserve;
    SIZE_T    HeapSegmentCommit;
    SIZE_T    HeapDeCommitTotalFreeThreshold;
    SIZE_T    HeapDeCommitFreeBlockThreshold;
    ULONG     NumberOfHeaps;
    ULONG     MaximumNumberOfHeaps;
    PVOID     ProcessHeaps;
    PVOID     GdiSharedHandleTable;
    PVOID     ProcessStarterHelper;
    ULONG     GdiDCAttributeList;
    PVOID     LoaderLock;
    ULONG     OSMajorVersion;
    ULONG     OSMinorVersion;
    USHORT    OSBuildNumber;
    USHORT    OSCSDVersion;
    ULONG     OSPlatformId;
    ULONG     ImageSubsystem;
    ULONG     ImageSubsystemMajorVersion;
    ULONG     ImageSubsystemMinorVersion;
    ULONG_PTR ActiveProcessAffinityMask;
    ULONG     GdiHandleBuffer[60];
    PVOID     PostProcessInitRoutine;
    PVOID     TlsExpansionBitmap;
    ULONG     TlsExpansionBitmapBits[32];
    ULONG     SessionId;
};

#endif

void query_cpuid() {
    std::cout << "\nCPUID : \n";

#ifdef _WIN32
    int info[4];

    __cpuid(info, 0);
    int maxLeaf = info[0];
    char vendor[13] = {};
    memcpy(vendor + 0, &info[1], 4);
    memcpy(vendor + 4, &info[3], 4);
    memcpy(vendor + 8, &info[2], 4);
    std::cout << "Vendor ID                  : " << vendor << "\n";
    std::cout << "Max Basic Leaf             : " << maxLeaf << "\n";

    __cpuid(info, 1);
    int stepping = info[0] & 0xF;
    int model = (info[0] >> 4) & 0xF;
    int family = (info[0] >> 8) & 0xF;
    int extModel = (info[0] >> 16) & 0xF;
    int extFamily = (info[0] >> 20) & 0xFF;
    int effectiveModel = (family == 6 || family == 15) ? (extModel << 4) | model : model;
    int effectiveFamily = (family == 15) ? extFamily + family : family;

    std::cout << "Stepping                   : " << stepping << "\n";
    std::cout << "Base Model                 : " << model << "\n";
    std::cout << "Base Family                : " << family << "\n";
    std::cout << "Extended Model             : " << extModel << "\n";
    std::cout << "Extended Family            : " << extFamily << "\n";
    std::cout << "Effective Model            : " << effectiveModel << "\n";
    std::cout << "Effective Family           : " << effectiveFamily << "\n";

    int logicalProcessors = (info[1] >> 16) & 0xFF;
    int localApicId = (info[1] >> 24) & 0xFF;
    std::cout << "Logical Processors (CPUID) : " << logicalProcessors << "\n";
    std::cout << "Local APIC ID              : " << localApicId << "\n";

    std::cout << "Feature Flags ECX          : 0x" << std::hex << info[2] << std::dec << "\n";
    std::cout << "Feature Flags EDX          : 0x" << std::hex << info[3] << std::dec << "\n";

    bool hasSSE = (info[3] >> 25) & 1;
    bool hasSSE2 = (info[3] >> 26) & 1;
    bool hasHTT = (info[3] >> 28) & 1;
    bool hasSSE3 = (info[2] >> 0) & 1;
    bool hasSSSE3 = (info[2] >> 9) & 1;
    bool hasSSE41 = (info[2] >> 19) & 1;
    bool hasSSE42 = (info[2] >> 20) & 1;
    bool hasAVX = (info[2] >> 28) & 1;
    bool hasAES = (info[2] >> 25) & 1;
    bool hasVMX = (info[2] >> 5) & 1;
    bool hasPCLMUL = (info[2] >> 1) & 1;
    bool hasF16C = (info[2] >> 29) & 1;
    bool hasRDRAND = (info[2] >> 30) & 1;
    std::cout << "SSE                        : " << hasSSE << "\n";
    std::cout << "SSE2                       : " << hasSSE2 << "\n";
    std::cout << "SSE3                       : " << hasSSE3 << "\n";
    std::cout << "SSSE3                      : " << hasSSSE3 << "\n";
    std::cout << "SSE4.1                     : " << hasSSE41 << "\n";
    std::cout << "SSE4.2                     : " << hasSSE42 << "\n";
    std::cout << "AVX                        : " << hasAVX << "\n";
    std::cout << "AES-NI                     : " << hasAES << "\n";
    std::cout << "VMX (VT-x)                 : " << hasVMX << "\n";
    std::cout << "PCLMULQDQ                  : " << hasPCLMUL << "\n";
    std::cout << "F16C                       : " << hasF16C << "\n";
    std::cout << "RDRAND                     : " << hasRDRAND << "\n";
    std::cout << "Hyper-Threading            : " << hasHTT << "\n";

    __cpuid(info, 7);
    bool hasAVX2 = (info[1] >> 5) & 1;
    bool hasBMI1 = (info[1] >> 3) & 1;
    bool hasBMI2 = (info[1] >> 8) & 1;
    bool hasRDSEED = (info[1] >> 18) & 1;
    bool hasADX = (info[1] >> 19) & 1;
    bool hasMPX = (info[1] >> 14) & 1;
    bool hasSHA = (info[1] >> 29) & 1;
    bool hasSGX = (info[1] >> 2) & 1;
    bool hasCET_SS = (info[3] >> 7) & 1;
    std::cout << "AVX2                       : " << hasAVX2 << "\n";
    std::cout << "BMI1                       : " << hasBMI1 << "\n";
    std::cout << "BMI2                       : " << hasBMI2 << "\n";
    std::cout << "RDSEED                     : " << hasRDSEED << "\n";
    std::cout << "ADX                        : " << hasADX << "\n";
    std::cout << "MPX                        : " << hasMPX << "\n";
    std::cout << "SHA                        : " << hasSHA << "\n";
    std::cout << "SGX                        : " << hasSGX << "\n";
    std::cout << "CET Shadow Stack           : " << hasCET_SS << "\n";

    __cpuid(info, 0x80000001);
    bool hasLAHF64 = (info[2] >> 0) & 1;
    bool hasLZCNT = (info[2] >> 5) & 1;
    bool hasPREFW = (info[2] >> 8) & 1;
    bool hasEM64T = (info[3] >> 29) & 1;
    bool hasNX = (info[3] >> 20) & 1;
    bool has1GBPage = (info[3] >> 26) & 1;
    bool hasRDTSCP = (info[3] >> 27) & 1;
    std::cout << "LAHF/SAHF in 64-bit        : " << hasLAHF64 << "\n";
    std::cout << "LZCNT                      : " << hasLZCNT << "\n";
    std::cout << "PREFETCHW                  : " << hasPREFW << "\n";
    std::cout << "EM64T (Long Mode)          : " << hasEM64T << "\n";
    std::cout << "NX / XD Bit                : " << hasNX << "\n";
    std::cout << "1GB Pages                  : " << has1GBPage << "\n";
    std::cout << "RDTSCP                     : " << hasRDTSCP << "\n";

    __cpuid(info, 0x80000008);
    int physBits = info[0] & 0xFF;
    int virtBits = (info[0] >> 8) & 0xFF;
    std::cout << "Physical Address Bits      : " << physBits << "\n";
    std::cout << "Virtual Address Bits       : " << virtBits << "\n";

    char brand[49] = {};
    for (int leaf = 0x80000002, i = 0; leaf <= 0x80000004; ++leaf, i += 16) {
        __cpuid(info, leaf);
        memcpy(brand + i, info, 16);
    }
    std::cout << "CPU Brand                  : " << brand << "\n";

    __cpuid(info, 4);
    int coresPerPackage = ((info[0] >> 26) & 0x3F) + 1;
    std::cout << "Cores Per Package (CPUID4) : " << coresPerPackage << "\n";
#endif
}

#ifdef _WIN32
void kusd_check() {
    std::cout << "\nKUSD : \n";

    const auto* k = reinterpret_cast<const KUSD_MAP*>(
        static_cast<uintptr_t>(0x7FFE0000UL));

    std::wcout << L"NtSystemRoot               : " << k->NtSystemRoot << L"\n";
    std::cout << "NtBuildNumber              : " << k->NtBuildNumber << "\n";
    std::cout << "NtMajorVersion             : " << k->MajorVersion << "\n";
    std::cout << "NtMinorVersion             : " << k->MinorVersion << "\n";
    std::cout << "NtProductType              : ";
    switch (k->NtProductType) {
    case 1: std::cout << "WinNT (Workstation)\n"; break;
    case 2: std::cout << "LanManNT (Server)\n";   break;
    case 3: std::cout << "Server\n";              break;
    default:std::cout << k->NtProductType << "\n";
    }
    std::cout << "ProductTypeIsValid         : " << (int)k->ProductTypeIsValid << "\n";
    std::cout << "TickCountMultiplier        : " << k->TickCountMultiplier << "\n";
    std::cout << "TimeZoneId                 : " << k->TimeZoneId << "\n";
    std::cout << "LargePageMinimum           : " << k->LargePageMinimum << " bytes\n";
    std::cout << "RNGSeedVersion             : " << k->RNGSeedVersion << "\n";
    std::cout << "KdDebuggerEnabled          : " << (int)k->KdDebuggerEnabled << "\n";
    std::cout << "SafeBootMode               : " << (int)k->SafeBootMode << "\n";
    std::cout << "ActiveConsoleId            : " << k->ActiveConsoleId << "\n";
    std::cout << "NumberOfPhysicalPages      : " << k->NumberOfPhysicalPages << "\n";
    std::cout << "SharedDataFlags            : 0x" << std::hex << k->SharedDataFlags << std::dec << "\n";
    std::cout << "SuiteMask                  : 0x" << std::hex << k->SuiteMask << std::dec << "\n";
    std::cout << "MitigationPolicies         : 0x" << std::hex << (int)k->MitigationPolicies << std::dec << "\n";
    std::cout << "BootId                     : " << k->BootId << "\n";
    std::cout << "AlternativeArchitecture    : " << k->AlternativeArchitecture << "\n";
    std::cout << "ImageNumberLow             : 0x" << std::hex << k->ImageNumberLow << std::dec << "\n";
    std::cout << "ImageNumberHigh            : 0x" << std::hex << k->ImageNumberHigh << std::dec << "\n";

    const char* arch = "Unknown";
    switch (k->NativeCpuArchitecture) {
    case 0x0000: arch = "x86";   break;
    case 0x0009: arch = "AMD64"; break;
    case 0x000A: arch = "IA64";  break;
    case 0x000C: arch = "ARM";   break;
    case 0x0012: arch = "ARM64"; break;
    }
    std::cout << "NativeCpuArchitecture      : " << k->NativeCpuArchitecture
        << " (" << arch << ")\n";
    std::cout << "NativeCpuRevision          : 0x" << std::hex << k->NativeCpuRevision << std::dec << "\n";

    std::cout << "\nProcessor Features : \n";
    const char* featureNames[] = {
        "FP", "VME", "DE", "PSE", "TSC", "MSR", "PAE", "MCE",
        "CX8", "APIC", "SEP", "MTRR", "PGE", "MCA", "CMOV", "PAT",
        "PSE36", "PSN", "CLFSH", "DS", "ACPI", "MMX", "FXSR", "SSE",
        "SSE2", "SS", "HTT", "TM", "IA64", "PBE", "SSE3", "CX16",
        "XSAVE", "AVX", "RDRAND", "RDSEED"
    };
    for (int i = 0; i < 36; i++) {
        if (k->ProcessorFeatures[i])
            std::cout << "  [" << std::setw(2) << i << "] " << featureNames[i] << "\n";
    }
}

void peb_check() {
    std::cout << "\nPEB : \n";

    PEB_MAP* peb = reinterpret_cast<PEB_MAP*>(__readgsqword(0x60));

    std::cout << "PEB Address                : 0x" << std::hex << (uintptr_t)peb << std::dec << "\n";
    std::cout << "Being Debugged             : " << (int)peb->BeingDebugged << "\n";
    std::cout << "Image Base Address         : 0x" << std::hex << (uintptr_t)peb->ImageBaseAddress << std::dec << "\n";
    std::cout << "Number of Processors       : " << peb->NumberOfProcessors << "\n";
    std::cout << "NtGlobalFlag               : 0x" << std::hex << peb->NtGlobalFlag << std::dec << "\n";
    std::cout << "OS Major Version           : " << peb->OSMajorVersion << "\n";
    std::cout << "OS Minor Version           : " << peb->OSMinorVersion << "\n";
    std::cout << "OS Build Number            : " << peb->OSBuildNumber << "\n";
    std::cout << "OS CSD Version             : " << peb->OSCSDVersion << "\n";
    std::cout << "OS Platform Id             : " << peb->OSPlatformId << "\n";
    std::cout << "Session ID                 : " << peb->SessionId << "\n";
    std::cout << "Image Subsystem            : " << peb->ImageSubsystem << "\n";
    std::cout << "Image Subsystem Major Ver  : " << peb->ImageSubsystemMajorVersion << "\n";
    std::cout << "Image Subsystem Minor Ver  : " << peb->ImageSubsystemMinorVersion << "\n";
    std::cout << "Cross Process Flags        : 0x" << std::hex << peb->CrossProcessFlags << std::dec << "\n";
    std::cout << "Number of Heaps            : " << peb->NumberOfHeaps << "\n";
    std::cout << "Max Number of Heaps        : " << peb->MaximumNumberOfHeaps << "\n";
    std::cout << "TLS Expansion Counter      : " << peb->TlsExpansionCounter << "\n";
    std::cout << "Heap Segment Reserve       : " << peb->HeapSegmentReserve << " bytes\n";
    std::cout << "Heap Segment Commit        : " << peb->HeapSegmentCommit << " bytes\n";
}

void system_info_check() {
    std::cout << "\nSystem info :\n";

    SYSTEM_INFO si;
    GetSystemInfo(&si);

    const char* archStr = "Unknown";
    switch (si.wProcessorArchitecture) {
    case PROCESSOR_ARCHITECTURE_AMD64:  archStr = "x64 (AMD64)"; break;
    case PROCESSOR_ARCHITECTURE_ARM:    archStr = "ARM";         break;
    case PROCESSOR_ARCHITECTURE_ARM64:  archStr = "ARM64";       break;
    case PROCESSOR_ARCHITECTURE_IA64:   archStr = "IA64";        break;
    case PROCESSOR_ARCHITECTURE_INTEL:  archStr = "x86";         break;
    }
    std::cout << "Processor Architecture     : " << archStr << "\n";
    std::cout << "Processor Type             : " << si.dwProcessorType << "\n";
    std::cout << "Processor Level            : " << si.wProcessorLevel << "\n";
    std::cout << "Processor Revision         : 0x" << std::hex << si.wProcessorRevision << std::dec << "\n";
    std::cout << "Number of Processors       : " << si.dwNumberOfProcessors << "\n";
    std::cout << "Page Size                  : " << si.dwPageSize << " bytes\n";
    std::cout << "Allocation Granularity     : " << si.dwAllocationGranularity << " bytes\n";
    std::cout << "Min Application Address    : 0x" << std::hex << (uintptr_t)si.lpMinimumApplicationAddress << std::dec << "\n";
    std::cout << "Max Application Address    : 0x" << std::hex << (uintptr_t)si.lpMaximumApplicationAddress << std::dec << "\n";
    std::cout << "Active Processor Mask      : 0x" << std::hex << si.dwActiveProcessorMask << std::dec << "\n";

    MEMORYSTATUSEX ms;
    ms.dwLength = sizeof(ms);
    GlobalMemoryStatusEx(&ms);
    std::cout << "Memory Load                : " << ms.dwMemoryLoad << "%\n";
    std::cout << "Total Physical Memory      : " << (ms.ullTotalPhys / (1024 * 1024)) << " MB\n";
    std::cout << "Available Physical Memory  : " << (ms.ullAvailPhys / (1024 * 1024)) << " MB\n";
    std::cout << "Total Virtual Memory       : " << (ms.ullTotalVirtual / (1024 * 1024)) << " MB\n";
    std::cout << "Available Virtual Memory   : " << (ms.ullAvailVirtual / (1024 * 1024)) << " MB\n";
    std::cout << "Total Page File            : " << (ms.ullTotalPageFile / (1024 * 1024)) << " MB\n";
    std::cout << "Available Page File        : " << (ms.ullAvailPageFile / (1024 * 1024)) << " MB\n";
}

void os_check() {
    std::cout << "\nOS ID : \n";

    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {

        auto readStr = [&](const wchar_t* name) -> std::wstring {
            wchar_t buf[256] = {};
            DWORD sz = sizeof(buf);
            RegQueryValueExW(hKey, name, nullptr, nullptr, (LPBYTE)buf, &sz);
            return buf;
            };
        auto readDword = [&](const wchar_t* name) -> DWORD {
            DWORD val = 0, sz = sizeof(DWORD);
            RegQueryValueExW(hKey, name, nullptr, nullptr, (LPBYTE)&val, &sz);
            return val;
            };

        std::wcout << L"ProductName                : " << readStr(L"ProductName") << L"\n";
        std::wcout << L"EditionID                  : " << readStr(L"EditionID") << L"\n";
        std::wcout << L"DisplayVersion             : " << readStr(L"DisplayVersion") << L"\n";
        std::wcout << L"ReleaseId                  : " << readStr(L"ReleaseId") << L"\n";
        std::wcout << L"BuildLab                   : " << readStr(L"BuildLab") << L"\n";
        std::wcout << L"BuildLabEx                 : " << readStr(L"BuildLabEx") << L"\n";
        std::wcout << L"RegisteredOwner            : " << readStr(L"RegisteredOwner") << L"\n";
        std::wcout << L"RegisteredOrganization     : " << readStr(L"RegisteredOrganization") << L"\n";
        std::wcout << L"InstallationType           : " << readStr(L"InstallationType") << L"\n";
        std::cout << "UBR (Update Build Revision): " << readDword(L"UBR") << "\n";
        std::cout << "CurrentMajorVersionNumber  : " << readDword(L"CurrentMajorVersionNumber") << "\n";
        std::cout << "CurrentMinorVersionNumber  : " << readDword(L"CurrentMinorVersionNumber") << "\n";

        RegCloseKey(hKey);
    }
}

void firmware_check() {
    std::cout << "\nFirmware and BIOS ID :\n";

    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"HARDWARE\\DESCRIPTION\\System\\BIOS", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {

        auto readStr = [&](const wchar_t* name) -> std::wstring {
            wchar_t buf[256] = {};
            DWORD sz = sizeof(buf);
            RegQueryValueExW(hKey, name, nullptr, nullptr, (LPBYTE)buf, &sz);
            return buf;
            };

        std::wcout << L"BIOSVendor                 : " << readStr(L"BIOSVendor") << L"\n";
        std::wcout << L"BIOSVersion                : " << readStr(L"BIOSVersion") << L"\n";
        std::wcout << L"BIOSReleaseDate            : " << readStr(L"BIOSReleaseDate") << L"\n";
        std::wcout << L"SystemManufacturer         : " << readStr(L"SystemManufacturer") << L"\n";
        std::wcout << L"SystemProductName          : " << readStr(L"SystemProductName") << L"\n";
        std::wcout << L"SystemFamily               : " << readStr(L"SystemFamily") << L"\n";
        std::wcout << L"SystemVersion              : " << readStr(L"SystemVersion") << L"\n";
        std::wcout << L"BaseBoardManufacturer      : " << readStr(L"BaseBoardManufacturer") << L"\n";
        std::wcout << L"BaseBoardProduct           : " << readStr(L"BaseBoardProduct") << L"\n";
        std::wcout << L"BaseBoardVersion           : " << readStr(L"BaseBoardVersion") << L"\n";

        RegCloseKey(hKey);
    }
}

void computer_check() {
    std::cout << "\nUser Identity :\n";

    wchar_t buf[256];
    DWORD sz = 256;

    GetComputerNameExW(ComputerNameDnsHostname, buf, &sz); std::wcout << L"DNS Hostname               : " << buf << L"\n"; sz = 256;
    GetComputerNameExW(ComputerNameDnsDomain, buf, &sz); std::wcout << L"DNS Domain                 : " << buf << L"\n"; sz = 256;
    GetComputerNameExW(ComputerNameNetBIOS, buf, &sz); std::wcout << L"NetBIOS Name               : " << buf << L"\n"; sz = 256;
    GetComputerNameExW(ComputerNameDnsFullyQualified, buf, &sz); std::wcout << L"FQDN                       : " << buf << L"\n"; sz = 256;

    wchar_t user[256]; DWORD usersz = 256;
    GetUserNameW(user, &usersz);
    std::wcout << L"Current User               : " << user << L"\n";

    DWORD pid = GetCurrentProcessId();
    std::cout << "Current PID                : " << pid << "\n";
}
#endif

int main() {
    std::cout << "Hardware ID :\n";


    query_cpuid();

#ifdef _WIN32
    kusd_check();
    peb_check();
    system_info_check();
    os_check();
    firmware_check();
    computer_check();
#endif

    std::cout << "\n";
    std::cout << "Done.\n";
    return 0;
}
