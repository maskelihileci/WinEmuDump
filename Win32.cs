using System;
using System.Runtime.InteropServices;


namespace WinEmuDump
{
    internal class Win32
    {
        ///////////////// WINDOWS CONSTANTS /////////////////
        public const uint TIME_ZONE_ID_UNKNOWN = 0;
        public const uint TIME_ZONE_ID_STANDARD = 1;
        public const uint TIME_ZONE_ID_DAYLIGHT = 2;
        public const int MAX_PATH = 260;

/// <summary>
        /// Include just the information necessary to capture stack traces for all existing threads in a process.
        /// </summary>
        public const uint MiniDumpNormal = 0x00000000;
        /// <summary>
        /// Include the data sections from all loaded modules. This results in the inclusion of global variables, which can make the minidump file significantly larger.
        /// </summary>
        public const uint MiniDumpWithDataSegs = 0x00000001;
        /// <summary>
        /// Include all accessible memory in the process. The raw memory data is included at the end, so that the initial structures can be mapped directly without the raw memory information. This option can result in a very large file.
        /// </summary>
        public const uint MiniDumpWithFullMemory = 0x00000002;
        /// <summary>
        /// Include high-level information about the operating system handles that are active when the minidump is made.
        /// </summary>
        public const uint MiniDumpWithHandleData = 0x00000004;
        /// <summary>
        /// Stack and backing store memory written to the minidump file should be filtered to remove all but the pointer values necessary to reconstruct a stack trace.
        /// </summary>
        public const uint MiniDumpFilterMemory = 0x00000008;
        /// <summary>
        /// Stack and backing store memory should be scanned for pointer references to modules in the module list.
        /// </summary>
        public const uint MiniDumpScanMemory = 0x00000010;
        /// <summary>
        /// Include information from the list of modules that were recently unloaded, if this information is maintained by the operating system.
        /// </summary>
        /// <remarks>
        /// Windows Server 2003 and Windows XP:  The operating system does not maintain information for unloaded modules until Windows Server 2003 with SP1 and Windows XP with SP2.
        /// DbgHelp 5.1:  This value is not supported.
        /// </remarks>
        public const uint MiniDumpWithUnloadedModules = 0x00000020;
        /// <summary>
        /// Include pages with data referenced by locals or other stack memory. This option can increase the size of the minidump file significantly.
        /// </summary>
        /// <remarks>DbgHelp 5.1:  This value is not supported.</remarks>
        public const uint MiniDumpWithIndirectlyReferencedMemory = 0x00000040;
        /// <summary>
        /// Filter module paths for information such as user names or important directories. This option may prevent the system from locating the image file and should be used only in special situations.
        /// </summary>
        /// <remarks>DbgHelp 5.1:  This value is not supported.</remarks>
        public const uint MiniDumpFilterModulePaths = 0x00000080;
        /// <summary>
        /// Include complete per-process and per-thread information from the operating system.
        /// </summary>
        /// <remarks>DbgHelp 5.1:  This value is not supported.</remarks>
        public const uint MiniDumpWithProcessThreadData = 0x00000100;
        /// <summary>
        /// Scan the virtual address space for PAGE_READWRITE memory to be included.
        /// </summary>
        /// <remarks>DbgHelp 5.1:  This value is not supported.</remarks>
        public const uint MiniDumpWithPrivateReadWriteMemory = 0x00000200;
        /// <summary>
        /// Reduce the data that is dumped by eliminating memory regions that are not essential to meet criteria specified for the dump. This can avoid dumping memory that may contain data that is private to the user. However, it is not a guarantee that no private information will be present.
        /// </summary>
        /// <remarks>DbgHelp 6.1 and earlier:  This value is not supported.</remarks>
        public const uint MiniDumpWithoutOptionalData = 0x00000400;
        /// <summary>
        /// Include memory region information.
        /// </summary>
        /// <remarks>DbgHelp 6.1 and earlier:  This value is not supported.</remarks>
        public const uint MiniDumpWithFullMemoryInfo = 0x00000800;
        /// <summary>
        /// Include thread state information.
        /// </summary>
        /// <remarks>DbgHelp 6.1 and earlier:  This value is not supported.</remarks>
        public const uint MiniDumpWithThreadInfo = 0x00001000;
        /// <summary>
        /// Include all code and code-related sections from loaded modules to capture executable content.
        /// </summary>
        /// <remarks>DbgHelp 6.1 and earlier:  This value is not supported.</remarks>
        public const uint MiniDumpWithCodeSegs = 0x00002000;
        /// <summary>
        /// Turns off secondary auxiliary-supported memory gathering.
        /// </summary>
        public const uint MiniDumpWithoutAuxiliaryState = 0x00004000;
        /// <summary>
        /// Requests that auxiliary data providers include their state in the dump image; the state data that is included is provider dependent. This option can result in a large dump image.
        /// </summary>
        public const uint MiniDumpWithFullAuxiliaryState = 0x00008000;
        /// <summary>
        /// Scans the virtual address space for PAGE_WRITECOPY memory to be included.
        /// </summary>
        /// <remarks>Prior to DbgHelp 6.1:  This value is not supported.</remarks>
        public const uint MiniDumpWithPrivateWriteCopyMemory = 0x00010000;
        /// <summary>
        /// If you specify MiniDumpWithFullMemory, the MiniDumpWriteDump function will fail if the function cannot read the memory regions; however, if you include MiniDumpIgnoreInaccessibleMemory, the MiniDumpWriteDump function will ignore the memory read failures and continue to generate the dump. Note that the inaccessible memory regions are not included in the dump.
        /// </summary>
        /// <remarks>Prior to DbgHelp 6.1:  This value is not supported.</remarks>
        public const uint MiniDumpIgnoreInaccessibleMemory = 0x00020000;
        /// <summary>
        /// Adds security token related data. This will make the "!token" extension work when processing a user-mode dump.
        /// </summary>
        /// <remarks>Prior to DbgHelp 6.1:  This value is not supported.</remarks>
        public const uint MiniDumpWithTokenInformation = 0x00040000;
        /// <summary>
        /// Adds module header related data.
        /// </summary>
        /// <remarks>Prior to DbgHelp 6.1:  This value is not supported.</remarks>
        public const uint MiniDumpWithModuleHeaders = 0x00080000;
        /// <summary>
        /// Adds filter triage related data.
        /// </summary>
        /// <remarks>Prior to DbgHelp 6.1:  This value is not supported.</remarks>
        public const uint MiniDumpFilterTriage = 0x00100000;

        public const uint MiniDumpWithAvxXStateContext = 0x00200000;
        public const uint MiniDumpWithIptTrace = 0x00400000;
        public const uint MiniDumpValidTypeFlags = 0x007fffff;

        // SuiteMask Constants
        public const ushort VER_SUITE_SINGLE_USERTS = 0x0001;
        public const ushort VER_SUITE_SMALLBUSINESS_RESTRICTED = 0x0002;
        public const ushort VER_SUITE_SMALLBUSINESS = 0x0004;
        public const ushort VER_SUITE_EMBEDDED_NT = 0x0008;
        public const ushort VER_SUITE_BACKOFFICE = 0x0010;
        public const ushort VER_SUITE_COMMUNICATIONS = 0x0020;
        public const ushort VER_SUITE_TERMINAL = 0x0040;
        public const ushort VER_SUITE_SMALLBUSINESS_RESTRICED = 0x0080;
        public const ushort VER_SUITE_BLADE = 0x0200;
        public const ushort VER_SUITE_EMBEDDED_RESTRICTED = 0x0400;
        public const ushort VER_SUITE_SECURITY_APPLIANCE = 0x0800;
        public const ushort VER_SUITE_MULTIUSER_TERMINAL = 0x1000;
        public const ushort VER_SUITE_MULTICORE_PRO = 0x2000;

        ///////////////// CONSTANTS /////////////////
        public const int MEM_COMMIT = 0x00001000;
        public const int PAGE_NOACCESS = 0x01;
        public const uint PROCESS_QUERY_INFORMATION = 0x0400;
        public const uint PROCESS_VM_READ = 0x0010;
        public const uint PROCESS_DUP_HANDLE = 0x0040;
        public const uint PROCESS_VM_OPERATION = 0x0008;
        public const uint MemoryBasicInformation = 0;
        public const uint TOKEN_ADJUST_PRIVILEGES = 0x00000020;
        public const uint TOKEN_QUERY = 0x00000008;
        public const uint THREAD_QUERY_INFORMATION = 0x0040;
        public const uint THREAD_GET_CONTEXT = 0x0008;
        public const uint SystemHandleInformation = 16;
        public const uint SystemProcessInformation = 5;
        public const uint SystemMemoryInformation = 0x0035;
        public const uint SystemInformationClass = 0x00B5;
        public const uint SystemObjectTypesInformation = 0x00B6; // OBJECT_TYPES_INFORMATION için

        // Minidump Stream Type Constants
        public const uint MINIDUMP_STREAM_TYPE_ThreadList = 3;
        public const uint MINIDUMP_STREAM_TYPE_ModuleList = 4;
        public const uint MINIDUMP_STREAM_TYPE_MemoryList = 5;
        public const uint MINIDUMP_STREAM_TYPE_Exception = 6;
        public const uint MINIDUMP_STREAM_TYPE_SystemInfo = 7;
        public const uint MINIDUMP_STREAM_TYPE_ThreadExList = 8;
        public const uint MINIDUMP_STREAM_TYPE_Memory64List = 9;
        public const uint MINIDUMP_STREAM_TYPE_CommentA = 10;
        public const uint MINIDUMP_STREAM_TYPE_CommentW = 11;
        public const uint MINIDUMP_STREAM_TYPE_HandleData = 12;
        public const uint MINIDUMP_STREAM_TYPE_FunctionTable = 13;
        public const uint MINIDUMP_STREAM_TYPE_UnloadedModuleList = 14;
        public const uint MINIDUMP_STREAM_TYPE_MiscInfo = 15;
        public const uint MINIDUMP_STREAM_TYPE_MemoryInfoList = 16;
        public const uint MINIDUMP_STREAM_TYPE_ThreadInfoList = 17;
        public const uint MINIDUMP_STREAM_TYPE_HandleOperationList = 18;
        public const uint MINIDUMP_STREAM_TYPE_Token = 19;
        public const uint MINIDUMP_STREAM_TYPE_JavaScriptData = 20;
        public const uint MINIDUMP_STREAM_TYPE_SystemMemoryInfo = 21;
        public const uint MINIDUMP_STREAM_TYPE_ProcessVmCounters = 22;
        public const uint MINIDUMP_STREAM_TYPE_IptTrace = 23;
        public const uint MINIDUMP_STREAM_TYPE_ThreadNames = 24;



        ///////////////// FUNCTIONS /////////////////
        // DllImport functions have been moved to separate files:
        // - NativeApi.cs (NT DLL functions)
        // - Kernel32Api.cs (Kernel32 DLL functions)
        // - PsApi.cs (PSAPI DLL functions)
        
        // THREADINFOCLASS enum (sadece ihtiyacımız olan)
        public const uint ThreadBasicInformation = 0;
        public const uint ThreadStackInformation = 5;
        public const uint ThreadNameInformation = 0x24;

        /// <summary>
        /// THREAD_BASIC_INFORMATION yapısı - Thread temel bilgileri için
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct THREAD_BASIC_INFORMATION
        {
            public uint ExitStatus;
            public IntPtr TebBaseAddress;
            public CLIENT_ID ClientId;
            public IntPtr AffinityMask;
            public uint Priority;
            public uint BasePriority;
        }

        /// <summary>
        /// THREAD_STACK_INFORMATION yapısı - Thread stack bilgileri için
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct THREAD_STACK_INFORMATION
        {
            public IntPtr StackBase;
            public IntPtr StackLimit;
            public IntPtr StackCommit;
            public IntPtr StackCommitMax;
            public IntPtr StackReserved;
        }

        ///////////////// MEMORY STATUS STRUCTS /////////////////

        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORYSTATUSEX
        {
            public uint dwLength;
            public uint dwMemoryLoad;
            public ulong ullTotalPhys;
            public ulong ullAvailPhys;
            public ulong ullTotalPageFile;
            public ulong ullAvailPageFile;
            public ulong ullTotalVirtual;
            public ulong ullAvailVirtual;
            public ulong sullAvailExtendedVirtual;
        }

        // DllImport functions have been moved to separate files:
        // - NativeApi.cs (NT DLL functions)
        // - Kernel32Api.cs (Kernel32 DLL functions)
        // - PsApi.cs (PSAPI DLL functions)

        ///////////////// PE PARSING FUNCTIONS FOR FUNCTION TABLE /////////////////

        ///////////////// TIME ZONE STRUCT /////////////////
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct TIME_ZONE_INFORMATION
        {
            public int Bias;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
            public string StandardName;
            public SYSTEMTIME StandardDate;
            public int StandardBias;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
            public string DaylightName;
            public SYSTEMTIME DaylightDate;
            public int DaylightBias;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SYSTEMTIME
        {
            public short Year;
            public short Month;
            public short DayOfWeek;
            public short Day;
            public short Hour;
            public short Minute;
            public short Second;
            public short Milliseconds;
        }

        
        ///////////////// STRUCTS /////////////////
        [StructLayout(LayoutKind.Sequential)]
        public struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_PRIVILEGES
        {
            public uint PrivilegeCount;
            public LUID Luid;
            public uint Attributes;
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public int AllocationProtect;
            public IntPtr RegionSize;
            public int State;
            public int Protect;
            public int Type;
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct CLIENT_ID
        {
            public IntPtr UniqueProcess;
            public IntPtr UniqueThread;
        }

        /// <summary>
        /// PROCESS_BASIC_INFORMATION yapısı - Process bilgileri için
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr Reserved1;
            public IntPtr PebBaseAddress;
            public IntPtr Reserved2;
            public IntPtr Reserved3;
            public IntPtr UniqueProcessId;
            public IntPtr Reserved4;
        }


        [StructLayout(LayoutKind.Sequential, Pack = 0)]
        public struct OBJECT_ATTRIBUTES
        {
            public int Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct OSVERSIONINFOEX
        {
            public int dwOSVersionInfoSize;
            public int dwMajorVersion;
            public int dwMinorVersion;
            public int dwBuildNumber;
            public int dwPlatformId;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
            public string szCSDVersion;
            public short wServicePackMajor;
            public short wServicePackMinor;
            public short wSuiteMask;
            public byte wProductType;
            public byte wReserved;
        }



        ////////////// STRUCTS - Minidump file //////////
        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct MinidumpHeader
        {
            public uint Signature;
            public uint Version;
            public uint NumberOfStreams;
            public uint StreamDirectoryRva;
            public uint CheckSum;
            public uint TimeDateStamp;
            public ulong Flags;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MinidumpStreamDirectoryEntry
        {
            public uint StreamType;
            public uint Size;
            public uint Location;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode, Pack = 2)]
        public struct CUSTOM_UNICODE_STRING
        {
            public uint Length;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 31)]
            public string Buffer;
        }

        // MINIDUMP_SYSTEM_INFO - Doğru yapı (DbgHelp uyumlu)
        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct MINIDUMP_SYSTEM_INFO
        {
            public ushort ProcessorArchitecture;
            public ushort ProcessorLevel;
            public ushort ProcessorRevision;
            public byte NumberOfProcessors;
            public byte ProductType;
            public uint MajorVersion;
            public uint MinorVersion;
            public uint BuildNumber;
            public uint PlatformId;
            public uint CSDVersionRva;      // RVA to CSD version string
            public ushort SuiteMask;
            public ushort Reserved2;
            public CPU_INFORMATION Cpu;
        }

        // CPU_INFORMATION union
        [StructLayout(LayoutKind.Explicit, Pack = 4)]
        public struct CPU_INFORMATION
        {
            // X86 CPU Info
            [FieldOffset(0)]
            public uint VendorId0;
            [FieldOffset(4)]
            public uint VendorId1;
            [FieldOffset(8)]
            public uint VendorId2;
            [FieldOffset(12)]
            public uint VersionInformation;
            [FieldOffset(16)]
            public uint FeatureInformation;
            [FieldOffset(20)]
            public uint AMDExtendedCpuFeatures;
            
            // Other CPU Info (x64, ARM, etc.)
            [FieldOffset(0)]
            public ulong ProcessorFeatures0;
            [FieldOffset(8)]
            public ulong ProcessorFeatures1;
        }

        // SystemInfoStream - Geçici veri toplama yapısı (eski uyumluluk için)
        [StructLayout(LayoutKind.Sequential)]
        public struct SystemInfoStream
        {
            public ushort ProcessorArchitecture;
            public ushort ProcessorLevel;
            public ushort ProcessorRevision;
            public byte NumberOfProcessors;
            public byte ProductType;
            public uint MajorVersion;
            public uint MinorVersion;
            public uint BuildNumber;
            public uint PlatformId;
            public uint CSDVersionRva;
            public ushort SuiteMask;
            public ushort Reserved2;
            public ulong ProcessorFeatures0;
            public ulong ProcessorFeatures1;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 2)]
        public struct ModuleListStream
        {
            public uint NumberOfModules;
            public IntPtr BaseAddress;
            public uint Size;
            public uint UnknownField1;
            public uint Timestamp;
            public uint PointerName;
            public IntPtr UnknownField2;
            public IntPtr UnknownField3;
            public IntPtr UnknownField4;
            public IntPtr UnknownField5;
            public IntPtr UnknownField6;
            public IntPtr UnknownField7;
            public IntPtr UnknownField8;
            public IntPtr UnknownField9;
            public IntPtr UnknownField10;
            public IntPtr UnknownField11;
        }

        // MINIDUMP_MEMORY_DESCRIPTOR64 - Correct structure for Memory64List
        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct MINIDUMP_MEMORY_DESCRIPTOR64
        {
            public UInt64 StartOfMemoryRange;
            public UInt64 DataSize;
        }

        // Memory64Info - Backward compatibility structure
        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct Memory64Info
        {
            public ulong StartOfMemoryRange;
            public MINIDUMP_LOCATION_DESCRIPTOR Memory;
        }

        // Memory64ListStream - Backward compatibility structure
        [StructLayout(LayoutKind.Sequential)]
        public struct Memory64ListStream
        {
            public ulong NumberOfEntries;
            public uint MemoryRegionsBaseAddress;
        }

        // MINIDUMP_MEMORY64_LIST - Correct structure for Memory64List stream
        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct MINIDUMP_MEMORY64_LIST
        {
            public UInt64 NumberOfMemoryRanges;
            public UInt64 BaseRva;
        }

        ///////////////// EXTENDED STRUCTS FOR ADVANCED MINIDUMP /////////////////

        [StructLayout(LayoutKind.Sequential)]
        public struct SYSTEM_HANDLE_TABLE_ENTRY_INFO
        {
            public ushort UniqueProcessId;
            public ushort CreatorBackTraceIndex;
            public byte ObjectTypeIndex;
            public byte HandleAttributes;
            public ushort HandleValue;
            public IntPtr Object;
            public uint GrantedAccess;
            public ushort CreatorBackTraceIndex2; // Windows 7+ için ek alan
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SYSTEM_HANDLE_INFORMATION
        {
            public uint NumberOfHandles;
            public SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SYSTEM_PROCESS_INFORMATION
        {
            public uint NextEntryOffset;
            public uint NumberOfThreads;
            public long WorkingSetPrivateSize;
            public uint HardFaultCount;
            public uint NumberOfThreadsHighWatermark;
            public ulong CycleTime;
            public long CreateTime;
            public long UserTime;
            public long KernelTime;
            public UNICODE_STRING ImageName;
            public int BasePriority;
            public IntPtr UniqueProcessId;
            public IntPtr InheritedFromUniqueProcessId;
            public uint HandleCount;
            public uint SessionId;
            public IntPtr UniqueProcessKey;
            public IntPtr PeakVirtualSize;
            public IntPtr VirtualSize;
            public uint PageFaultCount;
            public IntPtr PeakWorkingSetSize;
            public IntPtr WorkingSetSize;
            public IntPtr QuotaPeakPagedPoolUsage;
            public IntPtr QuotaPagedPoolUsage;
            public IntPtr QuotaPeakNonPagedPoolUsage;
            public IntPtr QuotaNonPagedPoolUsage;
            public IntPtr PagefileUsage;
            public IntPtr PeakPagefileUsage;
            public IntPtr PrivatePageCount;
            public long ReadOperationCount;
            public long WriteOperationCount;
            public long OtherOperationCount;
            public long ReadTransferCount;
            public long WriteTransferCount;
            public long OtherTransferCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        // OBJECT_TYPES_INFORMATION - Object type'larını listeler
        [StructLayout(LayoutKind.Sequential)]
        public struct OBJECT_TYPES_INFORMATION
        {
            public uint NumberOfTypes;
            // OBJECT_TYPE_INFORMATION structs takip eder (variable length)
        }

        // OBJECT_TYPE_INFORMATION - Tek bir object type bilgisi (SystemObjectTypesInformation için)
        [StructLayout(LayoutKind.Sequential)]
        public struct OBJECT_TYPE_INFORMATION
        {
            public UNICODE_STRING TypeName;
            public uint TotalNumberOfObjects;
            public uint TotalNumberOfHandles;
            public uint HighWaterNumberOfObjects;
            public uint HighWaterNumberOfHandles;
            public uint InvalidAttributes;
            public GENERIC_MAPPING GenericMapping;
            public uint ValidAccessMask;
            public uint SecurityRequired;
            public uint MaintainHandleCount;
            public uint PoolType;
            public uint PagedPoolUsage;
            public uint NonPagedPoolUsage;
        }

        // GENERIC_MAPPING - Generic access mapping
        [StructLayout(LayoutKind.Sequential)]
        public struct GENERIC_MAPPING
        {
            public uint GenericRead;
            public uint GenericWrite;
            public uint GenericExecute;
            public uint GenericAll;
        }

        // CONTEXT yapı sabitleri
        public const uint CONTEXT_AMD64 = 0x100000;
        public const uint CONTEXT_CONTROL = (CONTEXT_AMD64 | 0x1);
        public const uint CONTEXT_INTEGER = (CONTEXT_AMD64 | 0x2);
        public const uint CONTEXT_SEGMENTS = (CONTEXT_AMD64 | 0x4);
        public const uint CONTEXT_FLOATING_POINT = (CONTEXT_AMD64 | 0x8);
        public const uint CONTEXT_DEBUG_REGISTERS = (CONTEXT_AMD64 | 0x10);
        public const uint CONTEXT_FULL = (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT);

        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        public struct CONTEXT
        {
            //
            // Register parameter home addresses.
            //
            // N.B. These fields are for convience - they could be used to extend the
            //      context record in the future.
            //

            public ulong P1Home;
            public ulong P2Home;
            public ulong P3Home;
            public ulong P4Home;
            public ulong P5Home;
            public ulong P6Home;

            //
            // Control flags.
            //

            public uint ContextFlags;
            public uint MxCsr;

            //
            // Segment Registers and processor flags.
            //

            public ushort SegCs;
            public ushort SegDs;
            public ushort SegEs;
            public ushort SegFs;
            public ushort SegGs;
            public ushort SegSs;
            public uint EFlags;

            //
            // Debug registers
            //

            public ulong Dr0;
            public ulong Dr1;
            public ulong Dr2;
            public ulong Dr3;
            public ulong Dr6;
            public ulong Dr7;

            //
            // Integer registers.
            //

            public ulong Rax;
            public ulong Rcx;
            public ulong Rdx;
            public ulong Rbx;
            public ulong Rsp;
            public ulong Rbp;
            public ulong Rsi;
            public ulong Rdi;
            public ulong R8;
            public ulong R9;
            public ulong R10;
            public ulong R11;
            public ulong R12;
            public ulong R13;
            public ulong R14;
            public ulong R15;

            //
            // Program counter.
            //

            public ulong Rip;

            //
            // Floating point state.
            //

            public XSAVE_FORMAT FltSave;

            //
            // Vector registers.
            //

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 26)]
            public M128A[] VectorRegister;
            public ulong VectorControl;
            public ulong DebugControl;
            public ulong LastBranchToRip;
            public ulong LastBranchFromRip;
            public ulong LastExceptionToRip;
            public ulong LastExceptionFromRip;
        }

        // x64 specific structures
        [StructLayout(LayoutKind.Sequential)]
        public struct M128A
        {
            public ulong Low;
            public long High;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct XSAVE_FORMAT
        {
            public ushort ControlWord;
            public ushort StatusWord;
            public byte TagWord;
            public byte Reserved1;
            public ushort ErrorOpcode;
            public uint ErrorOffset;
            public uint ErrorSelector;
            public uint DataOffset;
            public uint DataSelector;
            public uint MXCsr;
            public uint MXCsr_Mask;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public M128A[] FloatRegisters;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public M128A[] XmmRegisters;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 96)]
            public byte[] Reserved4;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct FLOATING_SAVE_AREA
        {
            public uint ControlWord;
            public uint StatusWord;
            public uint TagWord;
            public uint ErrorOffset;
            public uint ErrorSelector;
            public uint DataOffset;
            public uint DataSelector;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 80)]
            public byte[] RegisterArea;
            public uint Cr0NpxState;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SYSTEM_INFO
        {
            public uint dwOemId;
            public uint dwPageSize;
            public IntPtr lpMinimumApplicationAddress;
            public IntPtr lpMaximumApplicationAddress;
            public IntPtr dwActiveProcessorMask;
            public uint dwNumberOfProcessors;
            public uint dwProcessorType;
            public uint dwAllocationGranularity;
            public short wProcessorLevel;
            public short wProcessorRevision;
            public ushort wProcessorArchitecture;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SYSTEM_MEMORY_INFO
        {
            public uint TotalPhysicalMemory;
            public uint AvailablePhysicalMemory;
            public uint TotalPageFile;
            public uint AvailablePageFile;
            public uint TotalVirtual;
            public uint AvailableVirtual;
        }

        // PROCESS_MEMORY_COUNTERS - Basic process memory counters (40 bytes)
        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_MEMORY_COUNTERS
        {
            public uint cb;
            public uint PageFaultCount;
            public uint PeakWorkingSetSize;
            public uint WorkingSetSize;
            public uint QuotaPeakPagedPoolUsage;
            public uint QuotaPagedPoolUsage;
            public uint QuotaPeakNonPagedPoolUsage;
            public uint QuotaNonPagedPoolUsage;
            public uint PagefileUsage;
            public uint PeakPagefileUsage;
        }

        // PROCESS_MEMORY_COUNTERS_EX - Extended process memory counters (72 bytes - Vista+)
        [StructLayout(LayoutKind.Sequential, Pack = 8)] // Pack=8 ile 64-bit alignment
        public struct PROCESS_MEMORY_COUNTERS_EX
        {
            public uint cb;
            public uint PageFaultCount;
            public uint PeakWorkingSetSize;     // 32-bit
            public uint WorkingSetSize;         // 32-bit
            public uint QuotaPeakPagedPoolUsage;
            public uint QuotaPagedPoolUsage;
            public uint QuotaPeakNonPagedPoolUsage;
            public uint QuotaNonPagedPoolUsage;
            public uint PagefileUsage;
            public uint PeakPagefileUsage;
            public uint PrivateUsage;           // Vista+ için eklendi
        }

        ///////////////// ADVANCED MINIDUMP STREAM STRUCTS /////////////////

        [StructLayout(LayoutKind.Sequential)]
        public struct ThreadListStream
        {
            public uint NumberOfThreads;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct Thread
        {
            public uint ThreadId;
            public uint SuspendCount;
            public uint PriorityClass;
            public uint Priority;
            public IntPtr Teb;
            public MINIDUMP_MEMORY_DESCRIPTOR Stack;
            public CONTEXT Context;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct HandleListStream
        {
            public uint SizeOfHeader;
            public uint SizeOfDescriptor;
            public uint NumberOfDescriptors;
            public uint Reserved;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct Handle
        {
            public ulong Handle64;         // 8 bytes - 64-bit handle value
            public uint TypeNameRva;       // 4 bytes - RVA to type name
            public uint ObjectNameRva;     // 4 bytes - RVA to object name
            public uint Attributes;        // 4 bytes - Handle attributes
            public uint GrantedAccess;     // 4 bytes - Granted access mask
            public uint HandleCount;       // 4 bytes - Handle reference count
            public uint PointerCount;      // 4 bytes - Pointer reference count
            // TOPLAM: 32 bytes - MINIDUMP_HANDLE_DESCRIPTOR_2 (Windows Vista+)
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct ThreadInfoListStream
        {
            public uint SizeOfHeader;     // Size of this header
            public uint SizeOfEntry;      // Size of each entry (ThreadInfo struct)
            public uint NumberOfEntries;  // Number of thread info entries
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct ThreadInfo
        {
            public uint ThreadId;
            public uint DumpFlags;
            public uint DumpError;
            public uint ExitStatus;
            public UInt64 CreateTime;
            public UInt64 ExitTime;
            public UInt64 KernelTime;
            public UInt64 UserTime;
            public UInt64 StartAddress;
            public UInt64 Affinity;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct ThreadNamesStream
        {
            public uint NumberOfThreadNames;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct ThreadName
        {
            public uint ThreadId;
            public uint ThreadNameRva;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MiscInfoStream
        {
            public uint SizeOfInfo;
            public uint Flags1;
            public uint ProcessId;
            public uint ProcessCreateTime;
            public uint ProcessUserTime;
            public uint ProcessKernelTime;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct ExceptionStream
        {
            public uint ThreadId;
            public uint Alignment;
            public ExceptionRecord ExceptionRecord;
            public uint ThreadContext;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct ExceptionRecord
        {
            public uint ExceptionCode;
            public uint ExceptionFlags;
            public IntPtr ExceptionRecordPtr;
            public IntPtr ExceptionAddress;
            public uint NumberParameters;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 15)]
            public IntPtr[] ExceptionInformation;
        }

        // MINIDUMP_UNLOADED_MODULE - Unloaded module information
        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct MINIDUMP_UNLOADED_MODULE
        {
            public ulong BaseOfImage;
            public uint SizeOfImage;
            public uint CheckSum;
            public uint TimeDateStamp;
            public uint ModuleNameRva;
        }

        // MINIDUMP_UNLOADED_MODULE_LIST - Unloaded module list header
        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct MINIDUMP_UNLOADED_MODULE_LIST
        {
            public uint SizeOfHeader;
            public uint SizeOfEntry;
            public uint NumberOfEntries;
        }

        // MINIDUMP_HANDLE_OPERATION_LIST - Handle operation list header
        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct MINIDUMP_HANDLE_OPERATION_LIST
        {
            public uint SizeOfHeader;
            public uint SizeOfEntry;
            public uint NumberOfEntries;
            public uint Reserved;
        }

        // MINIDUMP_FUNCTION_TABLE_DESCRIPTOR - Function table descriptor (Microsoft format)
        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct MINIDUMP_FUNCTION_TABLE_DESCRIPTOR
        {
            public ulong MinimumAddress;
            public ulong MaximumAddress;
            public ulong BaseAddress;
            public uint EntryCount;
            public uint SizeOfAlignPad; // Resmi Microsoft format'ta var (genellikle 0)
        }

        // MINIDUMP_FUNCTION_TABLE_STREAM - Function table stream header (Microsoft format)
        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct MINIDUMP_FUNCTION_TABLE_STREAM
        {
            public uint SizeOfHeader;
            public uint SizeOfDescriptor;
            public uint SizeOfNativeDescriptor;
            public uint SizeOfFunctionEntry;
            public uint NumberOfDescriptors;
            public uint SizeOfAlignPad; // Resmi Microsoft format'ta var (genellikle 0)
        }

        // MINIDUMP_PROCESS_VM_COUNTERS - Process VM counters stream
        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct MINIDUMP_PROCESS_VM_COUNTERS
        {
            public uint Revision;
            public uint PageFaultCount;
            public ulong PeakWorkingSetSize;
            public ulong WorkingSetSize;
            public ulong QuotaPeakPagedPoolUsage;
            public ulong QuotaPagedPoolUsage;
            public ulong QuotaPeakNonPagedPoolUsage;
            public ulong QuotaNonPagedPoolUsage;
            public ulong PagefileUsage;
            public ulong PeakPagefileUsage;
            public ulong PrivateUsage;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SystemMemoryInfoStream
        {
            public uint NumOfEntries;
            public uint Version;
        }

        ///////////////// SYSTEM MEMORY INFO STRUCTS /////////////////

        /// <summary>
        /// MiniDumpSystemBasicInformation class - Sistem bellek bilgilerini wrapper olarak sağlar
        /// </summary>
        public class MiniDumpSystemBasicInformation
        {
            private MINIDUMP_SYSTEM_BASIC_INFORMATION _systemBasicInformation;
            private MiniDumpFile _owner;

            internal MiniDumpSystemBasicInformation(MINIDUMP_SYSTEM_BASIC_INFORMATION systemBasicInformation, MiniDumpFile owner)
            {
                _systemBasicInformation = systemBasicInformation;
                _owner = owner;
            }

            public UInt32 TimerResolution { get { return _systemBasicInformation.TimerResolution; } }
            public UInt32 PageSize { get { return _systemBasicInformation.PageSize; } }
            public UInt32 NumberOfPhysicalPages { get { return _systemBasicInformation.NumberOfPhysicalPages; } }
            public UInt32 LowestPhysicalPageNumber { get { return _systemBasicInformation.LowestPhysicalPageNumber; } }
            public UInt32 HighestPhysicalPageNumber { get { return _systemBasicInformation.HighestPhysicalPageNumber; } }
            public UInt32 AllocationGranularity { get { return _systemBasicInformation.AllocationGranularity; } }
            public UInt64 MinimumUserModeAddress { get { return _systemBasicInformation.MinimumUserModeAddress; } }
            public UInt64 MaximumUserModeAddress { get { return _systemBasicInformation.MaximumUserModeAddress; } }
            public UInt64 ActiveProcessorsAffinityMask { get { return _systemBasicInformation.ActiveProcessorsAffinityMask; } }
            public UInt32 NumberOfProcessors { get { return _systemBasicInformation.NumberOfProcessors; } }
        }

        /// <summary>
        /// Placeholder class for MiniDumpFile (minimal implementation)
        /// </summary>
        public class MiniDumpFile
        {
            // Minimal implementation for MiniDumpSystemBasicInformation
        }

        /// <summary>
        /// MINIDUMP_SYSTEM_MEMORY_INFO_1 - Ana bellek bilgi container'ı
        /// </summary>
        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct MINIDUMP_SYSTEM_MEMORY_INFO_1
        {
            public ushort Revision;
            public ushort Flags;
            public MINIDUMP_SYSTEM_BASIC_INFORMATION BasicInfo;
            public MINIDUMP_SYSTEM_FILECACHE_INFORMATION FileCacheInfo;
            public MINIDUMP_SYSTEM_BASIC_PERFORMANCE_INFORMATION BasicPerfInfo;
            public MINIDUMP_SYSTEM_PERFORMANCE_INFORMATION PerfInfo;
        }

        /// <summary>
        /// MINIDUMP_SYSTEM_BASIC_INFORMATION - Temel sistem bilgileri
        /// </summary>
        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct MINIDUMP_SYSTEM_BASIC_INFORMATION
        {
            public UInt32 TimerResolution;
            public UInt32 PageSize;
            public UInt32 NumberOfPhysicalPages;
            public UInt32 LowestPhysicalPageNumber;
            public UInt32 HighestPhysicalPageNumber;
            public UInt32 AllocationGranularity;
            public UInt64 MinimumUserModeAddress;
            public UInt64 MaximumUserModeAddress;
            public UInt64 ActiveProcessorsAffinityMask;
            public UInt32 NumberOfProcessors;
        }

        /// <summary>
        /// MINIDUMP_SYSTEM_FILECACHE_INFORMATION - Dosya cache bilgileri
        /// </summary>
        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct MINIDUMP_SYSTEM_FILECACHE_INFORMATION
        {
            public UInt64 CurrentSize;
            public UInt64 PeakSize;
            public UInt32 PageFaultCount;
            public UInt64 MinimumWorkingSet;
            public UInt64 MaximumWorkingSet;
            public UInt64 CurrentSizeIncludingTransitionInPages;
            public UInt64 PeakSizeIncludingTransitionInPages;
            public UInt32 TransitionRePurposeCount;
            public UInt32 Flags;
        }

        /// <summary>
        /// MINIDUMP_SYSTEM_BASIC_PERFORMANCE_INFORMATION - Temel performans bilgileri
        /// </summary>
        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct MINIDUMP_SYSTEM_BASIC_PERFORMANCE_INFORMATION
        {
            public UInt64 AvailablePages;
            public UInt64 CommittedPages;
            public UInt64 CommitLimit;
            public UInt64 PeakCommitment;
        }

        /// <summary>
        /// MINIDUMP_SYSTEM_PERFORMANCE_INFORMATION - Detaylı performans bilgileri
        /// </summary>
        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct MINIDUMP_SYSTEM_PERFORMANCE_INFORMATION
        {
            public UInt64 IdleProcessTime;
            public UInt64 IoReadTransferCount;
            public UInt64 IoWriteTransferCount;
            public UInt64 IoOtherTransferCount;
            public UInt32 IoReadOperationCount;
            public UInt32 IoWriteOperationCount;
            public UInt32 IoOtherOperationCount;
            public UInt32 AvailablePages;
            public UInt32 CommittedPages;
            public UInt32 CommitLimit;
            public UInt32 PeakCommitment;
            public UInt32 PageFaultCount;
            public UInt32 CopyOnWriteCount;
            public UInt32 TransitionCount;
            public UInt32 CacheTransitionCount;
            public UInt32 DemandZeroCount;
            public UInt32 PageReadCount;
            public UInt32 PageReadIoCount;
            public UInt32 CacheReadCount;
            public UInt32 CacheIoCount;
            public UInt32 DirtyPagesWriteCount;
            public UInt32 DirtyWriteIoCount;
            public UInt32 MappedPagesWriteCount;
            public UInt32 MappedWriteIoCount;
            public UInt32 PagedPoolPages;
            public UInt32 NonPagedPoolPages;
            public UInt32 PagedPoolAllocs;
            public UInt32 PagedPoolFrees;
            public UInt32 NonPagedPoolAllocs;
            public UInt32 NonPagedPoolFrees;
            public UInt32 FreeSystemPtes;
            public UInt32 ResidentSystemCodePage;
            public UInt32 TotalSystemDriverPages;
            public UInt32 TotalSystemCodePages;
            public UInt32 NonPagedPoolLookasideHits;
            public UInt32 PagedPoolLookasideHits;
            public UInt32 AvailablePagedPoolPages;
            public UInt32 ResidentSystemCachePage;
            public UInt32 ResidentPagedPoolPage;
            public UInt32 ResidentSystemDriverPage;
            public UInt32 CcFastReadNoWait;
            public UInt32 CcFastReadWait;
            public UInt32 CcFastReadResourceMiss;
            public UInt32 CcFastReadNotPossible;
            public UInt32 CcFastMdlReadNoWait;
            public UInt32 CcFastMdlReadWait;
            public UInt32 CcFastMdlReadResourceMiss;
            public UInt32 CcFastMdlReadNotPossible;
            public UInt32 CcMapDataNoWait;
            public UInt32 CcMapDataWait;
            public UInt32 CcMapDataNoWaitMiss;
            public UInt32 CcMapDataWaitMiss;
            public UInt32 CcPinMappedDataCount;
            public UInt32 CcPinReadNoWait;
            public UInt32 CcPinReadWait;
            public UInt32 CcPinReadNoWaitMiss;
            public UInt32 CcPinReadWaitMiss;
            public UInt32 CcCopyReadNoWait;
            public UInt32 CcCopyReadWait;
            public UInt32 CcCopyReadNoWaitMiss;
            public UInt32 CcCopyReadWaitMiss;
            public UInt32 CcMdlReadNoWait;
            public UInt32 CcMdlReadWait;
            public UInt32 CcMdlReadNoWaitMiss;
            public UInt32 CcMdlReadWaitMiss;
            public UInt32 CcReadAheadIos;
            public UInt32 CcLazyWriteIos;
            public UInt32 CcLazyWritePages;
            public UInt32 CcDataFlushes;
            public UInt32 CcDataPages;
            public UInt32 ContextSwitches;
            public UInt32 FirstLevelTbFills;
            public UInt32 SecondLevelTbFills;
            public UInt32 SystemCalls;
            public UInt64 CcTotalDirtyPages;
            public UInt64 CcDirtyPageThreshold;
            public Int64 ResidentAvailablePages; //LONG64
            public UInt64 SharedCommittedPages;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public unsafe struct MemoryInfo
        {
            public ulong BaseAddress;
            public ulong AllocationBase;
            public uint AllocationProtect;
            public uint __alignment1;
            public ulong RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
            public uint __alignment2;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct MemoryInfoListStream
        {
            public uint SizeOfHeader;
            public uint SizeOfEntry;
            public ulong NumberOfEntries;
        }

        ///////////////// ADVANCED STREAM STRUCTS (Token, JavaScript, IPT) /////////////////

        // MINIDUMP_TOKEN_INFO_LIST - Token stream header
        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct MINIDUMP_TOKEN_INFO_LIST
        {
            public uint TokenListSize;     // Size of entire list
            public uint TokenListEntries;  // Number of entries
            public uint ListHeaderSize;    // Size of header
            public uint ElementHeaderSize; // Size of each element
        }

        // MINIDUMP_TOKEN_INFO - Token information
        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct MINIDUMP_TOKEN_INFO
        {
            public uint TokenSize;     // Size of TOKEN struct
            public uint TokenId;       // Token ID
            public uint TokenHandle;   // Token handle
            // TOKEN struct would follow, but we skip for simplicity
        }

        // MINIDUMP_JAVASCRIPT_DATA - JavaScript data stream
        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct MINIDUMP_JAVASCRIPT_DATA
        {
            public uint SizeOfStream;      // Size of entire stream
            public uint ContextCount;      // Number of JavaScript contexts
            // Context data would follow
        }

        // MINIDUMP_IPT_TRACE_STREAM - Intel PT trace stream
        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct MINIDUMP_IPT_TRACE_STREAM
        {
            public uint SizeOfHeader;      // Size of header
            public uint SizeOfEntry;       // Size of each entry
            public uint NumberOfEntries;   // Number of trace entries
            public uint TraceVersion;      // Trace format version
            public uint TraceState;        // Trace state flags
        }

        // Advanced stream type constants are already defined above

        ///////////////// MODULE INFO STRUCT /////////////////

        // VS_FIXEDFILEINFO - Version information
        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct VS_FIXEDFILEINFO
        {
            public uint dwSignature;
            public uint dwStrucVersion;
            public uint dwFileVersionMS;
            public uint dwFileVersionLS;
            public uint dwProductVersionMS;
            public uint dwProductVersionLS;
            public uint dwFileFlagsMask;
            public uint dwFileFlags;
            public uint dwFileOS;
            public uint dwFileType;
            public uint dwFileSubtype;
            public uint dwFileDateMS;
            public uint dwFileDateLS;
        }

        // MINIDUMP_LOCATION_DESCRIPTOR - Generic location descriptor
        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct MINIDUMP_LOCATION_DESCRIPTOR
        {
            public uint DataSize;
            public uint Rva;
        }

        // MINIDUMP_MODULE - Correct minidump module structure
        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct MINIDUMP_MODULE
        {
            public ulong BaseOfImage;
            public uint SizeOfImage;
            public uint CheckSum;
            public uint TimeDateStamp;
            public uint ModuleNameRva;
            public VS_FIXEDFILEINFO VersionInfo;
            public MINIDUMP_LOCATION_DESCRIPTOR CvRecord;
            public MINIDUMP_LOCATION_DESCRIPTOR MiscRecord;
            public ulong Reserved0;
            public ulong Reserved1;
        }

        // ModuleInfo - Temporary structure for collecting module data
        [StructLayout(LayoutKind.Sequential)]
        public struct ModuleInfo
        {
            public IntPtr BaseAddress;
            public IntPtr Size;
            public uint Timestamp;
            public uint Checksum;
            public uint ModuleNameRva;
            public IntPtr ImageName;  // Temporary pointer for module name
        }

        ///////////////// THREAD & EXCEPTION STRUCTS /////////////////

        // MINIDUMP_MEMORY_DESCRIPTOR - Memory region descriptor
        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct MINIDUMP_MEMORY_DESCRIPTOR
        {
            public ulong StartOfMemoryRange;
            public MINIDUMP_LOCATION_DESCRIPTOR Memory;
        }

        // MINIDUMP_THREAD - Thread information for minidump
        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct MINIDUMP_THREAD
        {
            public uint ThreadId;
            public uint SuspendCount;
            public uint PriorityClass;
            public uint Priority;
            public ulong Teb;
            public MINIDUMP_MEMORY_DESCRIPTOR Stack;
            public MINIDUMP_LOCATION_DESCRIPTOR ThreadContext;
        }

        // MINIDUMP_THREAD_EX - Extended thread information (Windows Vista+)
        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct MINIDUMP_THREAD_EX
        {
            public uint ThreadId;
            public uint SuspendCount;
            public uint PriorityClass;
            public uint Priority;
            public ulong Teb;
            public MINIDUMP_MEMORY_DESCRIPTOR Stack;
            public MINIDUMP_LOCATION_DESCRIPTOR ThreadContext;
            public MINIDUMP_LOCATION_DESCRIPTOR BackingStore;
        }

        // MINIDUMP_EXCEPTION - Exception information
        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct MINIDUMP_EXCEPTION
        {
            public uint ExceptionCode;
            public uint ExceptionFlags;
            public ulong ExceptionRecord;
            public ulong ExceptionAddress;
            public uint NumberParameters;
            public uint __unusedAlignment;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 15)]
            public ulong[] ExceptionInformation;
        }

        // MINIDUMP_EXCEPTION_STREAM - Exception stream for minidump
        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct MINIDUMP_EXCEPTION_STREAM
        {
            public uint ThreadId;
            public uint __alignment;
            public MINIDUMP_EXCEPTION ExceptionRecord;
            public MINIDUMP_LOCATION_DESCRIPTOR ThreadContext;
        }


        // MINIDUMP_THREAD_LIST - Thread list stream header
        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct MINIDUMP_THREAD_LIST
        {
            public uint NumberOfThreads;
            // MINIDUMP_THREAD entries follow
        }

        // MINIDUMP_THREAD_EX_LIST - Extended thread list stream header
        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct MINIDUMP_THREAD_EX_LIST
        {
            public uint NumberOfThreads;
            // MINIDUMP_THREAD_EX entries follow
        }

        // MINIDUMP_MISC_INFO_2 - Misc info for minidump (Windows XP+)
        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct MINIDUMP_MISC_INFO_2
        {
            public uint SizeOfInfo;
            public uint Flags1;
            public uint ProcessId;
            public uint ProcessCreateTime;
            public uint ProcessUserTime;
            public uint ProcessKernelTime;
            public uint ProcessorMaxMhz;
            public uint ProcessorCurrentMhz;
            public uint ProcessorMhzLimit;
            public uint ProcessorMaxIdleState;
            public uint ProcessorCurrentIdleState;
        }

        // MINIDUMP_MISC_INFO_4 - Extended misc info for minidump (Windows Vista+)
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode, Pack = 4)]
        public struct MINIDUMP_MISC_INFO_4
        {
            public uint SizeOfInfo;
            public uint Flags1;
            public uint ProcessId;
            public uint ProcessCreateTime;
            public uint ProcessUserTime;
            public uint ProcessKernelTime;
            public uint ProcessorMaxMhz;
            public uint ProcessorCurrentMhz;
            public uint ProcessorMhzLimit;
            public uint ProcessorMaxIdleState;
            public uint ProcessorCurrentIdleState;
            public uint ProcessIntegrityLevel;
            public uint ProcessExecuteFlags;
            public uint ProtectedProcess;
            public uint TimeZoneId;
            public TIME_ZONE_INFORMATION TimeZone;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string BuildString;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 40)]
            public string DbgBldStr;
        }

        ///////////////// PE PARSING STRUCTS FOR FUNCTION TABLE /////////////////

        // RTL_PROCESS_MODULE_INFORMATION - Process modül bilgilerini almak için
        [StructLayout(LayoutKind.Sequential)]
        public struct RTL_PROCESS_MODULE_INFORMATION
        {
            public IntPtr Section;
            public IntPtr MappedBase;
            public IntPtr ImageBase;
            public uint ImageSize;
            public uint Flags;
            public ushort LoadOrderIndex;
            public ushort InitOrderIndex;
            public ushort LoadCount;
            public ushort OffsetToFileName;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
            public byte[] FullPathName;

            // Constructor ile FullPathName array'ini başlat
            public RTL_PROCESS_MODULE_INFORMATION(bool initialize)
            {
                Section = IntPtr.Zero;
                MappedBase = IntPtr.Zero;
                ImageBase = IntPtr.Zero;
                ImageSize = 0;
                Flags = 0;
                LoadOrderIndex = 0;
                InitOrderIndex = 0;
                LoadCount = 0;
                OffsetToFileName = 0;
                FullPathName = initialize ? new byte[256] : null;
            }
        }

        // FunctionExport - Export function bilgileri
        [StructLayout(LayoutKind.Sequential)]
        public struct FunctionExport
        {
            public string FunctionName;
            public IntPtr FunctionAddress;
            public uint Ordinal;
        }

        // IMAGE_DOS_HEADER - PE dosya başlangıcı (Pack=1 ile binary alignment)
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_DOS_HEADER
        {
            public ushort e_magic;    // MZ signature @ 0x00
            public ushort e_cblp;     // @ 0x02
            public ushort e_cp;       // @ 0x04
            public ushort e_crlc;     // @ 0x06
            public ushort e_cparhdr;  // @ 0x08
            public ushort e_minalloc; // @ 0x0A
            public ushort e_maxalloc; // @ 0x0C
            public ushort e_ss;       // @ 0x0E
            public ushort e_sp;       // @ 0x10
            public ushort e_csum;     // @ 0x12
            public ushort e_ip;       // @ 0x14
            public ushort e_cs;       // @ 0x16
            public ushort e_lfarlc;   // @ 0x18
            public ushort e_ovno;     // @ 0x1A
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public ushort[] e_res4;   // @ 0x1C - 16 bytes
            public ushort e_oemid;    // @ 0x2C
            public ushort e_oeminfo;  // @ 0x2E
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 20)]
            public ushort[] e_res2;   // @ 0x30 - 40 bytes
            public int e_lfanew;      // PE header offset @ 0x3C (64 bytes total)
        }

        // IMAGE_FILE_HEADER - PE file header
        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_FILE_HEADER
        {
            public ushort Machine;
            public ushort NumberOfSections;
            public uint TimeDateStamp;
            public uint PointerToSymbolTable;
            public uint NumberOfSymbols;
            public ushort SizeOfOptionalHeader;
            public ushort Characteristics;
        }

        // IMAGE_DATA_DIRECTORY - PE data directory
        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DATA_DIRECTORY
        {
            public uint VirtualAddress;
            public uint Size;
        }

        // IMAGE_OPTIONAL_HEADER - PE optional header
        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_OPTIONAL_HEADER
        {
            public ushort Magic;
            public byte MajorLinkerVersion;
            public byte MinorLinkerVersion;
            public uint SizeOfCode;
            public uint SizeOfInitializedData;
            public uint SizeOfUninitializedData;
            public uint AddressOfEntryPoint;
            public uint BaseOfCode;
            public uint BaseOfData;
            public uint ImageBase;
            public uint SectionAlignment;
            public uint FileAlignment;
            public ushort MajorOperatingSystemVersion;
            public ushort MinorOperatingSystemVersion;
            public ushort MajorImageVersion;
            public ushort MinorImageVersion;
            public ushort MajorSubsystemVersion;
            public ushort MinorSubsystemVersion;
            public uint Win32VersionValue;
            public uint SizeOfImage;
            public uint SizeOfHeaders;
            public uint CheckSum;
            public ushort Subsystem;
            public ushort DllCharacteristics;
            public uint SizeOfStackReserve;
            public uint SizeOfStackCommit;
            public uint SizeOfHeapReserve;
            public uint SizeOfHeapCommit;
            public uint LoaderFlags;
            public uint NumberOfRvaAndSizes;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public IMAGE_DATA_DIRECTORY[] DataDirectory;
        }

        // IMAGE_NT_HEADERS64 - PE header (64-bit)
        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_NT_HEADERS64
        {
            public uint Signature;        // PE signature (PE\0\0)
            public IMAGE_FILE_HEADER FileHeader;
            public IMAGE_OPTIONAL_HEADER OptionalHeader;
        }

        // IMAGE_EXPORT_DIRECTORY - Export directory table
        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_EXPORT_DIRECTORY
        {
            public uint Characteristics;
            public uint TimeDateStamp;
            public ushort MajorVersion;
            public ushort MinorVersion;
            public uint Name;
            public uint Base;
            public uint NumberOfFunctions;
            public uint NumberOfNames;
            public uint AddressOfFunctions;     // RVA to function address array
            public uint AddressOfNames;         // RVA to function name array
            public uint AddressOfNameOrdinals;  // RVA to function ordinal array
        }

        // Constants for PE parsing
        public const uint IMAGE_DOS_SIGNATURE = 0x5A4D;  // "MZ"
        public const uint IMAGE_NT_SIGNATURE = 0x00004550; // "PE\0\0"
        public const ushort IMAGE_FILE_MACHINE_AMD64 = 0x8664;
        public const ushort IMAGE_FILE_MACHINE_I386 = 0x014c;
        public const uint IMAGE_DIRECTORY_ENTRY_EXPORT = 0;  // Export Directory
        public const uint IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3; // Exception Directory

        // RUNTIME_FUNCTION struct for exception unwinding (x64)
        [StructLayout(LayoutKind.Sequential)]
        public struct RUNTIME_FUNCTION
        {
            public uint BeginAddress;    // Function start RVA
            public uint EndAddress;      // Function end RVA
            public uint UnwindInfoAddress; // Unwind info RVA
        }

        // UNWIND_INFO struct for exception unwinding
        [StructLayout(LayoutKind.Sequential)]
        public struct UNWIND_INFO
        {
            public byte Version;         // Version (0x1)
            public byte Flags;           // Flags
            public byte SizeOfProlog;    // Size of function prologue
            public byte CountOfCodes;    // Number of unwind codes
            public byte FrameRegister;   // Frame register (0 = no frame register)
            public byte FrameOffset;     // Frame register offset
        }

        // UNWIND_CODE struct for unwind codes
        [StructLayout(LayoutKind.Sequential)]
        public struct UNWIND_CODE
        {
            public byte CodeOffset;      // Offset in prolog
            public byte UnwindOp;        // Unwind operation
            public byte OpInfo;          // Operation info
        }

        ///////////////// PE SECTION HEADER /////////////////

        // IMAGE_SECTION_HEADER - PE section header structure
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct PE_SECTION_HEADER
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public byte[] Name;              // 8 bytes - Section name
            public uint VirtualSize;         // 4 bytes - Size of section in memory
            public uint VirtualAddress;      // 4 bytes - RVA of section in memory
            public uint SizeOfRawData;       // 4 bytes - Size of section in file
            public uint PointerToRawData;    // 4 bytes - File offset to section
            public uint PointerToRelocations; // 4 bytes - File offset to relocations
            public uint PointerToLinenumbers; // 4 bytes - File offset to line numbers
            public ushort NumberOfRelocations; // 2 bytes - Number of relocations
            public ushort NumberOfLinenumbers; // 2 bytes - Number of line numbers
            public uint Characteristics;     // 4 bytes - Section flags
        }

        
        /// <summary>
        /// Minidump stream'ini temsil eden struct
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        internal struct MinidumpStream
        {
            public uint StreamType;
            public byte[] Data;
        }

        
        /// <summary>
        /// Thread CONTEXT bilgilerini tutan yardımcı struct
        /// </summary>
        internal struct ThreadContextInfo
        {
            public uint ThreadId;
            public CONTEXT Context;
        }

        /// <summary>
        /// Thread bilgilerini tutan detaylı struct
        /// </summary>
        internal struct ThreadDetailInfo
        {
            public uint ThreadId;
            public CONTEXT Context;

            public ThreadDetailInfo(uint threadId, CONTEXT context)
            {
                ThreadId = threadId;
                Context = context;
            }
        }

        /// <summary>
        /// Gelişmiş thread bilgilerini tutan struct (MINIDUMP_THREAD için)
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        internal struct MinidumpThreadInfo
        {
            public uint ThreadId;
            public ulong TebAddress;
            public ulong StackBase;
            public uint StackSize;
            public CONTEXT Context;
        }

            /// <summary>
    /// Sistem bilgilerini tutan struct
    /// </summary>
    public struct SystemInfoData
    {
        public uint MajorVersion;
        public uint MinorVersion;
        public uint BuildNumber;
        public uint PlatformId;
        public string CSDVersion;
        public ushort ProcessorArchitecture;
        public byte ProcessorCount;
        public short ProcessorLevel;
        public short ProcessorRevision;
        public ushort SuiteMask;
        public uint TotalPhysicalMemory;
        public uint AvailablePhysicalMemory;
        public uint TotalPageFile;
        public uint AvailablePageFile;
        public uint TotalVirtualMemory;
        public uint AvailableVirtualMemory;
        // CPU Information
        public uint VendorId0;
        public uint VendorId1;
        public uint VendorId2;
        public uint VersionInformation;
        public uint FeatureInformation;
        public uint AMDExtendedCpuFeatures;
    }

        /// <summary>
        /// İşlem bilgilerini tutan struct
        /// </summary>
        public struct ProcessInfoData
        {
            public uint ProcessId;
            public uint ParentProcessId;
            public IntPtr CreateTime;
            public IntPtr ExitTime;
            public IntPtr UserTime;
            public IntPtr KernelTime;
            public string ImageName;
            public string CommandLine;
        }

        /// <summary>
        /// Handle bilgilerini tutan struct
        /// </summary>
        public struct HandleInfo
        {
            public uint HandleValue;
            public uint GrantedAccess;
            public byte ObjectTypeIndex;
            public byte HandleAttributes;
            public IntPtr ObjectPointer;
            public string TypeName;
            public string ObjectName;  // Object name (File path, Registry key, etc.)
        }

    }
}