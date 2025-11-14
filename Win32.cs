using System;
using System.Runtime.InteropServices;


namespace WinEmuDump
{
    internal class Win32
    {

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
        public const int PAGE_READONLY = 0x02;
        public const int PAGE_READWRITE = 0x04;
        public const int PAGE_EXECUTE_READ = 0x20;
        public const int PAGE_EXECUTE_READWRITE = 0x40;
        public const uint MemoryBasicInformation = 0;
        public const uint THREAD_QUERY_INFORMATION = 0x0040;
        public const uint THREAD_GET_CONTEXT = 0x0008;

        public const uint EVENT_QUERY_STATE = 0x0001;
        public const uint DUPLICATE_SAME_ACCESS = 0x00000002;
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

        // Emulator-specific custom stream (EmuHandleInfo)
        // Vendor-specific aralıkta tutuyoruz ki resmi dbghelp ile çakışmasın.
        public const uint MINIDUMP_STREAM_TYPE_EmuHandleInfo = 0xE0000100;


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

        // MINIDUMP_MEMORY64_LIST - Correct structure for Memory64List stream
        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct MINIDUMP_MEMORY64_LIST
        {
            public UInt64 NumberOfMemoryRanges;
            public UInt64 BaseRva;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        // CONTEXT yapı sabitleri
        public const uint CONTEXT_AMD64 = 0x100000;
        public const uint CONTEXT_CONTROL = (CONTEXT_AMD64 | 0x1);
        public const uint CONTEXT_INTEGER = (CONTEXT_AMD64 | 0x2);
        public const uint CONTEXT_SEGMENTS = (CONTEXT_AMD64 | 0x4);
        public const uint CONTEXT_FLOATING_POINT = (CONTEXT_AMD64 | 0x8);
        public const uint CONTEXT_DEBUG_REGISTERS = (CONTEXT_AMD64 | 0x10);
        public const uint CONTEXT_FULL = (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT);

        ///////////////// ADVANCED MINIDUMP STREAM STRUCTS /////////////////

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

        ///////////////// ADVANCED STREAM STRUCTS (Token, JavaScript, IPT, EmuHandle) /////////////////

        // EMU_HANDLE_TYPE - Emulatör için handle türleri
        public enum EMU_HANDLE_TYPE : uint
        {
            Unknown      = 0,
            Event        = 1,
            Mutex        = 2,
            Semaphore    = 3,
            Timer        = 4,
            IoCompletion = 5,
        }

        // EMU_HANDLE_INFO_HEADER - EmuHandleInfo stream header
        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct EMU_HANDLE_INFO_HEADER
        {
            public uint SizeOfHeader;    // sizeof(EMU_HANDLE_INFO_HEADER)
            public ushort Version;       // 1
            public ushort Flags;         // global flags (şimdilik 0)
            public uint NumberOfEntries; // EMU_HANDLE_ENTRY sayısı
            public uint Reserved0;       // future use
            public uint Reserved1;       // future use
        }

        // EMU_HANDLE_ENTRY - Her handle için ortak bilgiler
        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct EMU_HANDLE_ENTRY
        {
            public ulong HandleValue;   // Orijinal hedef süreçteki handle değeri
            public EMU_HANDLE_TYPE EmuType;
            public uint Flags;          // Ortak bayraklar (HAS_STATE_INFO, STATE_QUERY_FAILED, vs.)
            public uint DetailRva;      // Tür spesifik bilgi bloğuna RVA (0 => yok)
            public uint DetailSize;     // Tür spesifik bilgi bloğu boyutu
            public uint Reserved0;      // future use
            public uint Reserved1;      // future use
        }

        // Ortak Flags (EMU_HANDLE_ENTRY.Flags) için bitler
        public const uint EMU_HANDLE_FLAG_HAS_STATE_INFO      = 0x00000001;
        public const uint EMU_HANDLE_FLAG_STATE_QUERY_FAILED  = 0x00000002;
        public const uint EMU_HANDLE_FLAG_TYPE_MISMATCH       = 0x00000004;

        // EMU_EVENT_INFO_V1 - Event handle detayları
        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct EMU_EVENT_INFO_V1
        {
            public uint Size;        // sizeof(EMU_EVENT_INFO_V1)
            public ushort Version;   // 1
            public ushort Flags;     // future use
            public byte ManualReset; // 0 = Auto, 1 = Manual, 0xFF = bilinmiyor
            public byte Signaled;    // 0 = Non-signaled, 1 = Signaled, 0xFF = bilinmiyor
            public ushort Reserved0; // alignment
            public uint Reserved1;   // future use
            public uint Reserved2;   // future use
            public uint Reserved3;   // future use
        }

        // EMU_MUTEX_INFO_V1 - Mutex handle detayları (şema hazır, veriler opsiyonel)
        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct EMU_MUTEX_INFO_V1
        {
            public uint Size;
            public ushort Version;       // 1
            public ushort Flags;
            public uint OwnerThreadId;   // biliniyorsa, yoksa 0
            public uint LockCount;       // biliniyorsa, yoksa 0
            public uint Reserved0;
        }

        // EMU_SEMAPHORE_INFO_V1 - Semaphore handle detayları (şema hazır, veriler opsiyonel)
        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct EMU_SEMAPHORE_INFO_V1
        {
            public uint Size;
            public ushort Version;   // 1
            public ushort Flags;
            public uint CurrentCount; // biliniyorsa
            public uint MaximumCount; // biliniyorsa
            public uint Reserved0;
        }

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
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 15)]  // FIXED: 15 elements (Microsoft standard)
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

        // RUNTIME_FUNCTION struct for exception unwinding (x64)
        [StructLayout(LayoutKind.Sequential)]
        public struct RUNTIME_FUNCTION
        {
            public uint BeginAddress;    // Function start RVA
            public uint EndAddress;      // Function end RVA
            public uint UnwindInfoAddress; // Unwind info RVA
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

    }
}