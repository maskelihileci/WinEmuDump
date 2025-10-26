using System;
using System.Runtime.InteropServices;


namespace WinEmuDump
{
    internal class Win32
    {
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
        [DllImport("ntdll.dll")]
        public static extern uint NtOpenProcess(ref IntPtr ProcessHandle, uint DesiredAccess, ref OBJECT_ATTRIBUTES ObjectAttributes, ref CLIENT_ID processId);

        [DllImport("ntdll.dll")]
        public static extern uint NtReadVirtualMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("ntdll.dll")]
        public static extern uint NtQueryVirtualMemory(IntPtr hProcess, IntPtr lpAddress, uint MemoryInformationClass, out MEMORY_BASIC_INFORMATION MemoryInformation, uint MemoryInformationLength, out uint ReturnLength);

        [DllImport("ntdll.dll")]
        public static extern uint NtOpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, ref IntPtr TokenHandle);

        [DllImport("ntdll.dll")]
        public static extern uint NtAdjustPrivilegesToken(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

        [DllImport("ntdll.dll")]
        public static extern uint NtClose(IntPtr hObject);

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern uint RtlGetVersion(ref OSVERSIONINFOEX lpVersionInformation);

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern uint NtQueryInformationProcess(IntPtr processHandle, int processInformationClass, IntPtr pbi, uint processInformationLength, out uint returnLength);

        [DllImport("ntdll.dll")]
        public static extern uint NtQuerySystemInformation(uint SystemInformationClass, IntPtr SystemInformation, uint SystemInformationLength, out uint ReturnLength);

        [DllImport("ntdll.dll")]
        public static extern uint NtOpenThread(ref IntPtr ThreadHandle, uint DesiredAccess, ref OBJECT_ATTRIBUTES ObjectAttributes, ref CLIENT_ID ClientId);

        [DllImport("ntdll.dll")]
        public static extern uint NtGetContextThread(IntPtr ThreadHandle, ref CONTEXT Context);

        [DllImport("ntdll.dll")]
        public static extern uint NtQueryInformationThread(IntPtr ThreadHandle, uint ThreadInformationClass, IntPtr ThreadInformation, uint ThreadInformationLength, out uint ReturnLength);

        [DllImport("ntdll.dll")]
        public static extern uint NtQueryObject(IntPtr Handle, uint ObjectInformationClass, IntPtr ObjectInformation, uint ObjectInformationLength, out uint ReturnLength);

        [DllImport("kernel32.dll")]
        public static extern bool IsWow64Process(IntPtr hProcess, out bool Wow64Process);

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll")]
        public static extern void GetSystemInfo(out SYSTEM_INFO lpSystemInfo);

        
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
        [StructLayout(LayoutKind.Sequential)]
        public struct MinidumpHeader
        {
            public uint Signature;
            public ushort Version;
            public ushort ImplementationVersion;
            public ushort NumberOfStreams;
            public uint StreamDirectoryRva;
            public uint CheckSum;
            public IntPtr TimeDateStamp;
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

        [StructLayout(LayoutKind.Sequential)]
        public struct Memory64Info
        {
            public IntPtr Address;
            public IntPtr Size;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct Memory64ListStream
        {
            public ulong NumberOfEntries;
            public uint MemoryRegionsBaseAddress;
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
            public Memory64Info Stack;
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

        [StructLayout(LayoutKind.Sequential)]
        public struct ThreadInfoListStream
        {
            public uint NumberOfEntries;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct ThreadInfo
        {
            public uint ThreadId;
            public uint DumpFlags;
            public uint DumpError;
            public uint ExitStatus;
            public IntPtr CreateTime;
            public IntPtr ExitTime;
            public IntPtr KernelTime;
            public IntPtr UserTime;
            public IntPtr StartAddress;
            public IntPtr Affinity;
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
            public IntPtr ThreadNameRva;
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

        [StructLayout(LayoutKind.Sequential)]
        public struct SystemMemoryInfoStream
        {
            public uint NumOfEntries;
            public uint Version;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MemoryInfo
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MemoryInfoListStream
        {
            public uint NumberOfEntries;
        }

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
    }
}