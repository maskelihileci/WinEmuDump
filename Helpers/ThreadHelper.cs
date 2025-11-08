using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;


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


/// <summary>
/// Thread CONTEXT bilgilerini tutan yardımcı struct
/// </summary>
internal struct ThreadContextInfo
{
    public uint ThreadId;
    public CONTEXT Context;
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
public struct CLIENT_ID
{
    public IntPtr UniqueProcess;
    public IntPtr UniqueThread;
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

namespace WinEmuDump.Helpers
{
    /// <summary>
    /// Thread işlemleri için gerekli sabitler
    /// </summary>
    internal static class ThreadConstants
    {
        public const uint THREAD_SUSPEND_RESUME = 0x0002;
        public const uint THREAD_GET_CONTEXT = 0x0008;
        public const uint THREAD_QUERY_INFORMATION = 0x0040;
        public const uint ThreadBasicInformation = 0;
        public const uint ThreadStackInformation = 5;
        public const uint ThreadNameInformation = 0x24;
    }

    /// <summary>
    /// Thread işlemleri için yardımcı fonksiyonlar
    /// ThreadCollector.cs'den birleştirilmiş duplicate kodlar
    /// </summary>
    internal static class ThreadHelper
    {
        /// <summary>
        /// TEB adresini alır
        /// ThreadCollector.cs'deki duplicate fonksiyonun birleştirilmiş versiyonu
        /// </summary>
        /// <param name="threadHandle">Thread handle'ı</param>
        /// <returns>TEB adresi</returns>
        public static IntPtr GetThreadTebAddress(IntPtr threadHandle)
        {
            try
            {
                THREAD_BASIC_INFORMATION threadBasicInfo = new THREAD_BASIC_INFORMATION();
                IntPtr buffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(THREAD_BASIC_INFORMATION)));
                try
                {
                    uint ntStatus = NativeApi.NtQueryInformationThread(
                        threadHandle,
                        ThreadConstants.ThreadBasicInformation,
                        buffer,
                        (uint)Marshal.SizeOf(typeof(THREAD_BASIC_INFORMATION)),
                        out uint returnLength
                    );

                    if (ntStatus == 0)
                    {
                        threadBasicInfo = Marshal.PtrToStructure<THREAD_BASIC_INFORMATION>(buffer);
                        return threadBasicInfo.TebBaseAddress;
                    }
                    else
                    {
                        return IntPtr.Zero;
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
            catch
            {
                return IntPtr.Zero;
            }
        }

        /// <summary>
        /// Thread stack bilgilerini alır
        /// ThreadCollector.cs'deki duplicate fonksiyonun birleştirilmiş versiyonu
        /// </summary>
        /// <param name="hProcess">Process handle'ı</param>
        /// <param name="threadHandle">Thread handle'ı</param>
        /// <returns>Stack başlangıç adresi ve boyutu</returns>
        public static (IntPtr baseAddress, uint size) GetThreadStackInfo(IntPtr hProcess, IntPtr threadHandle)
        {
            try
            {
                // Stack base ve limit'i NtQueryInformationThread ile al
                THREAD_STACK_INFORMATION stackInfo = new THREAD_STACK_INFORMATION();
                IntPtr buffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(THREAD_STACK_INFORMATION)));
                try
                {
                    uint ntStatus = NativeApi.NtQueryInformationThread(
                        threadHandle,
                        ThreadConstants.ThreadStackInformation,
                        buffer,
                        (uint)Marshal.SizeOf(typeof(THREAD_STACK_INFORMATION)),
                        out uint returnLength
                    );

                    if (ntStatus == 0)
                    {
                        stackInfo = Marshal.PtrToStructure<THREAD_STACK_INFORMATION>(buffer);

                        // Stack boyutunu hesapla
                        uint stackSize = (uint)(stackInfo.StackLimit.ToInt64() - stackInfo.StackBase.ToInt64());
                        if (stackSize < 0) stackSize = (uint)Math.Abs(stackSize);

                        return (stackInfo.StackBase, stackSize);
                    }
                    else
                    {
                        return (IntPtr.Zero, 0);
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
            catch
            {
                return (IntPtr.Zero, 0);
            }
        }

        /// <summary>
        /// Process'i suspend eder
        /// ThreadCollector.cs'deki duplicate fonksiyonun birleştirilmiş versiyonu
        /// </summary>
        /// <param name="hProcess">Process handle'ı</param>
        /// <returns>Başarılı ise true</returns>
        public static bool SuspendProcess(IntPtr hProcess)
        {
            try
            {
                return NativeApi.NtSuspendProcess(hProcess) == 0;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Process'i resume eder
        /// ThreadCollector.cs'deki duplicate fonksiyonun birleştirilmiş versiyonu
        /// </summary>
        /// <param name="hProcess">Process handle'ı</param>
        /// <returns>Başarılı ise true</returns>
        public static bool ResumeProcess(IntPtr hProcess)
        {
            try
            {
                return NativeApi.NtResumeProcess(hProcess) == 0;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Hedef işlemin tüm thread'lerini ve özelliklerini toplar
        /// </summary>
        /// <param name="hProcess">Hedef işlemin handle'ı</param>
        /// <param name="threadList">Toplanan thread bilgilerini içeren çıkış listesi</param>
        /// <returns>Başarılı ise true, aksi halde false</returns>
        public static bool CollectThreadInformation(IntPtr hProcess, out List<ThreadInfo> threadList)
        {
            threadList = new List<ThreadInfo>();

            try
            {
                // İşlem içindeki tüm thread'leri al
                Process process = Process.GetProcessById(WinEmuDump.Helpers.ProcessHelper.GetProcessIdFromHandle(hProcess));
                ProcessThreadCollection threads = process.Threads;

                foreach (ProcessThread thread in threads)
                {
                    try
                    {
                        ThreadInfo threadInfo = new ThreadInfo
                        {
                            ThreadId = (uint)thread.Id,
                            DumpFlags = 0x00000003, // Default dump flags
                            DumpError = 0,
                            ExitStatus = 259, // STILL_ACTIVE
                            CreateTime = 0UL, // Not available through ProcessThread
                            ExitTime = 0UL,
                            KernelTime = 0UL,
                            UserTime = 0UL,
                            StartAddress = 0UL, // Not available through ProcessThread
                            Affinity = 0UL
                        };

                        threadList.Add(threadInfo);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[WARNING] Thread {thread.Id} bilgileri alınamadı: {ex.Message}");
                        // Devam et, diğer thread'leri işle
                    }
                }

                Console.WriteLine($"[INFO] {threadList.Count} thread bilgisi toplandı");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ERROR] Thread bilgileri toplanamadı: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Hedef işlemin tüm thread'lerini CONTEXT bilgileri ile toplar
        /// </summary>
        /// <param name="hProcess">Hedef işlemin handle'ı</param>
        /// <param name="threadContexts">Thread CONTEXT bilgilerini içeren çıkış listesi</param>
        /// <returns>Başarılı ise true, aksi halde false</returns>
        public static bool CollectThreadContexts(IntPtr hProcess, out List<ThreadContextInfo> threadContexts)
        {
            threadContexts = new List<ThreadContextInfo>();

            try
            {
                Process process = Process.GetProcessById(WinEmuDump.Helpers.ProcessHelper.GetProcessIdFromHandle(hProcess));
                ProcessThreadCollection threads = process.Threads;

                foreach (ProcessThread thread in threads)
                {
                    try
                    {
                        // Thread handle'ını al
                        IntPtr threadHandle = IntPtr.Zero;
                        CLIENT_ID clientId = new CLIENT_ID
                        {
                            UniqueProcess = (IntPtr)process.Id,
                            UniqueThread = (IntPtr)thread.Id
                        };
                        OBJECT_ATTRIBUTES objAttr = new OBJECT_ATTRIBUTES { Length = (int)Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES)) };

                        uint ntStatus = NativeApi.NtOpenThread(ref threadHandle, ThreadConstants.THREAD_GET_CONTEXT, ref objAttr, ref clientId);
                        if (ntStatus != 0)
                        {
                            Console.WriteLine($"[WARNING] Thread {thread.Id} handle'ı açılamadı. NTSTATUS: 0x{ntStatus:X}");
                            continue;
                        }

                        // Thread CONTEXT'ini al
                        CONTEXT context = new CONTEXT { ContextFlags = 0x10001F }; // CONTEXT_FULL
                        ntStatus = NativeApi.NtGetContextThread(threadHandle, ref context);
                        if (ntStatus != 0)
                        {
                            Console.WriteLine($"[WARNING] Thread {thread.Id} CONTEXT'i alınamadı. NTSTATUS: 0x{ntStatus:X}");
                            NativeApi.NtClose(threadHandle);
                            continue;
                        }

                        ThreadContextInfo contextInfo = new ThreadContextInfo
                        {
                            ThreadId = (uint)thread.Id,
                            Context = context
                        };

                        threadContexts.Add(contextInfo);
                        NativeApi.NtClose(threadHandle);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[WARNING] Thread {thread.Id} CONTEXT bilgisi alınamadı: {ex.Message}");
                    }
                }

                Console.WriteLine($"[INFO] {threadContexts.Count} thread CONTEXT bilgisi toplandı");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ERROR] Thread CONTEXT bilgileri toplanamadı: {ex.Message}");
                return false;
            }
        }
    }
}