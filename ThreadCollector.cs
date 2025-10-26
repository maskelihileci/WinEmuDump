using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using static WinEmuDump.Win32;


namespace WinEmuDump
{
    internal class ThreadCollector
    {
        // ThreadCollector.cs - İşlem thread'lerini toplama işlevi
        // Bu dosya işlemin tüm thread'lerini ve özelliklerini toplar

        // Source File #1

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
                Process process = Process.GetProcessById(GetProcessIdFromHandle(hProcess));
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
                            CreateTime = IntPtr.Zero, // Not available through ProcessThread
                            ExitTime = IntPtr.Zero,
                            KernelTime = IntPtr.Zero,
                            UserTime = IntPtr.Zero,
                            StartAddress = IntPtr.Zero, // Not available through ProcessThread
                            Affinity = IntPtr.Zero
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
        /// Hedef işlemin tüm thread'lerini gelişmiş bilgilerle toplar (TEB, Stack, Context)
        /// </summary>
        /// <param name="hProcess">Hedef işlemin handle'ı</param>
        /// <param name="threadInfos">Thread bilgilerini içeren çıkış listesi</param>
        /// <returns>Başarılı ise true, aksi halde false</returns>
        internal static bool CollectAdvancedThreadInformation(IntPtr hProcess, out List<MinidumpThreadInfo> threadInfos)
        {
            threadInfos = new List<MinidumpThreadInfo>();

            try
            {
                Console.WriteLine("[DEBUG] === CollectAdvancedThreadInformation BAŞLIYOR ===");
                Console.WriteLine($"[DEBUG] hProcess: 0x{hProcess:X}");

                // Process ID'yi al
                int processId = GetProcessIdFromHandle(hProcess);
                Console.WriteLine($"[DEBUG] Process ID: {processId}");

                // Process'i al
                Process process = Process.GetProcessById(processId);
                Console.WriteLine($"[DEBUG] Process nesnesi alındı: {process.ProcessName}");

                // Thread listesini al
                ProcessThreadCollection threads = process.Threads;
                Console.WriteLine($"[DEBUG] Toplam {threads.Count} thread bulundu");

                // Process'i suspend et
                Console.WriteLine("[DEBUG] Process suspend ediliyor...");
                bool suspendResult = SuspendProcess(hProcess);
                Console.WriteLine($"[DEBUG] Suspend result: {suspendResult}");

                int successfulThreads = 0;
                int failedThreads = 0;

                foreach (ProcessThread thread in threads)
                {
                    try
                    {
                        Console.WriteLine($"[DEBUG] Thread {thread.Id} işleniyor...");

                        // Thread handle'ını al
                        IntPtr threadHandle = IntPtr.Zero;
                        CLIENT_ID clientId = new CLIENT_ID
                        {
                            UniqueProcess = (IntPtr)process.Id,
                            UniqueThread = (IntPtr)thread.Id
                        };
                        OBJECT_ATTRIBUTES objAttr = new OBJECT_ATTRIBUTES { Length = (int)Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES)) };

                        Console.WriteLine($"[DEBUG] NtOpenThread çağrılıyor - Process: {clientId.UniqueProcess}, Thread: {clientId.UniqueThread}");
                        uint ntStatus = NtOpenThread(ref threadHandle, THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, ref objAttr, ref clientId);
                        Console.WriteLine($"[DEBUG] NtOpenThread result: 0x{ntStatus:X}, Handle: 0x{threadHandle:X}");

                        if (ntStatus != 0)
                        {
                            Console.WriteLine($"[WARNING] Thread {thread.Id} handle'ı açılamadı. NTSTATUS: 0x{ntStatus:X}");
                            failedThreads++;
                            continue;
                        }

                        // TEB adresini al
                        Console.WriteLine($"[DEBUG] Thread {thread.Id} için TEB adresi alınıyor...");
                        IntPtr tebAddress = GetThreadTebAddress(threadHandle);
                        Console.WriteLine($"[DEBUG] TEB Address: 0x{tebAddress:X}");

                        // Stack bilgilerini al
                        Console.WriteLine($"[DEBUG] Thread {thread.Id} için Stack bilgileri alınıyor...");
                        (IntPtr stackBase, uint stackSize) = GetThreadStackInfo(hProcess, threadHandle);
                        Console.WriteLine($"[DEBUG] Stack Base: 0x{stackBase:X}, Size: {stackSize}");

                        // Thread CONTEXT'ini al
                        Console.WriteLine($"[DEBUG] Thread {thread.Id} için CONTEXT alınıyor...");
                        CONTEXT context = new CONTEXT { ContextFlags = Win32.CONTEXT_FULL };
                        ntStatus = NtGetContextThread(threadHandle, ref context);
                        Console.WriteLine($"[DEBUG] NtGetContextThread result: 0x{ntStatus:X}");

                        if (ntStatus != 0)
                        {
                            Console.WriteLine($"[WARNING] Thread {thread.Id} CONTEXT'i alınamadı. NTSTATUS: 0x{ntStatus:X}");
                            NtClose(threadHandle);
                            failedThreads++;
                            continue;
                        }

                        MinidumpThreadInfo threadInfo = new MinidumpThreadInfo
                        {
                            ThreadId = (uint)thread.Id,
                            TebAddress = (ulong)tebAddress.ToInt64(),
                            StackBase = (ulong)stackBase.ToInt64(),
                            StackSize = stackSize,
                            Context = context
                        };

                        threadInfos.Add(threadInfo);
                        successfulThreads++;

                        NtClose(threadHandle);
                        Console.WriteLine($"[SUCCESS] Thread {thread.Id} başarıyla işlendi: TEB=0x{tebAddress:X}, Stack=0x{stackBase:X} ({stackSize} bytes)");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[WARNING] Thread {thread.Id} gelişmiş bilgileri alınamadı: {ex.Message}");
                        Console.WriteLine($"[DEBUG] Exception Details: {ex.StackTrace}");
                        failedThreads++;
                    }
                }

                // Process'i resume et
                Console.WriteLine("[DEBUG] Process resume ediliyor...");
                bool resumeResult = ResumeProcess(hProcess);
                Console.WriteLine($"[DEBUG] Resume result: {resumeResult}");

                Console.WriteLine($"[INFO] Thread toplama özeti: {successfulThreads} başarılı, {failedThreads} başarısız");
                Console.WriteLine($"[INFO] {threadInfos.Count} thread gelişmiş bilgileri toplandı");
                Console.WriteLine("[DEBUG] === CollectAdvancedThreadInformation BİTTİ ===");

                return successfulThreads > 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ERROR] Gelişmiş thread bilgileri toplanamadı: {ex.Message}");
                Console.WriteLine($"[DEBUG] Exception Details: {ex.StackTrace}");

                // Hata durumunda process'i resume etmeye çalış
                try
                {
                    Console.WriteLine("[DEBUG] Hata sonrası process resume ediliyor...");
                    ResumeProcess(hProcess);
                }
                catch (Exception resumeEx)
                {
                    Console.WriteLine($"[ERROR] Resume sırasında hata: {resumeEx.Message}");
                }

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
                Process process = Process.GetProcessById(GetProcessIdFromHandle(hProcess));
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

                        uint ntStatus = NtOpenThread(ref threadHandle, THREAD_GET_CONTEXT, ref objAttr, ref clientId);
                        if (ntStatus != 0)
                        {
                            Console.WriteLine($"[WARNING] Thread {thread.Id} handle'ı açılamadı. NTSTATUS: 0x{ntStatus:X}");
                            continue;
                        }

                        // Thread CONTEXT'ini al
                        CONTEXT context = new CONTEXT { ContextFlags = 0x10001F }; // CONTEXT_FULL
                        ntStatus = NtGetContextThread(threadHandle, ref context);
                        if (ntStatus != 0)
                        {
                            Console.WriteLine($"[WARNING] Thread {thread.Id} CONTEXT'i alınamadı. NTSTATUS: 0x{ntStatus:X}");
                            NtClose(threadHandle);
                            continue;
                        }

                        ThreadContextInfo contextInfo = new ThreadContextInfo
                        {
                            ThreadId = (uint)thread.Id,
                            Context = context
                        };

                        threadContexts.Add(contextInfo);
                        NtClose(threadHandle);
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

        /// <summary>
        /// Process handle'ından process ID'sini çıkarır
        /// </summary>
        /// <param name="hProcess">Process handle'ı</param>
        /// <returns>Process ID</returns>
        private static int GetProcessIdFromHandle(IntPtr hProcess)
        {
            try
            {
                // Kernel32.dll'deki GetProcessId fonksiyonunu kullan
                IntPtr kernel32 = LoadLibrary("kernel32.dll");
                IntPtr getProcessId = GetProcAddress(kernel32, "GetProcessId");

                if (getProcessId != IntPtr.Zero)
                {
                    GetProcessIdDelegate getPid = Marshal.GetDelegateForFunctionPointer<GetProcessIdDelegate>(getProcessId);
                    return (int)getPid(hProcess);
                }
            }
            catch
            {
                // Fallback: Mevcut process ise kendi ID'mizi döndür
                return Process.GetCurrentProcess().Id;
            }

            return 0;
        }

        [DllImport("kernel32.dll")]
        private static extern IntPtr LoadLibrary(string dllName);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string procedureName);

        /// <summary>
        /// TEB (Thread Environment Block) adresini alır
        /// </summary>
        /// <param name="threadHandle">Thread handle'ı</param>
        /// <returns>TEB adresi</returns>
        private static IntPtr GetThreadTebAddress(IntPtr threadHandle)
        {
            try
            {
                // ThreadInformationClass.ThreadBasicInformation kullan
                const uint ThreadBasicInformation = 0;
                IntPtr pThreadInfo = Marshal.AllocHGlobal(48); // THREAD_BASIC_INFORMATION boyutu
                try
                {
                    uint ntStatus = NtQueryInformationThread(threadHandle, ThreadBasicInformation, pThreadInfo, 48, out _);
                    if (ntStatus != 0)
                    {
                        Console.WriteLine($"[WARNING] NtQueryInformationThread başarısız: 0x{ntStatus:X}");
                        return IntPtr.Zero;
                    }

                    // THREAD_BASIC_INFORMATION'dan TebBaseAddress'i oku (offset 8)
                    IntPtr tebAddress = Marshal.ReadIntPtr(pThreadInfo, 8);
                    return tebAddress;
                }
                finally
                {
                    Marshal.FreeHGlobal(pThreadInfo);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ERROR] TEB adresi alınamadı: {ex.Message}");
                return IntPtr.Zero;
            }
        }

        /// <summary>
        /// Thread'in stack bilgilerini toplar
        /// </summary>
        /// <param name="hProcess">Process handle'ı</param>
        /// <param name="threadHandle">Thread handle'ı</param>
        /// <returns>Stack başlangıç adresi ve boyutu</returns>
        private static (IntPtr baseAddress, uint size) GetThreadStackInfo(IntPtr hProcess, IntPtr threadHandle)
        {
            try
            {
                IntPtr tebAddress = GetThreadTebAddress(threadHandle);
                if (tebAddress == IntPtr.Zero)
                    return (IntPtr.Zero, 0);

                // TEB'den stack bilgilerini oku (x64 için offset'ler)
                // StackBase: offset 0x08 (TEB + 8)
                // StackLimit: offset 0x10 (TEB + 16)

                IntPtr stackBase = IntPtr.Zero;
                IntPtr stackLimit = IntPtr.Zero;

                // StackBase oku
                uint ntStatus = NtReadVirtualMemory(hProcess, IntPtr.Add(tebAddress, 8), ref stackBase, (IntPtr)IntPtr.Size, out _);
                if (ntStatus != 0)
                {
                    Console.WriteLine($"[WARNING] StackBase okunamadı: 0x{ntStatus:X}");
                    return (IntPtr.Zero, 0);
                }

                // StackLimit oku
                ntStatus = NtReadVirtualMemory(hProcess, IntPtr.Add(tebAddress, 16), ref stackLimit, (IntPtr)IntPtr.Size, out _);
                if (ntStatus != 0)
                {
                    Console.WriteLine($"[WARNING] StackLimit okunamadı: 0x{ntStatus:X}");
                    return (IntPtr.Zero, 0);
                }

                // Stack boyutu hesapla (StackBase - StackLimit)
                long stackSize = (long)stackBase - (long)stackLimit;
                if (stackSize <= 0 || stackSize > 1024 * 1024 * 10) // 10MB'den büyük olmamalı
                {
                    Console.WriteLine($"[WARNING] Geçersiz stack boyutu: {stackSize}");
                    return (IntPtr.Zero, 0);
                }

                return (stackLimit, (uint)stackSize);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ERROR] Stack bilgileri alınamadı: {ex.Message}");
                return (IntPtr.Zero, 0);
            }
        }

        /// <summary>
        /// Process'i suspend eder
        /// </summary>
        /// <param name="hProcess">Process handle'ı</param>
        /// <returns>Başarılı ise true</returns>
        private static bool SuspendProcess(IntPtr hProcess)
        {
            try
            {
                Process process = Process.GetProcessById(GetProcessIdFromHandle(hProcess));
                if (process == null)
                    return false;

                foreach (ProcessThread thread in process.Threads)
                {
                    try
                    {
                        IntPtr threadHandle = IntPtr.Zero;
                        CLIENT_ID clientId = new CLIENT_ID
                        {
                            UniqueProcess = (IntPtr)process.Id,
                            UniqueThread = (IntPtr)thread.Id
                        };
                        OBJECT_ATTRIBUTES objAttr = new OBJECT_ATTRIBUTES { Length = (int)Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES)) };

                        uint ntStatus = NtOpenThread(ref threadHandle, THREAD_SUSPEND_RESUME, ref objAttr, ref clientId);
                        if (ntStatus == 0)
                        {
                            NtSuspendThread(threadHandle, out _);
                            NtClose(threadHandle);
                        }
                    }
                    catch
                    {
                        // Thread suspend edilemedi, devam et
                    }
                }
                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Process'i resume eder
        /// </summary>
        /// <param name="hProcess">Process handle'ı</param>
        /// <returns>Başarılı ise true</returns>
        private static bool ResumeProcess(IntPtr hProcess)
        {
            try
            {
                Process process = Process.GetProcessById(GetProcessIdFromHandle(hProcess));
                if (process == null)
                    return false;

                foreach (ProcessThread thread in process.Threads)
                {
                    try
                    {
                        IntPtr threadHandle = IntPtr.Zero;
                        CLIENT_ID clientId = new CLIENT_ID
                        {
                            UniqueProcess = (IntPtr)process.Id,
                            UniqueThread = (IntPtr)thread.Id
                        };
                        OBJECT_ATTRIBUTES objAttr = new OBJECT_ATTRIBUTES { Length = (int)Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES)) };

                        uint ntStatus = NtOpenThread(ref threadHandle, THREAD_SUSPEND_RESUME, ref objAttr, ref clientId);
                        if (ntStatus == 0)
                        {
                            NtResumeThread(threadHandle, out _);
                            NtClose(threadHandle);
                        }
                    }
                    catch
                    {
                        // Thread resume edilemedi, devam et
                    }
                }
                return true;
            }
            catch
            {
                return false;
            }
        }

        // THREAD_SUSPEND_RESUME constant
        private const uint THREAD_SUSPEND_RESUME = 0x0002;

        [DllImport("ntdll.dll")]
        private static extern uint NtSuspendThread(IntPtr ThreadHandle, out uint PreviousSuspendCount);

        [DllImport("ntdll.dll")]
        private static extern uint NtResumeThread(IntPtr ThreadHandle, out uint PreviousSuspendCount);

        [DllImport("ntdll.dll")]
        private static extern uint NtReadVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, ref IntPtr Buffer, IntPtr BufferSize, out IntPtr NumberOfBytesRead);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate uint GetProcessIdDelegate(IntPtr hProcess);
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
}