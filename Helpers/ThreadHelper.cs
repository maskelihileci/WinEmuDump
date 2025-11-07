using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using static WinEmuDump.Win32;

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
                        ThreadBasicInformation,
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
                        ThreadStackInformation,
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

                        uint ntStatus = NativeApi.NtOpenThread(ref threadHandle, THREAD_GET_CONTEXT, ref objAttr, ref clientId);
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