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
}