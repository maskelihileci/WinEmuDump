using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using static WinEmuDump.Win32;


namespace WinEmuDump
{
    internal class SystemInfoCollector
    {
        // SystemInfoCollector.cs - Sistem bilgilerini toplama işlevi
        // Bu dosya sistem bilgilerini, bellek bilgilerini ve diğer sistem verilerini toplar

        // Source File #3

        /// <summary>
        /// Sistem bilgilerini toplar
        /// </summary>
        /// <param name="systemInfo">Toplanan sistem bilgilerini içeren çıkış parametresi</param>
        /// <returns>Başarılı ise true, aksi halde false</returns>
        public static bool CollectSystemInfo(out SystemInfoData systemInfo)
        {
            systemInfo = new SystemInfoData();

            try
            {
                // İşletim sistemi sürüm bilgilerini al
                OSVERSIONINFOEX osVersion = new OSVERSIONINFOEX();
                osVersion.dwOSVersionInfoSize = Marshal.SizeOf(typeof(OSVERSIONINFOEX));
                if (RtlGetVersion(ref osVersion) != 0)
                {
                    Console.WriteLine("[WARNING] RtlGetVersion başarısız, varsayılan değerler kullanılıyor");
                    // Varsayılan değerler (Windows 10/11)
                    systemInfo.MajorVersion = 10;
                    systemInfo.MinorVersion = 0;
                    systemInfo.BuildNumber = 19041;
                    systemInfo.PlatformId = 2;
                    systemInfo.CSDVersion = "Windows 10";
                }
                else
                {
                    systemInfo.MajorVersion = (uint)osVersion.dwMajorVersion;
                    systemInfo.MinorVersion = (uint)osVersion.dwMinorVersion;
                    systemInfo.BuildNumber = (uint)osVersion.dwBuildNumber;
                    systemInfo.PlatformId = (uint)osVersion.dwPlatformId;
                    systemInfo.CSDVersion = osVersion.szCSDVersion;
                }

                // Sistem bilgilerini al
                SYSTEM_INFO sysInfo;
                GetSystemInfo(out sysInfo);
                systemInfo.ProcessorArchitecture = (ushort)sysInfo.wProcessorArchitecture;
                systemInfo.ProcessorCount = (byte)sysInfo.dwNumberOfProcessors;
                systemInfo.ProcessorLevel = sysInfo.wProcessorLevel;
                systemInfo.ProcessorRevision = sysInfo.wProcessorRevision;

                // Bellek bilgilerini al
                if (CollectMemoryInfo(out SYSTEM_MEMORY_INFO memoryInfo))
                {
                    systemInfo.TotalPhysicalMemory = memoryInfo.TotalPhysicalMemory;
                    systemInfo.AvailablePhysicalMemory = memoryInfo.AvailablePhysicalMemory;
                    systemInfo.TotalPageFile = memoryInfo.TotalPageFile;
                    systemInfo.AvailablePageFile = memoryInfo.AvailablePageFile;
                    systemInfo.TotalVirtualMemory = memoryInfo.TotalVirtual;
                    systemInfo.AvailableVirtualMemory = memoryInfo.AvailableVirtual;
                }

                Console.WriteLine($"[INFO] Sistem bilgileri toplandı: Windows {systemInfo.MajorVersion}.{systemInfo.MinorVersion} Build {systemInfo.BuildNumber}");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ERROR] Sistem bilgileri toplanamadı: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Sistem bellek bilgilerini toplar
        /// </summary>
        /// <param name="memoryInfo">Toplanan bellek bilgilerini içeren çıkış parametresi</param>
        /// <returns>Başarılı ise true, aksi halde false</returns>
        public static bool CollectMemoryInfo(out SYSTEM_MEMORY_INFO memoryInfo)
        {
            memoryInfo = new SYSTEM_MEMORY_INFO();

            try
            {
                // MEMORYSTATUSEX kullanarak bellek bilgilerini al
                MEMORYSTATUSEX memStatus = new MEMORYSTATUSEX();
                memStatus.dwLength = (uint)Marshal.SizeOf(typeof(MEMORYSTATUSEX));

                if (GlobalMemoryStatusEx(ref memStatus))
                {
                    memoryInfo.TotalPhysicalMemory = (uint)(memStatus.ullTotalPhys / 1024 / 1024); // MB
                    memoryInfo.AvailablePhysicalMemory = (uint)(memStatus.ullAvailPhys / 1024 / 1024);
                    memoryInfo.TotalPageFile = (uint)(memStatus.ullTotalPageFile / 1024 / 1024);
                    memoryInfo.AvailablePageFile = (uint)(memStatus.ullAvailPageFile / 1024 / 1024);
                    memoryInfo.TotalVirtual = (uint)(memStatus.ullTotalVirtual / 1024 / 1024);
                    memoryInfo.AvailableVirtual = (uint)(memStatus.ullAvailVirtual / 1024 / 1024);

                    Console.WriteLine($"[INFO] Bellek bilgileri toplandı: {memoryInfo.TotalPhysicalMemory}MB toplam, {memoryInfo.AvailablePhysicalMemory}MB kullanılabilir");
                    return true;
                }
                else
                {
                    Console.WriteLine("[WARNING] GlobalMemoryStatusEx başarısız");
                    return false;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ERROR] Bellek bilgileri toplanamadı: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// İşlem bilgilerini toplar
        /// </summary>
        /// <param name="hProcess">Hedef işlemin handle'ı</param>
        /// <param name="processInfo">Toplanan işlem bilgilerini içeren çıkış parametresi</param>
        /// <returns>Başarılı ise true, aksi halde false</returns>
        public static bool CollectProcessInfo(IntPtr hProcess, out ProcessInfoData processInfo)
        {
            processInfo = new ProcessInfoData();

            try
            {
                int processId = GetProcessIdFromHandle(hProcess);
                Process process = Process.GetProcessById(processId);

                processInfo.ProcessId = (uint)process.Id;
                processInfo.ParentProcessId = 0; // Process sınıfından doğrudan alınamıyor
                processInfo.CreateTime = DateTimeToFileTime(process.StartTime);
                processInfo.ExitTime = process.HasExited ? DateTimeToFileTime(process.ExitTime) : IntPtr.Zero;
                processInfo.UserTime = IntPtr.Zero; // Process sınıfından alınamıyor
                processInfo.KernelTime = IntPtr.Zero; // Process sınıfından alınamıyor
                processInfo.ImageName = process.ProcessName;
                processInfo.CommandLine = GetCommandLine(process);

                Console.WriteLine($"[INFO] İşlem bilgileri toplandı: {processInfo.ImageName} (PID: {processInfo.ProcessId})");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ERROR] İşlem bilgileri toplanamadı: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// İşlemin komut satırını alır
        /// </summary>
        /// <param name="process">Process nesnesi</param>
        /// <returns>Komut satırı</returns>
        private static string GetCommandLine(Process process)
        {
            try
            {
                return process.StartInfo.Arguments ?? "";
            }
            catch
            {
                return "";
            }
        }

        /// <summary>
        /// DateTime'ı FILETIME'a çevirir
        /// </summary>
        /// <param name="dateTime">DateTime değeri</param>
        /// <returns>FILETIME pointer</returns>
        private static IntPtr DateTimeToFileTime(DateTime dateTime)
        {
            try
            {
                long fileTime = dateTime.ToFileTime();
                return (IntPtr)fileTime;
            }
            catch
            {
                return IntPtr.Zero;
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

        // P/Invoke tanımlamaları
        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern uint RtlGetVersion(ref OSVERSIONINFOEX lpVersionInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX lpBuffer);

        [DllImport("kernel32.dll")]
        private static extern IntPtr LoadLibrary(string dllName);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string procedureName);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate uint GetProcessIdDelegate(IntPtr hProcess);

        // Ek struct tanımlamaları
        [StructLayout(LayoutKind.Sequential)]
        private struct MEMORYSTATUSEX
        {
            public uint dwLength;
            public uint dwMemoryLoad;
            public ulong ullTotalPhys;
            public ulong ullAvailPhys;
            public ulong ullTotalPageFile;
            public ulong ullAvailPageFile;
            public ulong ullTotalVirtual;
            public ulong ullAvailVirtual;
            public ulong ullAvailExtendedVirtual;
        }
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
        public uint TotalPhysicalMemory;
        public uint AvailablePhysicalMemory;
        public uint TotalPageFile;
        public uint AvailablePageFile;
        public uint TotalVirtualMemory;
        public uint AvailableVirtualMemory;
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
}