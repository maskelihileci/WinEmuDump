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
        /// <param name="hProcess">Hedef işlemin handle'ı (architecture tespiti için)</param>
        /// <param name="systemInfo">Toplanan sistem bilgilerini içeren çıkış parametresi</param>
        /// <returns>Başarılı ise true, aksi halde false</returns>
        public static bool CollectSystemInfo(IntPtr hProcess, out SystemInfoData systemInfo)
        {
            systemInfo = new SystemInfoData();

            try
            {
                // İşletim sistemi sürüm bilgilerini al - Windows Registry kullanarak (gerçek API yaklaşımı)
                try
                {
                    using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion"))
                    {
                        if (key != null)
                        {
                            // Windows 10+ için yeni registry anahtarları
                            object majorVersion = key.GetValue("CurrentMajorVersionNumber");
                            object minorVersion = key.GetValue("CurrentMinorVersionNumber");
                            object buildNumber = key.GetValue("CurrentBuildNumber");

                            if (majorVersion != null && minorVersion != null && buildNumber != null)
                            {
                                systemInfo.MajorVersion = Convert.ToUInt32(majorVersion);
                                systemInfo.MinorVersion = Convert.ToUInt32(minorVersion);
                                systemInfo.BuildNumber = Convert.ToUInt32(buildNumber);
                            }
                            else
                            {
                                // Eski registry anahtarları (Windows 8 ve öncesi)
                                object version = key.GetValue("CurrentVersion");
                                if (version != null)
                                {
                                    Version ver = new Version(version.ToString());
                                    systemInfo.MajorVersion = (uint)ver.Major;
                                    systemInfo.MinorVersion = (uint)ver.Minor;
                                }
                                object build = key.GetValue("CurrentBuild");
                                if (build != null)
                                {
                                    systemInfo.BuildNumber = Convert.ToUInt32(build);
                                }
                            }

                            systemInfo.PlatformId = 2; // VER_PLATFORM_WIN32_NT

                            // CSDVersion - Windows 10+ için boş bırak (service pack yok)
                            systemInfo.CSDVersion = "";

                            key.Close();
                        }
                        else
                        {
                            Console.WriteLine("[WARNING] Windows registry anahtarı bulunamadı, Environment.OSVersion kullanılıyor");
                            // Fallback: Environment.OSVersion
                            Version osVersion = Environment.OSVersion.Version;
                            systemInfo.MajorVersion = (uint)osVersion.Major;
                            systemInfo.MinorVersion = (uint)osVersion.Minor;
                            systemInfo.BuildNumber = (uint)osVersion.Build;
                            systemInfo.PlatformId = (uint)Environment.OSVersion.Platform;
                            systemInfo.CSDVersion = "";
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[ERROR] OS sürüm bilgileri alınamadı: {ex.Message}");
                    return false;
                }

                // Sistem bilgilerini al
                SYSTEM_INFO sysInfo;
                GetSystemInfo(out sysInfo);

                // Gerçek processor architecture'ı tespit et
                // Hedef process'in architecture'ını kontrol et
                systemInfo.ProcessorArchitecture = SystemInfoCollector.DetectProcessArchitecture(hProcess);
                systemInfo.ProcessorCount = (byte)sysInfo.dwNumberOfProcessors;
                systemInfo.ProcessorLevel = sysInfo.wProcessorLevel;
                systemInfo.ProcessorRevision = sysInfo.wProcessorRevision;

                Console.WriteLine($"[DEBUG] ProcessorArchitecture tespit edildi: {systemInfo.ProcessorArchitecture} ({(systemInfo.ProcessorArchitecture == 9 ? "x64" : systemInfo.ProcessorArchitecture == 0 ? "x86" : "Unknown")})");

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
        /// Process'in gerçek architecture'ını tespit eder
        /// </summary>
        /// <param name="hProcess">Process handle'ı</param>
        /// <returns>Processor architecture (9=x64, 0=x86)</returns>
        public static ushort DetectProcessArchitecture(IntPtr hProcess)
        {
            try
            {
                // Önce sistem mimarisini kontrol et - Environment.Is64BitOperatingSystem daha güvenilir
                bool isSystem64Bit = Environment.Is64BitOperatingSystem;

                if (!isSystem64Bit)
                {
                    // Sistem 32-bit ise, process de 32-bit olur
                    return 0; // PROCESSOR_ARCHITECTURE_INTEL = 0 (x86)
                }

                // Sistem 64-bit ise, process'in WOW64 altında çalışıp çalışmadığını kontrol et
                bool isWow64;
                if (IsWow64Process(hProcess, out isWow64))
                {
                    if (isWow64)
                    {
                        // Process WOW64 altında çalışıyor, yani x86 process x64 sistemde
                        return 0; // PROCESSOR_ARCHITECTURE_INTEL = 0 (x86)
                    }
                    else
                    {
                        // Process WOW64 altında çalışmıyor, sistem x64 ise x64
                        return 9; // PROCESSOR_ARCHITECTURE_AMD64 = 9 (x64)
                    }
                }
                else
                {
                    // IsWow64Process başarısız oldu, fallback olarak sistem mimarisi
                    // Sistem x64 ise ve process WOW64 altında değilse x64 varsay
                    Console.WriteLine("[WARNING] IsWow64Process failed, assuming x64 for 64-bit system");
                    return 9; // x64 varsay
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[WARNING] Process architecture detection failed: {ex.Message}");
                // En son çare: Environment.Is64BitOperatingSystem kullan
                try
                {
                    bool isSystem64Bit = Environment.Is64BitOperatingSystem;
                    return isSystem64Bit ? (ushort)9 : (ushort)0;
                }
                catch
                {
                    // Son fallback: Sistem bilgilerini kullan
                    SYSTEM_INFO sysInfo;
                    GetSystemInfo(out sysInfo);
                    return (ushort)sysInfo.wProcessorArchitecture;
                }
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

        // Gerçek işlem zamanlarını NtQueryInformationProcess ile al
        try
        {
            // PROCESS_TIMES yapısı için gerekli boyutu hesapla
            uint processTimesSize = (uint)(Marshal.SizeOf(typeof(long)) * 4); // CreateTime, ExitTime, KernelTime, UserTime
            IntPtr processTimesPtr = Marshal.AllocHGlobal((int)processTimesSize);

            try
            {
                uint ntstatus = NtQueryInformationProcess(hProcess, 4, processTimesPtr, processTimesSize, out uint returnLength); // ProcessTimes = 4

                if (ntstatus == 0 && returnLength >= processTimesSize)
                {
                    // FILETIME değerlerini oku (saniye cinsinden, 1970'den beri)
                    long createTime = Marshal.ReadInt64(processTimesPtr, 0);
                    long exitTime = Marshal.ReadInt64(processTimesPtr, 8);
                    long kernelTime = Marshal.ReadInt64(processTimesPtr, 16);
                    long userTime = Marshal.ReadInt64(processTimesPtr, 24);

                    // .NET DateTime'a çevir ve FILETIME'a geri çevir
                    processInfo.UserTime = (IntPtr)userTime;
                    processInfo.KernelTime = (IntPtr)kernelTime;

                    Console.WriteLine($"[DEBUG] Process times - User: {userTime}, Kernel: {kernelTime}");
                }
                else
                {
                    // Fallback: Process.TotalProcessorTime kullan
                    TimeSpan totalProcessorTime = process.TotalProcessorTime;
                    TimeSpan privilegedProcessorTime = process.PrivilegedProcessorTime;
                    TimeSpan userProcessorTime = totalProcessorTime - privilegedProcessorTime;

                    processInfo.UserTime = (IntPtr)(userProcessorTime.Ticks * 100);
                    processInfo.KernelTime = (IntPtr)(privilegedProcessorTime.Ticks * 100);

                    Console.WriteLine($"[DEBUG] Fallback process times - User: {processInfo.UserTime}, Kernel: {processInfo.KernelTime}");
                }
            }
            finally
            {
                Marshal.FreeHGlobal(processTimesPtr);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[WARNING] Process times alınamadı: {ex.Message}");
            processInfo.UserTime = IntPtr.Zero;
            processInfo.KernelTime = IntPtr.Zero;
        }

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