using System;
using System.Diagnostics;
using System.Runtime.InteropServices;


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




namespace WinEmuDump.Helpers
{
    internal static class SystemInfoHelper
    {
        // SystemInfoCollector.cs içeriği buraya taşınacak

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
                Kernel32Api.GetSystemInfo(out sysInfo);

                // SuiteMask bilgisini al (OSVERSIONINFOEX kullanarak)
                systemInfo.SuiteMask = SystemInfoHelper.GetSuiteMask();

                // Gerçek processor architecture'ı tespit et
                // Hedef process'in architecture'ını kontrol et
                systemInfo.ProcessorArchitecture = SystemInfoHelper.DetectProcessArchitecture(hProcess);
                systemInfo.ProcessorCount = (byte)sysInfo.dwNumberOfProcessors;
                systemInfo.ProcessorLevel = sysInfo.wProcessorLevel;
                systemInfo.ProcessorRevision = sysInfo.wProcessorRevision;

                Console.WriteLine($"[DEBUG] ProcessorArchitecture tespit edildi: {systemInfo.ProcessorArchitecture} ({(systemInfo.ProcessorArchitecture == 9 ? "x64" : systemInfo.ProcessorArchitecture == 0 ? "x86" : "Unknown")})");

                // CPU bilgilerini topla
                SystemInfoHelper.CollectCpuInfo(out systemInfo.VendorId0, out systemInfo.VendorId1, out systemInfo.VendorId2,
                                                   out systemInfo.VersionInformation, out systemInfo.FeatureInformation, out systemInfo.AMDExtendedCpuFeatures);

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

                Console.WriteLine($"[DEBUG] CPU bilgileri toplandı:");
                Console.WriteLine($"  - VendorId0: 0x{systemInfo.VendorId0:X}");
                Console.WriteLine($"  - VendorId1: 0x{systemInfo.VendorId1:X}");
                Console.WriteLine($"  - VendorId2: 0x{systemInfo.VendorId2:X}");
                Console.WriteLine($"  - VersionInformation: 0x{systemInfo.VersionInformation:X}");
                Console.WriteLine($"  - FeatureInformation: 0x{systemInfo.FeatureInformation:X}");
                Console.WriteLine($"  - AMDExtendedCpuFeatures: 0x{systemInfo.AMDExtendedCpuFeatures:X}");

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
                if (Kernel32Api.IsWow64Process(hProcess, out isWow64))
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
                    Kernel32Api.GetSystemInfo(out sysInfo);
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

                if (Kernel32Api.GlobalMemoryStatusEx(ref memStatus))
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
        /// Sistem SuiteMask bilgisini alır
        /// </summary>
        /// <returns>SuiteMask değeri</returns>
        public static ushort GetSuiteMask()
        {
            try
            {
                // OSVERSIONINFOEX yapısını kullanarak suite bilgilerini al
                OSVERSIONINFOEX versionInfo = new OSVERSIONINFOEX();
                versionInfo.dwOSVersionInfoSize = Marshal.SizeOf(typeof(OSVERSIONINFOEX));

                uint ntstatus = NativeApi.RtlGetVersion(ref versionInfo);

                if (ntstatus == 0)
                {
                    Console.WriteLine($"[DEBUG] SuiteMask alındı: 0x{versionInfo.wSuiteMask:X}");
                    return (ushort)versionInfo.wSuiteMask;
                }
                else
                {
                    Console.WriteLine($"[WARNING] RtlGetVersion başarısız, NTSTATUS: 0x{ntstatus:X}");
                    // Fallback: Varsayılan değerler
                    // VER_SUITE_SINGLE_USERTS = 0x100 - Single User Terminal Services
                    // VER_SUITE_SINGLEUSERTS = 0x100 - Single User
                    // Modern Windows sistemler için uygun değer
                    return 0x100; // VER_SUITE_SINGLE_USERTS
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[WARNING] SuiteMask alınamadı: {ex.Message}");
                // Varsayılan değer döndür
                return 0x100; // VER_SUITE_SINGLE_USERTS
            }
        }

        /// <summary>
        /// CPU bilgilerini toplar (Vendor ID, Version, Feature flags)
        /// </summary>
        /// <param name="vendorId0">CPU Vendor ID - İlk 4 byte</param>
        /// <param name="vendorId1">CPU Vendor ID - İkinci 4 byte</param>
        /// <param name="vendorId2">CPU Vendor ID - Üçüncü 4 byte</param>
        /// <param name="versionInformation">CPU Version Information</param>
        /// <param name="featureInformation">CPU Feature Information</param>
        /// <param name="amdExtendedCpuFeatures">AMD Extended CPU Features</param>
        public static void CollectCpuInfo(out uint vendorId0, out uint vendorId1, out uint vendorId2,
                                         out uint versionInformation, out uint featureInformation, out uint amdExtendedCpuFeatures)
        {
            vendorId0 = 0;
            vendorId1 = 0;
            vendorId2 = 0;
            versionInformation = 0;
            featureInformation = 0;
            amdExtendedCpuFeatures = 0;

            try
            {
                // CPU bilgilerini CpuHelper'dan al
                CpuHelper.GetCpuInfo(out vendorId0, out vendorId1, out vendorId2,
                                    out versionInformation, out featureInformation, out amdExtendedCpuFeatures);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[WARNING] CPU bilgileri alınamadı: {ex.Message}");
                // Varsayılan değerlerle devam et
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
                int processId = (int)Kernel32Api.GetProcessId(hProcess);
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
                        uint ntstatus = NativeApi.NtQueryInformationProcess(hProcess, 4, processTimesPtr, processTimesSize, out uint returnLength); // ProcessTimes = 4

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
    }
}