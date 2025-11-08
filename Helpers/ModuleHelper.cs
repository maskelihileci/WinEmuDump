using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;


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

namespace WinEmuDump.Helpers
{
    /// <summary>
    /// Module enumeration işlemleri
    /// Program.cs ve PeCollector.cs'den birleştirilmiş module operasyonları
    /// </summary>
    internal static class ModuleHelper
    {
        /// <summary>
        /// Process modüllerini toplar (Program.cs'den alınmış, geliştirilmiş versiyon)
        /// </summary>
        /// <param name="hProcess">Process handle'ı</param>
        /// <returns>ModuleInfo listesi</returns>
        public static List<ModuleInfo> CollectProcessModules(IntPtr hProcess)
        {
            var moduleList = new List<ModuleInfo>();

            try
            {
                int processId = ProcessHelper.GetProcessIdFromHandle(hProcess);
                if (processId == 0)
                {
                    Console.WriteLine("[WARNING] Process ID alınamadı");
                    return moduleList;
                }

                Process process = Process.GetProcessById(processId);

                // Ana modülü al
                var mainModule = GetMainModuleInfo(process);
                if (mainModule.BaseAddress != IntPtr.Zero)
                    moduleList.Add(mainModule);

                // Diğer modülleri topla
                foreach (ProcessModule module in process.Modules)
                {
                    try
                    {
                        if (module.BaseAddress != mainModule.BaseAddress) // Ana modülü tekrar ekleme
                        {
                            var moduleInfo = GetModuleInfo(module);
                            if (moduleInfo.BaseAddress != IntPtr.Zero)
                                moduleList.Add(moduleInfo);
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[WARNING] Module {module.ModuleName} işlenirken hata: {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[WARNING] Module bilgileri toplanırken hata: {ex.Message}");
            }

            return moduleList;
        }

        /// <summary>
        /// Process'in modüllerini PSAPI ile alır (PeCollector.cs'den alınmış, geliştirilmiş)
        /// </summary>
        /// <param name="hProcess">Process handle'ı</param>
        /// <param name="modules">Module listesi çıkış parametresi</param>
        /// <returns>Başarılı ise true</returns>
        public static bool GetProcessModules(IntPtr hProcess, out List<RTL_PROCESS_MODULE_INFORMATION> modules)
        {
            modules = new List<RTL_PROCESS_MODULE_INFORMATION>();

            try
            {
                // Maksimum 1024 module
                IntPtr[] moduleHandles = new IntPtr[1024];
                uint bufferSize = (uint)(moduleHandles.Length * IntPtr.Size);

                Console.WriteLine($"[DEBUG] PSAPI EnumProcessModules başlatılıyor...");

                if (PsApi.EnumProcessModules(hProcess, moduleHandles, bufferSize, out uint neededSize))
                {
                    Console.WriteLine($"[DEBUG] EnumProcessModules başarılı, neededSize={neededSize}");

                    int moduleCount = (int)(neededSize / IntPtr.Size);
                    Console.WriteLine($"[DEBUG] Toplam module sayısı: {moduleCount}");

                    for (int i = 0; i < moduleCount && i < moduleHandles.Length; i++)
                    {
                        IntPtr moduleHandle = moduleHandles[i];

                        if (moduleHandle != IntPtr.Zero)
                        {
                            long baseAddress = moduleHandle.ToInt64();

                            if (baseAddress < 0x10000 || baseAddress > 0x7FFFFFFFFFFFL)
                            {
                                Console.WriteLine($"[WARNING] Module {i}: Geçersiz base address @ 0x{baseAddress:X}, atlanıyor");
                                continue;
                            }

                            var moduleInfo = CreateRtlProcessModuleInformation(moduleHandle, hProcess);
                            if (moduleInfo.ImageBase != IntPtr.Zero)
                                modules.Add(moduleInfo);
                        }
                    }

                    Console.WriteLine($"[DEBUG] Toplam {modules.Count} modül başarıyla alındı");
                    return modules.Count > 0;
                }
                else
                {
                    int lastError = Marshal.GetLastWin32Error();
                    Console.WriteLine($"[WARNING] EnumProcessModules başarısız: LastError={lastError}");
                    return false;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[WARNING] GetProcessModules exception: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Ana modül bilgisini alır
        /// </summary>
        private static ModuleInfo GetMainModuleInfo(Process process)
        {
            try
            {
                return new ModuleInfo
                {
                    BaseAddress = process.MainModule.BaseAddress,
                    Size = (IntPtr)process.MainModule.ModuleMemorySize,
                    Timestamp = 0,
                    Checksum = 0,
                    ModuleNameRva = 0,
                    ImageName = Marshal.StringToHGlobalUni(process.MainModule.FileName)
                };
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[WARNING] Ana modül bilgisi alınamadı: {ex.Message}");
                return new ModuleInfo();
            }
        }

        /// <summary>
        /// ProcessModule'den ModuleInfo oluşturur
        /// </summary>
        private static ModuleInfo GetModuleInfo(ProcessModule module)
        {
            try
            {
                return new ModuleInfo
                {
                    BaseAddress = module.BaseAddress,
                    Size = (IntPtr)module.ModuleMemorySize,
                    Timestamp = 0,
                    Checksum = 0,
                    ModuleNameRva = 0,
                    ImageName = Marshal.StringToHGlobalUni(module.FileName)
                };
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[WARNING] Module bilgisi oluşturulamadı: {ex.Message}");
                return new ModuleInfo();
            }
        }

        /// <summary>
        /// RTL_PROCESS_MODULE_INFORMATION oluşturur
        /// </summary>
        private static RTL_PROCESS_MODULE_INFORMATION CreateRtlProcessModuleInformation(IntPtr moduleHandle, IntPtr hProcess)
        {
            try
            {
                var moduleInfo = new RTL_PROCESS_MODULE_INFORMATION(true);

                // Module base address
                moduleInfo.ImageBase = moduleHandle;

                // Module boyutunu güvenli şekilde hesapla
                moduleInfo.ImageSize = GetModuleImageSize(hProcess, moduleHandle);
                if (moduleInfo.ImageSize == 0)
                {
                    moduleInfo.ImageSize = 0x1000; // Fallback: 4KB
                }

                // Module name'i al
                StringBuilder moduleName = new StringBuilder(256);
                uint nameLength = PsApi.GetModuleBaseName(Process.GetCurrentProcess().Handle, moduleHandle, moduleName, 256);

                if (nameLength > 0)
                {
                    string name = moduleName.ToString();
                    byte[] nameBytes = System.Text.Encoding.ASCII.GetBytes(name);
                    int copyLength = Math.Min(nameBytes.Length, 256 - moduleInfo.OffsetToFileName);

                    Array.Copy(nameBytes, 0, moduleInfo.FullPathName, moduleInfo.OffsetToFileName, copyLength);
                    Console.WriteLine($"[DEBUG] Module: {name} @ 0x{moduleHandle:X}");
                }
                else
                {
                    Console.WriteLine($"[DEBUG] Module: İsim alınamadı @ 0x{moduleHandle:X}");
                }

                return moduleInfo;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[WARNING] RTL_PROCESS_MODULE_INFORMATION oluşturulamadı: {ex.Message}");
                return new RTL_PROCESS_MODULE_INFORMATION(true);
            }
        }

        /// <summary>
        /// Modülün gerçek boyutunu PE header'dan alır
        /// </summary>
        public static uint GetModuleImageSize(IntPtr hProcess, IntPtr moduleBase)
        {
            try
            {
                // PE offset'i oku
                byte[] peOffsetBytes = new byte[4];
                uint ntStatus = MemoryHelper.SafeReadVirtualMemory(hProcess, IntPtr.Add(moduleBase, 0x3C), peOffsetBytes, 4);
                if (ntStatus != 0)
                    return 0;

                int peOffset = BitConverter.ToInt32(peOffsetBytes, 0);

                // Magic byte'ı oku
                byte[] magicBytes = new byte[2];
                ntStatus = MemoryHelper.SafeReadVirtualMemory(hProcess, IntPtr.Add(moduleBase, peOffset + 4), magicBytes, 2);
                if (ntStatus != 0)
                    return 0;

                ushort magic = BitConverter.ToUInt16(magicBytes, 0);

                // SizeOfImage offset'i belirle
                int sizeOfImageOffset = magic == 0x20B ? peOffset + 4 + 20 + 64 : peOffset + 4 + 20 + 56;

                // SizeOfImage'ı oku
                byte[] sizeOfImageBytes = new byte[4];
                ntStatus = MemoryHelper.SafeReadVirtualMemory(hProcess, IntPtr.Add(moduleBase, sizeOfImageOffset), sizeOfImageBytes, 4);
                if (ntStatus != 0)
                    return 0;

                uint imageSize = BitConverter.ToUInt32(sizeOfImageBytes, 0);

                // Validasyon
                if (imageSize >= 0x1000 && imageSize <= 0x40000000) // 4KB - 1GB
                    return imageSize;

                if (imageSize > 0 && imageSize < 0x100000) // 1MB altı ama > 0
                    return imageSize;

                return 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[WARNING] GetModuleImageSize exception: {ex.Message}");
                return 0;
            }
        }

        /// <summary>
        /// Belirli bir adresin hangi modüle ait olduğunu bulur
        /// </summary>
        /// <param name="hProcess">Process handle'ı</param>
        /// <param name="address">Aranacak adres</param>
        /// <returns>Modül adı (bulunamazsa null)</returns>
        public static string FindModuleForAddress(IntPtr hProcess, ulong address)
        {
            try
            {
                var modules = CollectProcessModules(hProcess);

                foreach (var module in modules)
                {
                    try
                    {
                        ulong moduleBase = (ulong)module.BaseAddress.ToInt64();
                        ulong moduleSize = (ulong)module.Size.ToInt64();
                        ulong moduleEnd = moduleBase + moduleSize;

                        if (address >= moduleBase && address < moduleEnd)
                        {
                            string moduleName = "Unknown";
                            if (module.ImageName != IntPtr.Zero)
                            {
                                try
                                {
                                    moduleName = Marshal.PtrToStringUni(module.ImageName) ?? "Unknown";
                                }
                                catch
                                {
                                    moduleName = "Unknown";
                                }
                            }

                            return System.IO.Path.GetFileName(moduleName);
                        }
                    }
                    catch
                    {
                        continue;
                    }
                }

                return null;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[DEBUG] FindModuleForAddress exception: {ex.Message}");
                return null;
            }
        }
    }
}