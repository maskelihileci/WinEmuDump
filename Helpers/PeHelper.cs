using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

// IMAGE_EXPORT_DIRECTORY - Export directory table
[StructLayout(LayoutKind.Sequential)]
public struct IMAGE_EXPORT_DIRECTORY
{
    public uint Characteristics;
    public uint TimeDateStamp;
    public ushort MajorVersion;
    public ushort MinorVersion;
    public uint Name;
    public uint Base;
    public uint NumberOfFunctions;
    public uint NumberOfNames;
    public uint AddressOfFunctions;     // RVA to function address array
    public uint AddressOfNames;         // RVA to function name array
    public uint AddressOfNameOrdinals;  // RVA to function ordinal array
}

internal struct PEHeaderConstants
{
    public const uint IMAGE_DOS_SIGNATURE = 0x5A4D;  // "MZ"
    public const uint IMAGE_NT_SIGNATURE = 0x00004550; // "PE\0\0"
    public const ushort IMAGE_FILE_MACHINE_AMD64 = 0x8664;
    public const ushort IMAGE_FILE_MACHINE_I386 = 0x014c;
    public const uint IMAGE_DIRECTORY_ENTRY_EXPORT = 0;  // Export Directory
    public const uint IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3; // Exception Directory
}


// FunctionExport - Export function bilgileri
[StructLayout(LayoutKind.Sequential)]
public struct FunctionExport
{
    public string FunctionName;
    public IntPtr FunctionAddress;
    public uint Ordinal;
}

namespace WinEmuDump.Helpers
{
    /// <summary>
    /// PE (Portable Executable) dosya işleme fonksiyonları
    /// PeCollector.cs'den birleştirilmiş PE parsing kodları
    /// </summary>
    internal static class PeHelper
    {

        // Helper classes for PE parsing
        private class FileHeaderInfo
        {
            public ushort Machine { get; set; }
            public ushort NumberOfSections { get; set; }
            public ushort SizeOfOptionalHeader { get; set; }
        }

        private class DataDirectoryInfo
        {
            public uint NumberOfRvaAndSizes { get; set; }
            public int ExportRvaOffset { get; set; }
            public int ExportRva { get; set; }
        }

        private class ExportDirectoryInfo
        {
            public uint NumberOfFunctions { get; set; }
            public uint NumberOfNames { get; set; }
            public uint AddressOfFunctions { get; set; }
            public uint AddressOfNames { get; set; }
            public uint AddressOfNameOrdinals { get; set; }
            public uint BaseOrdinal { get; set; }
        }



        /// <summary>
        /// Modülün PE export bilgilerini parse eder
        /// PeCollector.cs'den alınmış, güvenli versiyon
        /// </summary>
        /// <param name="hProcess">Hedef process handle'ı</param>
        /// <param name="moduleBase">Modül base address</param>
        /// <param name="exports">Parse edilen export'lar</param>
        /// <returns>Başarılı ise true</returns>
        public static bool ParsePeExportsSafe(IntPtr hProcess, IntPtr moduleBase, out List<FunctionExport> exports)
        {
            exports = new List<FunctionExport>();

            try
            {
                // Memory address validation
                if (moduleBase == IntPtr.Zero)
                {
                    Console.WriteLine($"[DEBUG] ParsePeExportsSafe: Null module base address");
                    return false;
                }

                long baseAddress = moduleBase.ToInt64();

                // Geçersiz adres aralıkları kontrolü
                if (baseAddress < 0x10000 || baseAddress > 0x7FFFFFFFFFFFL)
                {
                    Console.WriteLine($"[DEBUG] ParsePeExportsSafe: Module base address geçersiz aralıkta: 0x{baseAddress:X}");
                    return false;
                }

                // DOS signature kontrolü
                if (!ValidateDosSignature(hProcess, moduleBase))
                    return false;

                // PE header offset'i alma
                int peOffset = GetPeOffset(hProcess, moduleBase);
                if (peOffset <= 0)
                    return false;

                // PE signature kontrolü
                if (!ValidatePeSignature(hProcess, moduleBase, peOffset))
                    return false;

                // File header okuma
                var fileHeaderInfo = ReadFileHeader(hProcess, moduleBase, peOffset);
                if (fileHeaderInfo == null)
                    return false;

                // Export directory parsing
                return ParseExportDirectory(hProcess, moduleBase, peOffset, fileHeaderInfo, exports);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[DEBUG] ParsePeExportsSafe: Exception for module 0x{moduleBase:X} - {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// DOS signature'ı validate eder
        /// </summary>
        private static bool ValidateDosSignature(IntPtr hProcess, IntPtr moduleBase)
        {
            byte[] dosMagicBytes = new byte[2];
            uint ntStatus = MemoryHelper.SafeReadVirtualMemory(hProcess, moduleBase, dosMagicBytes, 2);
            if (ntStatus != 0)
            {
                Console.WriteLine($"[DEBUG] DOS magic okunamıyor, NTSTATUS=0x{ntStatus:X}");
                return false;
            }

            ushort dosMagic = (ushort)(dosMagicBytes[0] | (dosMagicBytes[1] << 8));
            return dosMagic == PEHeaderConstants.IMAGE_DOS_SIGNATURE;
        }

        /// <summary>
        /// PE header offset'ini alır
        /// </summary>
        private static int GetPeOffset(IntPtr hProcess, IntPtr moduleBase)
        {
            byte[] peOffsetBytes = new byte[4];
            uint ntStatus = MemoryHelper.SafeReadVirtualMemory(hProcess, IntPtr.Add(moduleBase, 0x3C), peOffsetBytes, 4);
            if (ntStatus != 0)
                return 0;

            int peOffset = BitConverter.ToInt32(peOffsetBytes, 0);
            return (peOffset > 0 && peOffset <= 0x100000) ? peOffset : 0;
        }

        /// <summary>
        /// PE signature'ı validate eder
        /// </summary>
        private static bool ValidatePeSignature(IntPtr hProcess, IntPtr moduleBase, int peOffset)
        {
            byte[] peSignatureBytes = new byte[4];
            uint ntStatus = MemoryHelper.SafeReadVirtualMemory(hProcess, IntPtr.Add(moduleBase, peOffset), peSignatureBytes, 4);
            if (ntStatus != 0)
                return false;

            uint peSignature = BitConverter.ToUInt32(peSignatureBytes, 0);
            return peSignature == PEHeaderConstants.IMAGE_NT_SIGNATURE;
        }

        /// <summary>
        /// File header'ı okur ve bilgileri döndürür
        /// </summary>
        private static FileHeaderInfo ReadFileHeader(IntPtr hProcess, IntPtr moduleBase, int peOffset)
        {
            int fileHeaderOffset = peOffset + 4;
            byte[] fileHeaderBytes = new byte[20];
            uint ntStatus = MemoryHelper.SafeReadVirtualMemory(hProcess, IntPtr.Add(moduleBase, fileHeaderOffset), fileHeaderBytes, 20);
            if (ntStatus != 0)
                return null;

            return new FileHeaderInfo
            {
                Machine = BitConverter.ToUInt16(fileHeaderBytes, 0),
                NumberOfSections = BitConverter.ToUInt16(fileHeaderBytes, 2),
                SizeOfOptionalHeader = BitConverter.ToUInt16(fileHeaderBytes, 16)
            };
        }

        /// <summary>
        /// Export directory'yi parse eder
        /// </summary>
        private static bool ParseExportDirectory(IntPtr hProcess, IntPtr moduleBase, int peOffset, FileHeaderInfo fileHeaderInfo, List<FunctionExport> exports)
        {
            try
            {
                int optionalHeaderOffset = peOffset + 4 + 20;
                ushort magic = ReadOptionalHeaderMagic(hProcess, moduleBase, optionalHeaderOffset);
                if (magic == 0)
                    return false;

                var dataDirInfo = GetDataDirectoryInfo(hProcess, moduleBase, optionalHeaderOffset, magic);
                if (dataDirInfo == null)
                    return false;

                // Export directory bilgilerini oku
                var exportInfo = ReadExportDirectoryInfo(hProcess, moduleBase, dataDirInfo.ExportRva);
                if (exportInfo == null)
                    return false;

                // Function export'larını parse et
                return ParseExportFunctions(hProcess, moduleBase, exportInfo, exports);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[DEBUG] ParseExportDirectory exception: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Optional header magic değerini okur
        /// </summary>
        private static ushort ReadOptionalHeaderMagic(IntPtr hProcess, IntPtr moduleBase, int optionalHeaderOffset)
        {
            byte[] magicBytes = new byte[2];
            uint ntStatus = MemoryHelper.SafeReadVirtualMemory(hProcess, IntPtr.Add(moduleBase, optionalHeaderOffset), magicBytes, 2);
            if (ntStatus != 0)
                return 0;

            return BitConverter.ToUInt16(magicBytes, 0);
        }

        /// <summary>
        /// Data directory bilgilerini alır
        /// </summary>
        private static DataDirectoryInfo GetDataDirectoryInfo(IntPtr hProcess, IntPtr moduleBase, int optionalHeaderOffset, ushort magic)
        {
            int dataDirectoryOffset = magic == 0x20B ? optionalHeaderOffset + 112 : optionalHeaderOffset + 96;
            byte[] rvaSizesBytes = new byte[4];
            uint ntStatus = MemoryHelper.SafeReadVirtualMemory(hProcess, IntPtr.Add(moduleBase, dataDirectoryOffset), rvaSizesBytes, 4);
            if (ntStatus != 0)
                return null;

            uint numberOfRvaAndSizes = BitConverter.ToUInt32(rvaSizesBytes, 0);
            if (numberOfRvaAndSizes <= PEHeaderConstants.IMAGE_DIRECTORY_ENTRY_EXPORT)
                return null;

            return new DataDirectoryInfo
            {
                NumberOfRvaAndSizes = numberOfRvaAndSizes,
                ExportRvaOffset = dataDirectoryOffset + (int)(PEHeaderConstants.IMAGE_DIRECTORY_ENTRY_EXPORT * 8)
            };
        }

        /// <summary>
        /// Export directory bilgilerini okur
        /// </summary>
        private static ExportDirectoryInfo ReadExportDirectoryInfo(IntPtr hProcess, IntPtr moduleBase, int exportRva)
        {
            byte[] exportDirBytes = new byte[40];
            uint ntStatus = MemoryHelper.SafeReadVirtualMemory(hProcess, IntPtr.Add(moduleBase, exportRva), exportDirBytes, 40);
            if (ntStatus != 0)
                return null;

            return new ExportDirectoryInfo
            {
                NumberOfFunctions = BitConverter.ToUInt32(exportDirBytes, 20),
                NumberOfNames = BitConverter.ToUInt32(exportDirBytes, 24),
                AddressOfFunctions = BitConverter.ToUInt32(exportDirBytes, 28),
                AddressOfNames = BitConverter.ToUInt32(exportDirBytes, 32),
                AddressOfNameOrdinals = BitConverter.ToUInt32(exportDirBytes, 36),
                BaseOrdinal = BitConverter.ToUInt32(exportDirBytes, 16)
            };
        }

        /// <summary>
        /// Export function'larını parse eder
        /// </summary>
        private static bool ParseExportFunctions(IntPtr hProcess, IntPtr moduleBase, ExportDirectoryInfo exportInfo, List<FunctionExport> exports)
        {
            if (exportInfo.NumberOfFunctions == 0 || exportInfo.NumberOfFunctions >= 0x10000)
                return false;

            uint maxFunctions = Math.Min(exportInfo.NumberOfFunctions, 1000u);

            for (uint i = 0; i < maxFunctions; i++)
            {
                // Function address RVA'sini oku
                byte[] funcRvaBytes = new byte[4];
                uint ntStatus = MemoryHelper.SafeReadVirtualMemory(hProcess,
                    IntPtr.Add(moduleBase, (int)(exportInfo.AddressOfFunctions + i * 4)),
                    funcRvaBytes, 4);
                if (ntStatus != 0)
                    continue;

                uint functionRva = BitConverter.ToUInt32(funcRvaBytes, 0);
                if (functionRva == 0)
                    continue;

                var functionExport = new FunctionExport
                {
                    FunctionAddress = IntPtr.Add(moduleBase, (int)functionRva),
                    Ordinal = exportInfo.BaseOrdinal + i,
                    FunctionName = $"Ordinal_{exportInfo.BaseOrdinal + i}"
                };

                // Function name'i al (varsa)
                if (exportInfo.NumberOfNames > 0 && i < exportInfo.NumberOfNames)
                {
                    string functionName = GetFunctionName(hProcess, moduleBase, exportInfo, i);
                    if (!string.IsNullOrEmpty(functionName))
                        functionExport.FunctionName = functionName;
                }

                exports.Add(functionExport);
            }

            return exports.Count > 0;
        }

        /// <summary>
        /// Function name'ini alır
        /// </summary>
        private static string GetFunctionName(IntPtr hProcess, IntPtr moduleBase, ExportDirectoryInfo exportInfo, uint index)
        {
            try
            {
                // Name ordinal'ini bul
                byte[] nameOrdinalBytes = new byte[2];
                uint ntStatus = MemoryHelper.SafeReadVirtualMemory(hProcess,
                    IntPtr.Add(moduleBase, (int)(exportInfo.AddressOfNameOrdinals + index * 2)),
                    nameOrdinalBytes, 2);
                if (ntStatus != 0)
                    return null;

                ushort nameOrdinal = BitConverter.ToUInt16(nameOrdinalBytes, 0);
                if (nameOrdinal >= exportInfo.NumberOfFunctions)
                    return null;

                // Function name RVA'sini al
                byte[] nameRvaBytes = new byte[4];
                ntStatus = MemoryHelper.SafeReadVirtualMemory(hProcess,
                    IntPtr.Add(moduleBase, (int)(exportInfo.AddressOfNames + index * 4)),
                    nameRvaBytes, 4);
                if (ntStatus != 0)
                    return null;

                uint nameStringRva = BitConverter.ToUInt32(nameRvaBytes, 0);
                if (nameStringRva == 0)
                    return null;

                // Function name string'ini oku
                byte[] nameBytes = new byte[256];
                ntStatus = MemoryHelper.SafeReadVirtualMemory(hProcess,
                    IntPtr.Add(moduleBase, (int)nameStringRva),
                    nameBytes, 256);
                if (ntStatus != 0)
                    return null;

                int nullIndex = Array.IndexOf(nameBytes, (byte)0);
                return nullIndex > 0
                    ? System.Text.Encoding.ASCII.GetString(nameBytes, 0, nullIndex)
                    : null;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// PSAPI kullanarak process modüllerini alır - Handle'ları base address'lere çevirir
        /// </summary>
        public static bool GetProcessModules(IntPtr hProcess, out List<RTL_PROCESS_MODULE_INFORMATION> modules)
        {
            modules = new List<RTL_PROCESS_MODULE_INFORMATION>();

            try
            {
                // Önce gerekli buffer boyutunu öğren
                IntPtr[] moduleHandles = new IntPtr[1024]; // Maksimum 1024 module
                uint bufferSize = (uint)(moduleHandles.Length * IntPtr.Size);

                Console.WriteLine($"[DEBUG] PSAPI EnumProcessModules başlatılıyor...");

                if (PsApi.EnumProcessModules(hProcess, moduleHandles, bufferSize, out uint neededSize))
                {
                    Console.WriteLine($"[DEBUG] EnumProcessModules başarılı, neededSize={neededSize}");

                    // Gerekli module sayısını hesapla
                    int moduleCount = (int)(neededSize / IntPtr.Size);
                    Console.WriteLine($"[DEBUG] Toplam module sayısı: {moduleCount}");

                    // Her module için bilgi topla
                    for (int i = 0; i < moduleCount && i < moduleHandles.Length; i++)
                    {
                        IntPtr moduleHandle = moduleHandles[i];

                        if (moduleHandle != IntPtr.Zero)
                        {
                            // Base address validation
                            long baseAddress = moduleHandle.ToInt64();

                            // Geçersiz adres kontrolü
                            if (baseAddress < 0x10000 || baseAddress > 0x7FFFFFFFFFFFL)
                            {
                                Console.WriteLine($"[WARNING] Module {i}: Geçersiz base address @ 0x{baseAddress:X}, atlanıyor");
                                continue;
                            }

                            RTL_PROCESS_MODULE_INFORMATION moduleInfo = new RTL_PROCESS_MODULE_INFORMATION(true);

                            // Module base address'i al (handle genellikle base address'tir)
                            moduleInfo.ImageBase = moduleHandle;

                            // Module boyutunu güvenli şekilde hesapla (PE header'dan)
                            moduleInfo.ImageSize = ModuleHelper.GetModuleImageSize(hProcess, moduleHandle);
                            if (moduleInfo.ImageSize == 0)
                            {
                                moduleInfo.ImageSize = 0x1000; // Fallback: varsayılan 4KB
                            }

                            // Module name'i al
                            StringBuilder moduleName = new StringBuilder(256);
                            uint nameLength = PsApi.GetModuleBaseName(hProcess, moduleHandle, moduleName, 256);

                            if (nameLength > 0)
                            {
                                // Module name'i byte array'e kopyala
                                string name = moduleName.ToString();
                                byte[] nameBytes = System.Text.Encoding.ASCII.GetBytes(name);
                                int copyLength = Math.Min(nameBytes.Length, 256 - moduleInfo.OffsetToFileName);

                                Array.Copy(nameBytes, 0, moduleInfo.FullPathName, moduleInfo.OffsetToFileName, copyLength);

                                Console.WriteLine($"[DEBUG] Module {i}: {name} @ 0x{moduleHandle:X} ({baseAddress:X})");
                            }
                            else
                            {
                                Console.WriteLine($"[DEBUG] Module {i}: İsim alınamadı @ 0x{moduleHandle:X} ({baseAddress:X})");
                            }

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
        /// Güvenli cross-process memory okuma fonksiyonu
        /// </summary>
        public static uint SafeReadVirtualMemory(IntPtr hProcess, IntPtr baseAddress, byte[] buffer, int size)
        {
            try
            {
                return NativeApi.NtReadVirtualMemory(hProcess, baseAddress, buffer, size, out IntPtr bytesRead);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[WARNING] SafeReadVirtualMemory error: {ex.Message}");
                return 0xC0000005; // STATUS_ACCESS_VIOLATION
            }
        }

        /// <summary>
        /// .pdata section'ından RUNTIME_FUNCTION array'ini parse eder
        /// </summary>
        public static bool ParseRuntimeFunctionsFromPdata(IntPtr hProcess, IntPtr moduleBase, uint moduleSize, List<Win32.RUNTIME_FUNCTION> runtimeFunctions)
        {
            try
            {
                // PE header'dan section header'larını oku
                List<Win32.PE_SECTION_HEADER> sections = GetSectionHeaders(hProcess, moduleBase, moduleSize);

                // .pdata section'ını bul
                Win32.PE_SECTION_HEADER pdataSection = sections.FirstOrDefault(s => System.Text.Encoding.ASCII.GetString(s.Name).TrimEnd('\0') == ".pdata");
                if (pdataSection.VirtualSize == 0)
                {
                    Console.WriteLine($"[DEBUG] .pdata section bulunamadı");
                    return false;
                }

                Console.WriteLine($"[DEBUG] .pdata section bulundu: RVA=0x{pdataSection.VirtualAddress:X}, Size=0x{pdataSection.VirtualSize:X}");

                // .pdata section'ındaki RUNTIME_FUNCTION'ları oku
                uint functionCount = pdataSection.VirtualSize / (uint)Marshal.SizeOf(typeof(Win32.RUNTIME_FUNCTION));

                if (functionCount == 0)
                {
                    Console.WriteLine($"[DEBUG] .pdata section boş");
                    return false;
                }

                Console.WriteLine($"[DEBUG] {functionCount} RUNTIME_FUNCTION bekleniyor");

                // Her RUNTIME_FUNCTION'ı oku
                for (uint i = 0; i < functionCount && i < 10000; i++) // Max 10000 function ile sınırla
                {
                    byte[] funcBytes = new byte[12]; // RUNTIME_FUNCTION = 12 bytes
                    uint ntStatus = SafeReadVirtualMemory(hProcess,
                        IntPtr.Add(moduleBase, (int)(pdataSection.VirtualAddress + i * 12)),
                        funcBytes, 12);

                    if (ntStatus != 0)
                    {
                        continue; // Bu function'ı atla
                    }

                    Win32.RUNTIME_FUNCTION func = new Win32.RUNTIME_FUNCTION
                    {
                        BeginAddress = BitConverter.ToUInt32(funcBytes, 0),
                        EndAddress = BitConverter.ToUInt32(funcBytes, 4),
                        UnwindInfoAddress = BitConverter.ToUInt32(funcBytes, 8)
                    };

                    // Validasyon - Daha esnek validasyon
                    bool isValid = true;
                    string validationReason = "";

                    // Temel kontroller
                    if (func.BeginAddress == 0 && func.EndAddress == 0 && func.UnwindInfoAddress == 0)
                    {
                        isValid = false;
                        validationReason = "All zeros";
                    }
                    else if (func.BeginAddress >= func.EndAddress)
                    {
                        isValid = false;
                        validationReason = "Begin >= End";
                    }
                    else if (func.BeginAddress > 0xFFFF0000) // Çok büyük adresler şüpheli
                    {
                        isValid = false;
                        validationReason = "Begin address too large";
                    }

                    if (isValid)
                    {
                        runtimeFunctions.Add(func);

                        if (i < 5) // İlk 5 function'ı logla (daha az spam)
                        {
                            Console.WriteLine($"[DEBUG] RUNTIME_FUNCTION {i}: Begin=0x{func.BeginAddress:X}, End=0x{func.EndAddress:X}, Unwind=0x{func.UnwindInfoAddress:X}");
                        }
                    }
                    else if (i < 3) // İlk birkaç geçersiz function'ı logla
                    {
                        Console.WriteLine($"[DEBUG] RUNTIME_FUNCTION {i} SKIPPED: {validationReason} - Begin=0x{func.BeginAddress:X}, End=0x{func.EndAddress:X}, Unwind=0x{func.UnwindInfoAddress:X}");
                    }
                }

                Console.WriteLine($"[DEBUG] {runtimeFunctions.Count} geçerli RUNTIME_FUNCTION bulundu");
                return runtimeFunctions.Count > 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[DEBUG] ParseRuntimeFunctionsFromPdata exception: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// PE dosyasından section header'larını alır
        /// </summary>
        private static List<Win32.PE_SECTION_HEADER> GetSectionHeaders(IntPtr hProcess, IntPtr moduleBase, uint moduleSize)
        {
            List<Win32.PE_SECTION_HEADER> sections = new List<Win32.PE_SECTION_HEADER>();

            try
            {
                // DOS header'dan PE offset'i oku
                byte[] peOffsetBytes = new byte[4];
                uint ntStatus = SafeReadVirtualMemory(hProcess, IntPtr.Add(moduleBase, 0x3C), peOffsetBytes, 4);
                if (ntStatus != 0)
                {
                    return sections;
                }

                int peOffset = BitConverter.ToInt32(peOffsetBytes, 0);

                // PE signature oku
                byte[] peSigBytes = new byte[4];
                ntStatus = SafeReadVirtualMemory(hProcess, IntPtr.Add(moduleBase, peOffset), peSigBytes, 4);
                if (ntStatus != 0)
                {
                    return sections;
                }

                uint peSignature = BitConverter.ToUInt32(peSigBytes, 0);
                if (peSignature != PEHeaderConstants.IMAGE_NT_SIGNATURE)
                {
                    return sections;
                }

                // File header'dan section count'u oku
                byte[] fileHeaderBytes = new byte[20];
                ntStatus = SafeReadVirtualMemory(hProcess, IntPtr.Add(moduleBase, peOffset + 4), fileHeaderBytes, 20);
                if (ntStatus != 0)
                {
                    return sections;
                }

                ushort numberOfSections = BitConverter.ToUInt16(fileHeaderBytes, 2);
                ushort sizeOfOptionalHeader = BitConverter.ToUInt16(fileHeaderBytes, 16);

                // Optional header'dan section table offset'ini hesapla
                int sectionTableOffset = peOffset + 4 + 20 + sizeOfOptionalHeader;

                // Her section header'ı oku
                for (int i = 0; i < numberOfSections; i++)
                {
                    byte[] sectionBytes = new byte[40]; // Section header = 40 bytes
                    ntStatus = SafeReadVirtualMemory(hProcess,
                        IntPtr.Add(moduleBase, sectionTableOffset + i * 40),
                        sectionBytes, 40);

                    if (ntStatus != 0)
                    {
                        continue;
                    }

                    Win32.PE_SECTION_HEADER section = new Win32.PE_SECTION_HEADER
                    {
                        Name = new byte[8],
                        VirtualSize = BitConverter.ToUInt32(sectionBytes, 8),
                        VirtualAddress = BitConverter.ToUInt32(sectionBytes, 12),
                        SizeOfRawData = BitConverter.ToUInt32(sectionBytes, 16),
                        PointerToRawData = BitConverter.ToUInt32(sectionBytes, 20),
                        PointerToRelocations = BitConverter.ToUInt32(sectionBytes, 24),
                        PointerToLinenumbers = BitConverter.ToUInt32(sectionBytes, 28),
                        NumberOfRelocations = BitConverter.ToUInt16(sectionBytes, 32),
                        NumberOfLinenumbers = BitConverter.ToUInt16(sectionBytes, 34),
                        Characteristics = BitConverter.ToUInt32(sectionBytes, 36)
                    };

                    // Name'i kopyala
                    Array.Copy(sectionBytes, 0, section.Name, 0, 8);

                    // Null terminator ekle ve string'e çevir
                    string sectionName = System.Text.Encoding.ASCII.GetString(section.Name).TrimEnd('\0');

                    if (i < 10) // İlk 10 section'ı logla
                    {
                        Console.WriteLine($"[DEBUG] Section {i}: {sectionName} @ RVA=0x{section.VirtualAddress:X}, Size=0x{section.VirtualSize:X}");
                    }

                    sections.Add(section);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[DEBUG] GetSectionHeaders exception: {ex.Message}");
            }

            return sections;
        }
    }
}