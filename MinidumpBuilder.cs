using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using static WinEmuDump.Win32;
using static WinEmuDump.CreateFile;


namespace WinEmuDump
{
    internal class MinidumpBuilder
    {
        // MinidumpBuilder.cs - Gelişmiş minidump oluşturma işlevi
        // Bu dosya tüm bilgileri birleştirerek gelişmiş minidump dosyası oluşturur

        // Source File #4

        /// <summary>
        /// Tüm bilgileri birleştirerek gelişmiş minidump dosyası oluşturur
        /// </summary>
        /// <param name="hProcess">Hedef işlemin handle'ı</param>
        /// <param name="processInfo">İşlem bilgileri</param>
        /// <param name="threadList">Gelişmiş thread bilgileri listesi</param>
        /// <param name="handleList">Handle bilgileri listesi</param>
        /// <param name="moduleList">Modül bilgileri listesi</param>
        /// <param name="systemInfo">Sistem bilgileri</param>
        /// <param name="outputPath">Çıktı dosyası yolu</param>
        /// <returns>Başarılı ise true, aksi halde false</returns>
        public static bool BuildAdvancedMinidump(IntPtr hProcess, ProcessInfoData processInfo, List<MinidumpThreadInfo> threadList,
            List<HandleInfo> handleList, List<ModuleInfo> moduleList, SystemInfoData systemInfo, string outputPath)
        {
            try
            {
                Console.WriteLine("[INFO] Gelişmiş minidump oluşturma başlatıldı");

                // Stream'leri hazırlama
                List<MinidumpStream> streams = new List<MinidumpStream>();
                int systemInfoStreamIndex = 0;
                int handleStreamIndex = -1;
                int moduleStreamIndex = -1;
                int threadListStreamIndex = -1;
                int exceptionStreamIndex = -1;
                int memory64ListStreamIndex = -1;

                // SystemInfo Stream (placeholder)
                streams.Add(CreateSystemInfoStream(systemInfo, 0));

                // ThreadList Stream
                if (threadList.Count > 0)
                {
                    threadListStreamIndex = streams.Count;
                    streams.Add(CreateThreadListStream(threadList, 0)); // Geçici RVA = 0
                }

                // Exception Stream (varsa)
                uint threadIdForException = threadList.Count > 0 ? threadList[0].ThreadId : 0; // İlk thread'i kullan
                if (threadIdForException != 0)
                {
                    exceptionStreamIndex = streams.Count;
                    streams.Add(CreateExceptionStream(threadIdForException, 0)); // Geçici RVA = 0
                }

                // HandleList Stream (placeholder)
                if (handleList.Count > 0)
                {
                    handleStreamIndex = streams.Count;
                    streams.Add(CreateHandleListStream(handleList, 0)); // Geçici RVA = 0
                }

                // ModuleList Stream (placeholder)
                if (moduleList.Count > 0)
                {
                    moduleStreamIndex = streams.Count;
                    streams.Add(CreateModuleListStream(moduleList, 0)); // Geçici RVA = 0
                }

                // Memory64List Stream (Full memory) - Geçici RVA = 0
                memory64ListStreamIndex = streams.Count;
                streams.Add(CreateMemory64ListStream(hProcess, 0));

                // MemoryInfoList Stream (Memory region details)
                streams.Add(CreateMemoryInfoListStream(hProcess));

                // MiscInfo Stream
                streams.Add(CreateMiscInfoStream(processInfo));

                // Minidump header oluştur - DÜZELTİLMİŞ FORMAT
                MinidumpHeader header = new MinidumpHeader
                {
                    Signature = 0x504d444d, // "PMDM"
                    Version = 0xa793,
                    NumberOfStreams = (uint)streams.Count,
                    StreamDirectoryRva = 0x20,
                    TimeDateStamp = (uint)(DateTime.Now.ToFileTimeUtc() / 10000000 - 11644473600), // Unix timestamp
                    Flags = Win32.MiniDumpWithFullMemory | Win32.MiniDumpWithHandleData | Win32.MiniDumpWithFullMemoryInfo | Win32.MiniDumpIgnoreInaccessibleMemory // FullMemory | HandleData | FullMemoryInfo | IgnoreInaccessibleMemory
                };

                // Stream directory oluştur ve HandleStream RVA'larını düzelt
                List<byte> streamDirectoryBytes = new List<byte>();
                uint currentOffset = (uint)(Marshal.SizeOf(typeof(MinidumpHeader)) + (uint)streams.Count * (uint)Marshal.SizeOf(typeof(MinidumpStreamDirectoryEntry)));

                for (int i = 0; i < streams.Count; i++)
                {
                    var stream = streams[i];
                    
                    // Offset taşma kontrolü
                    if (currentOffset + (uint)stream.Data.Length < currentOffset)
                    {
                        Console.WriteLine($"[ERROR] Offset taşması algılandı! Stream: {stream.StreamType}, Size: {stream.Data.Length}");
                        return false;
                    }

                    // SystemInfo stream'i için RVA'ları düzelt
                    if (i == systemInfoStreamIndex)
                    {
                        Console.WriteLine($"[DEBUG] SystemInfo stream RVA düzeltiliyor, base offset: 0x{currentOffset:X}");
                        streams[i] = CreateSystemInfoStream(systemInfo, currentOffset);
                    }
                    
                    // Handle stream'i için RVA'ları düzelt
                    if (i == handleStreamIndex)
                    {
                        Console.WriteLine($"[DEBUG] Handle stream RVA düzeltiliyor, base offset: 0x{currentOffset:X}");
                        streams[i] = CreateHandleListStream(handleList, currentOffset);
                    }
                    
                    // Module stream'i için RVA'ları düzelt
                    if (i == moduleStreamIndex)
                    {
                        Console.WriteLine($"[DEBUG] Module stream RVA düzeltiliyor, base offset: 0x{currentOffset:X}");
                        streams[i] = CreateModuleListStream(moduleList, currentOffset);
                    }

                    // ThreadList stream'i için RVA'ları düzelt
                    if (i == threadListStreamIndex)
                    {
                        Console.WriteLine($"[DEBUG] ThreadList stream RVA düzeltiliyor, base offset: 0x{currentOffset:X}");
                        streams[i] = CreateThreadListStream(threadList, currentOffset);
                    }

                    // Exception stream'i için RVA'ları düzelt
                    if (i == exceptionStreamIndex)
                    {
                        Console.WriteLine($"[DEBUG] Exception stream RVA düzeltiliyor, base offset: 0x{currentOffset:X}");
                        uint threadIdForExceptionFix = threadList.Count > 0 ? threadList[0].ThreadId : 0;
                        streams[i] = CreateExceptionStream(threadIdForExceptionFix, currentOffset);
                    }

                    // Memory64List stream'i için RVA'ları düzelt
                    if (i == memory64ListStreamIndex)
                    {
                        Console.WriteLine($"[DEBUG] Memory64List stream RVA düzeltiliyor, base offset: 0x{currentOffset:X}");
                        streams[i] = CreateMemory64ListStream(hProcess, currentOffset);
                    }

                    MinidumpStreamDirectoryEntry entry = new MinidumpStreamDirectoryEntry
                    {
                        StreamType = streams[i].StreamType,
                        Size = (uint)streams[i].Data.Length,
                        Location = currentOffset
                    };

                    streamDirectoryBytes.AddRange(StructToByteArray(entry));
                    currentOffset += (uint)streams[i].Data.Length;
                }

                // Tüm veriyi birleştir
                List<byte> minidumpData = new List<byte>();
                minidumpData.AddRange(StructToByteArray(header));
                minidumpData.AddRange(streamDirectoryBytes);

                foreach (var stream in streams)
                {
                    minidumpData.AddRange(stream.Data);
                }

                // Dosyaya yaz
                using (FileStream fs = new FileStream(outputPath, FileMode.Create))
                {
                    fs.Write(minidumpData.ToArray(), 0, minidumpData.Count);
                }

                Console.WriteLine($"[SUCCESS] Gelişmiş minidump dosyası oluşturuldu: {outputPath}");
                Console.WriteLine($"[INFO] Toplam boyut: {minidumpData.Count} bytes, {streams.Count} stream");

                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ERROR] Gelişmiş minidump oluşturma hatası: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// SystemInfo stream'i oluşturur (DOĞRU MINIDUMP FORMATI)
        /// </summary>
        private static MinidumpStream CreateSystemInfoStream(SystemInfoData systemInfo, uint streamBaseRva = 0)
        {
            Console.WriteLine($"[DEBUG] SystemInfo stream oluşturuluyor");
            Console.WriteLine($"[DEBUG] MINIDUMP_SYSTEM_INFO boyutu: {Marshal.SizeOf(typeof(MINIDUMP_SYSTEM_INFO))} bytes");
            
            List<byte> systemInfoData = new List<byte>();
            
            // 1. CSD Version string'i hazırla
            string csdVersion = systemInfo.CSDVersion;
            uint csdVersionRva = streamBaseRva + (uint)Marshal.SizeOf(typeof(MINIDUMP_SYSTEM_INFO)); // Her zaman RVA hesapla

            if (string.IsNullOrEmpty(csdVersion))
            {
                // CSDVersion boşsa, boş string kullan (ama RVA geçerli tut)
                csdVersion = "";
            }
            
            // 3. MINIDUMP_SYSTEM_INFO oluştur
            MINIDUMP_SYSTEM_INFO sysInfo = new MINIDUMP_SYSTEM_INFO
            {
                ProcessorArchitecture = systemInfo.ProcessorArchitecture,
                ProcessorLevel = (ushort)systemInfo.ProcessorLevel,
                ProcessorRevision = (ushort)systemInfo.ProcessorRevision,
                NumberOfProcessors = systemInfo.ProcessorCount,
                ProductType = 1, // VER_NT_WORKSTATION
                MajorVersion = systemInfo.MajorVersion,
                MinorVersion = systemInfo.MinorVersion,
                BuildNumber = systemInfo.BuildNumber,
                PlatformId = systemInfo.PlatformId,
                CSDVersionRva = csdVersionRva,
                SuiteMask = systemInfo.SuiteMask,
                Reserved2 = 0,
                Cpu = new CPU_INFORMATION
                {
                    VendorId0 = systemInfo.VendorId0,
                    VendorId1 = systemInfo.VendorId1,
                    VendorId2 = systemInfo.VendorId2,
                    VersionInformation = systemInfo.VersionInformation,
                    FeatureInformation = systemInfo.FeatureInformation,
                    AMDExtendedCpuFeatures = systemInfo.AMDExtendedCpuFeatures,
                    ProcessorFeatures0 = systemInfo.FeatureInformation,
                    ProcessorFeatures1 = systemInfo.AMDExtendedCpuFeatures
                }
            };
            
            // 4. MINIDUMP_SYSTEM_INFO struct'ını yaz
            byte[] sysInfoBytes = StructToByteArray(sysInfo);
            systemInfoData.AddRange(sysInfoBytes);

            // 5. CSD Version string'ini yaz (her zaman RVA geçerli olduğundan)
            if (!string.IsNullOrEmpty(csdVersion))
            {
                // CSDVersion varsa normal şekilde yaz
                byte[] csdVersionBytes = System.Text.Encoding.Unicode.GetBytes(csdVersion);
                uint csdVersionLength = (uint)(csdVersionBytes.Length + 2); // +2 for null terminator

                systemInfoData.AddRange(BitConverter.GetBytes(csdVersionLength));
                systemInfoData.AddRange(csdVersionBytes);
                systemInfoData.AddRange(new byte[2]); // Null terminator
            }
            else
            {
                // CSDVersion boşsa, length=0 ve hiç içerik yazma
                systemInfoData.AddRange(BitConverter.GetBytes((uint)0));
                // Hiç içerik veya null terminator ekleme
            }
            
            Console.WriteLine($"[DEBUG] SystemInfo: Windows {systemInfo.MajorVersion}.{systemInfo.MinorVersion} Build {systemInfo.BuildNumber}");
            Console.WriteLine($"[DEBUG] CSDVersion: '{csdVersion}' @ RVA=0x{csdVersionRva:X}");
            Console.WriteLine($"[DEBUG] SystemInfo stream boyutu: {systemInfoData.Count} bytes");
            
            return new MinidumpStream
            {
                StreamType = MINIDUMP_STREAM_TYPE_SystemInfo,
                Data = systemInfoData.ToArray()
            };
        }

        /// <summary>
        /// ThreadList stream'i oluşturur (MINIDUMP_THREAD formatında - DOĞRU FORMAT)
        /// </summary>
        private static MinidumpStream CreateThreadListStream(List<MinidumpThreadInfo> threadList, uint streamBaseRva = 0)
        {
            Console.WriteLine($"[DEBUG] ThreadList stream oluşturuluyor, thread sayısı: {threadList.Count}");
            Console.WriteLine($"[DEBUG] MINIDUMP_THREAD boyutu: {Marshal.SizeOf(typeof(MINIDUMP_THREAD))} bytes");
            Console.WriteLine($"[DEBUG] MINIDUMP_THREAD_LIST boyutu: {Marshal.SizeOf(typeof(MINIDUMP_THREAD_LIST))} bytes");

            List<byte> threadData = new List<byte>();

            // 1. MINIDUMP_THREAD_LIST header yaz
            MINIDUMP_THREAD_LIST threadListHeader = new MINIDUMP_THREAD_LIST
            {
                NumberOfThreads = (uint)threadList.Count
            };
            byte[] headerBytes = StructToByteArray(threadListHeader);
            threadData.AddRange(headerBytes);

            Console.WriteLine($"[DEBUG] ThreadList header yazıldı: {headerBytes.Length} bytes");

            // 2. MINIDUMP_THREAD struct'larını ve CONTEXT verilerini topla
            List<byte> contextData = new List<byte>();

            // Context offset'leri hesapla (stream başından itibaren)
            uint currentContextOffset = (uint)threadData.Count + (uint)(threadList.Count * Marshal.SizeOf(typeof(MINIDUMP_THREAD)));

            foreach (var threadInfo in threadList)
            {
                // Context RVA hesapla (dosyanın başından itibaren)
                uint contextRva = streamBaseRva + currentContextOffset;

                // MINIDUMP_THREAD oluştur
                MINIDUMP_THREAD thread = new MINIDUMP_THREAD
                {
                    ThreadId = threadInfo.ThreadId,
                    SuspendCount = 1, // Suspended durumda
                    PriorityClass = 0, // Bilinmiyor
                    Priority = 0, // Bilinmiyor
                    Teb = threadInfo.TebAddress,
                    Stack = new MINIDUMP_MEMORY_DESCRIPTOR
                    {
                        StartOfMemoryRange = threadInfo.StackBase,
                        Memory = new MINIDUMP_LOCATION_DESCRIPTOR
                        {
                            DataSize = threadInfo.StackSize,
                            Rva = 0 // Memory64List'te olacak
                        }
                    },
                    ThreadContext = new MINIDUMP_LOCATION_DESCRIPTOR
                    {
                        DataSize = (uint)Marshal.SizeOf(typeof(CONTEXT)),
                        Rva = contextRva
                    }
                };

                // MINIDUMP_THREAD struct'ını yaz
                byte[] threadBytes = StructToByteArray(thread);
                threadData.AddRange(threadBytes);

                // CONTEXT verisini ekle
                byte[] contextBytes = StructToByteArray(threadInfo.Context);
                contextData.AddRange(contextBytes);

                currentContextOffset += (uint)Marshal.SizeOf(typeof(CONTEXT));

                Console.WriteLine($"[DEBUG] Thread {threadInfo.ThreadId}: TEB=0x{threadInfo.TebAddress:X}, Stack=0x{threadInfo.StackBase:X} ({threadInfo.StackSize} bytes), ContextRVA=0x{contextRva:X}");
            }

            // 3. Context verilerini yaz
            threadData.AddRange(contextData);

            Console.WriteLine($"[DEBUG] ThreadList stream boyutu: {threadData.Count} bytes");
            Console.WriteLine($"[DEBUG] - Header: {headerBytes.Length} bytes");
            Console.WriteLine($"[DEBUG] - Threads: {threadList.Count * Marshal.SizeOf(typeof(MINIDUMP_THREAD))} bytes");
            Console.WriteLine($"[DEBUG] - Contexts: {contextData.Count} bytes");
            Console.WriteLine($"[DEBUG] - Toplam: {threadData.Count} bytes");

            return new MinidumpStream
            {
                StreamType = MINIDUMP_STREAM_TYPE_ThreadList,
                Data = threadData.ToArray()
            };
        }

        /// <summary>
        /// HandleList stream'i oluşturur (Standart Minidump Formatı)
        /// </summary>
        /// <param name="handleList">Handle bilgileri listesi</param>
        /// <param name="streamBaseRva">Stream'in dosyadaki başlangıç RVA'sı (0 = ilk geçiş)</param>
        private static MinidumpStream CreateHandleListStream(List<HandleInfo> handleList, uint streamBaseRva)
        {
            Console.WriteLine($"[DEBUG] HandleList stream oluşturuluyor, handle sayısı: {handleList.Count}");
            
            // Struct boyutlarını kontrol et
            Console.WriteLine($"[DEBUG] HandleListStream boyutu: {Marshal.SizeOf(typeof(HandleListStream))} bytes");
            Console.WriteLine($"[DEBUG] Handle boyutu: {Marshal.SizeOf(typeof(Handle))} bytes");
            
            List<byte> handleData = new List<byte>();
            
            // 1. HandleListStream header yaz (DOĞRU MINIDUMP FORMATI)
            HandleListStream handleListStream = new HandleListStream
            {
                SizeOfHeader = (uint)Marshal.SizeOf(typeof(HandleListStream)), // 16 byte
                SizeOfDescriptor = (uint)Marshal.SizeOf(typeof(Handle)), // 32 byte (Handle struct boyutu)
                NumberOfDescriptors = (uint)handleList.Count,
                Reserved = 0
            };
            byte[] headerBytes = StructToByteArray(handleListStream);
            handleData.AddRange(headerBytes);
            
            Console.WriteLine($"[DEBUG] HandleListStream header yazıldı: {headerBytes.Length} bytes (Beklenen: {Marshal.SizeOf(typeof(HandleListStream))} = SizeOfHeader: {handleListStream.SizeOfHeader}, SizeOfDescriptor: {handleListStream.SizeOfDescriptor})");
            Console.WriteLine($"[DEBUG] Handle struct boyutu: {Marshal.SizeOf(typeof(Handle))} bytes (32-bit handle kullanıyoruz)");
            
            // 2. Handle struct'ları ve string verilerini topla
            List<Handle> handles = new List<Handle>();
            List<byte> stringData = new List<byte>();
            
            // String offset'leri hesapla (stream başından itibaren)
            uint currentStringOffset = (uint)handleData.Count + (uint)(handleList.Count * Marshal.SizeOf(typeof(Handle)));
            
            Console.WriteLine($"[DEBUG] String offset başlangıcı: 0x{currentStringOffset:X}");
            
            foreach (var handleInfo in handleList)
            {
                // TypeName RVA hesapla
                uint typeNameRva = streamBaseRva + currentStringOffset;
                
                // TypeName string verisi
                string typeName = handleInfo.TypeName ?? "Unknown";
                byte[] typeNameBytes = System.Text.Encoding.Unicode.GetBytes(typeName);
                uint typeNameLength = (uint)(typeNameBytes.Length + 2); // +2 for null terminator
                
                // TypeName string'ini ekle
                stringData.AddRange(BitConverter.GetBytes(typeNameLength));
                stringData.AddRange(typeNameBytes);
                stringData.AddRange(new byte[2]); // Null terminator
                
                currentStringOffset += 4 + typeNameLength;
                
                // ObjectName RVA hesapla (varsa)
                uint objectNameRva = 0;
                if (!string.IsNullOrEmpty(handleInfo.ObjectName))
                {
                    objectNameRva = streamBaseRva + currentStringOffset;
                    
                    // ObjectName string verisi
                    byte[] objectNameBytes = System.Text.Encoding.Unicode.GetBytes(handleInfo.ObjectName);
                    uint objectNameLength = (uint)(objectNameBytes.Length + 2);
                    
                    // ObjectName string'ini ekle
                    stringData.AddRange(BitConverter.GetBytes(objectNameLength));
                    stringData.AddRange(objectNameBytes);
                    stringData.AddRange(new byte[2]); // Null terminator
                    
                    currentStringOffset += 4 + objectNameLength;
                }
                
                Handle handle = new Handle
                {
                    Handle64 = handleInfo.HandleValue,
                    TypeNameRva = typeNameRva,
                    ObjectNameRva = objectNameRva,
                    Attributes = handleInfo.HandleAttributes,
                    GrantedAccess = handleInfo.GrantedAccess,
                    HandleCount = 1,
                    PointerCount = 1
                };
                
                handles.Add(handle);
                
                Console.WriteLine($"[DEBUG] Handle {handle.Handle64}: TypeName='{typeName}' @ 0x{typeNameRva:X}, ObjectName='{handleInfo.ObjectName ?? "N/A"}' @ 0x{objectNameRva:X}");
            }
            
            // 3. Handle struct'larını yaz
            foreach (var handle in handles)
            {
                byte[] handleBytes = StructToByteArray(handle);
                handleData.AddRange(handleBytes);
                Console.WriteLine($"[DEBUG] Handle struct yazıldı: Value={handle.Handle64}, Size={handleBytes.Length}");
            }
            
            // 4. String verilerini yaz
            handleData.AddRange(stringData);
            
            Console.WriteLine($"[DEBUG] HandleList stream boyutu: {handleData.Count} bytes");
            Console.WriteLine($"[DEBUG] - Header: {headerBytes.Length} bytes");
            Console.WriteLine($"[DEBUG] - Handles: {handles.Count * Marshal.SizeOf(typeof(Handle))} bytes");
            Console.WriteLine($"[DEBUG] - Strings: {stringData.Count} bytes");
            Console.WriteLine($"[DEBUG] - Toplam: {handleData.Count} bytes");
            Console.WriteLine($"[DEBUG] Expected Minidump Explorer SizeOfDescriptor: {Marshal.SizeOf(typeof(HandleListStream))} bytes");
            
            return new MinidumpStream
            {
                StreamType = MINIDUMP_STREAM_TYPE_HandleData,
                Data = handleData.ToArray()
            };
        }
/// <summary>
/// ModuleList stream'i oluşturur (DOĞRU MINIDUMP FORMATI)
/// </summary>
private static MinidumpStream CreateModuleListStream(List<ModuleInfo> moduleList, uint streamBaseRva = 0)
{
    Console.WriteLine($"[DEBUG] ModuleList stream oluşturuluyor, modül sayısı: {moduleList.Count}");
    Console.WriteLine($"[DEBUG] MINIDUMP_MODULE boyutu: {Marshal.SizeOf(typeof(MINIDUMP_MODULE))} bytes");
    
    List<byte> moduleData = new List<byte>();
    
    // 1. Modül sayısını yaz
    moduleData.AddRange(BitConverter.GetBytes((uint)moduleList.Count));
    
    // 2. MINIDUMP_MODULE struct'larını ve string verilerini topla
    List<MINIDUMP_MODULE> modules = new List<MINIDUMP_MODULE>();
    List<byte> stringData = new List<byte>();
    
    // String offset'leri hesapla (stream başından itibaren)
    // 4 bytes (count) + (moduleList.Count * sizeof(MINIDUMP_MODULE))
    uint currentStringOffset = 4 + (uint)(moduleList.Count * Marshal.SizeOf(typeof(MINIDUMP_MODULE)));
    
    Console.WriteLine($"[DEBUG] String offset başlangıcı: 0x{currentStringOffset:X}");
    
    foreach (var moduleInfo in moduleList)
    {
        // ModuleName için string hazırla
        string moduleName = "";
        if (moduleInfo.ImageName != IntPtr.Zero)
        {
            try
            {
                moduleName = Marshal.PtrToStringUni(moduleInfo.ImageName) ?? "Unknown";
            }
            catch
            {
                moduleName = "Unknown";
            }
        }
        else
        {
            moduleName = "Unknown";
        }
        
        // ModuleNameRva hesapla (dosyanın başından itibaren)
        uint moduleNameRva = streamBaseRva + currentStringOffset;
        
        // MINIDUMP_STRING formatı: Length (4 bytes) + Unicode string + null terminator
        byte[] moduleNameBytes = System.Text.Encoding.Unicode.GetBytes(moduleName);
        uint moduleNameLength = (uint)(moduleNameBytes.Length + 2); // +2 for null terminator
        
        // String verisini ekle
        stringData.AddRange(BitConverter.GetBytes(moduleNameLength));
        stringData.AddRange(moduleNameBytes);
        stringData.AddRange(new byte[2]); // Null terminator
        
        currentStringOffset += 4 + moduleNameLength;
        
        // MINIDUMP_MODULE oluştur (DOĞRU YAPIYLA)
        MINIDUMP_MODULE module = new MINIDUMP_MODULE
        {
            BaseOfImage = (ulong)moduleInfo.BaseAddress.ToInt64(),
            SizeOfImage = (uint)moduleInfo.Size.ToInt64(),
            CheckSum = moduleInfo.Checksum,
            TimeDateStamp = moduleInfo.Timestamp,
            ModuleNameRva = moduleNameRva,
            VersionInfo = new VS_FIXEDFILEINFO
            {
                dwSignature = 0xFEEF04BD,
                dwStrucVersion = 0x00010000,
                dwFileVersionMS = 0,
                dwFileVersionLS = 0,
                dwProductVersionMS = 0,
                dwProductVersionLS = 0,
                dwFileFlagsMask = 0,
                dwFileFlags = 0,
                dwFileOS = 0x00040004, // VOS_NT_WINDOWS32
                dwFileType = 0x00000001, // VFT_APP
                dwFileSubtype = 0,
                dwFileDateMS = 0,
                dwFileDateLS = 0
            },
            CvRecord = new MINIDUMP_LOCATION_DESCRIPTOR { DataSize = 0, Rva = 0 },
            MiscRecord = new MINIDUMP_LOCATION_DESCRIPTOR { DataSize = 0, Rva = 0 },
            Reserved0 = 0,
            Reserved1 = 0
        };
        
        modules.Add(module);
        
        Console.WriteLine($"[DEBUG] Modül: '{moduleName}' @ 0x{module.BaseOfImage:X}, NameRva=0x{moduleNameRva:X}");
    }
    
    // 3. MINIDUMP_MODULE struct'larını yaz
    foreach (var module in modules)
    {
        byte[] moduleBytes = StructToByteArray(module);
        moduleData.AddRange(moduleBytes);
        Console.WriteLine($"[DEBUG] MINIDUMP_MODULE yazıldı: BaseOfImage=0x{module.BaseOfImage:X}, Size={moduleBytes.Length} bytes");
    }
    
    // 4. String verilerini yaz
    moduleData.AddRange(stringData);
    
    Console.WriteLine($"[DEBUG] ModuleList stream boyutu: {moduleData.Count} bytes");
    Console.WriteLine($"[DEBUG] - Header: 4 bytes");
    Console.WriteLine($"[DEBUG] - Modules: {modules.Count * Marshal.SizeOf(typeof(MINIDUMP_MODULE))} bytes (her biri {Marshal.SizeOf(typeof(MINIDUMP_MODULE))} bytes)");
    Console.WriteLine($"[DEBUG] - Strings: {stringData.Count} bytes");
    Console.WriteLine($"[DEBUG] - Toplam: {moduleData.Count} bytes");
    
    return new MinidumpStream
    {
        StreamType = MINIDUMP_STREAM_TYPE_ModuleList,
        Data = moduleData.ToArray()
    };
}
        /// <summary>
        /// Memory64List stream'i oluşturur (Full memory dump)
        /// </summary>
        /// <param name="hProcess">Hedef işlemin handle'ı</param>
        /// <param name="streamBaseRva">Stream'in dosyadaki başlangıç RVA'sı (0 = ilk geçiş)</param>
        private static MinidumpStream CreateMemory64ListStream(IntPtr hProcess, uint streamBaseRva = 0)
        {
            try
            {
                // Bellek bölgelerini tara
                List<Win32.Memory64Info> memoryRegions = new List<Win32.Memory64Info>();
                IntPtr memAddress = IntPtr.Zero;
                long maxAddress = 0x7FFFFFFEFFFF;

                // Bellek limitleri - toplam okunacak belleğin sınırlandırılması
                const long MAX_TOTAL_MEMORY_SIZE = 512 * 1024 * 1024; // 512MB limit
                const long MAX_REGION_SIZE = 64 * 1024 * 1024; // 64MB per region limit
                long totalMemorySize = 0;
                int processedRegions = 0;

                Console.WriteLine("[INFO] Bellek bölgeleri taranıyor...");

                while ((long)memAddress < maxAddress)
                {
                    MEMORY_BASIC_INFORMATION mbi = new MEMORY_BASIC_INFORMATION();
                    uint ntStatus = NtQueryVirtualMemory(hProcess, memAddress, MemoryBasicInformation, out mbi, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION)), out _);

                    if (ntStatus != 0)
                        break;

                    // Okunabilir bellek bölgeleri (PAGE_NOACCESS hariç)
                    if (mbi.Protect != PAGE_NOACCESS)
                    {
                        long regionSize = (long)mbi.RegionSize;

                        // Bölge boyutu limiti kontrolü
                        if (regionSize > MAX_REGION_SIZE)
                        {
                            Console.WriteLine($"[WARNING] Bölge boyutu çok büyük ({regionSize:X} bytes), atlanıyor");
                            memAddress = (IntPtr)((ulong)memAddress + (ulong)mbi.RegionSize);
                            continue;
                        }

                        // Toplam bellek limiti kontrolü
                        if (totalMemorySize + regionSize > MAX_TOTAL_MEMORY_SIZE)
                        {
                            Console.WriteLine($"[WARNING] Toplam bellek limiti aşıldı ({totalMemorySize:X} + {regionSize:X} > {MAX_TOTAL_MEMORY_SIZE:X}), tarama durduruluyor");
                            break;
                        }

                        Win32.Memory64Info memInfo = new Win32.Memory64Info
                        {
                            StartOfMemoryRange = (ulong)mbi.BaseAddress.ToInt64(),
                            Memory = new MINIDUMP_LOCATION_DESCRIPTOR
                            {
                                DataSize = (uint)mbi.RegionSize.ToInt64(),
                                Rva = 0 // RVA will be calculated later
                            }
                        };
                        memoryRegions.Add(memInfo);
                        totalMemorySize += regionSize;
                        processedRegions++;

                        // Progress reporting
                        if (processedRegions % 100 == 0)
                        {
                            Console.WriteLine($"[INFO] {processedRegions} bellek bölgesi tarandı, toplam boyut: {totalMemorySize / (1024 * 1024)} MB");
                        }
                    }

                    memAddress = (IntPtr)((ulong)memAddress + (ulong)mbi.RegionSize);
                }

                Console.WriteLine($"[INFO] Toplam {memoryRegions.Count} bellek bölgesi bulundu, {totalMemorySize / (1024 * 1024)} MB");

                // Raw memory data - Sadece başarılı okunan bölgeleri dahil et
                const int MAX_CHUNK_SIZE = 64 * 1024; // 64KB chunks (daha küçük chunk'lar daha güvenilir)
                long totalReadSize = 0;
                var validRegions = new List<Win32.Memory64Info>();

                // İlk olarak bölgeleri test et - sadece tamamen okunabilenleri dahil et
                foreach (var memInfo in memoryRegions)
                {
                    bool regionReadable = true;
                    long remainingSize = (long)memInfo.Memory.DataSize;

                    // Bölgeyi test etmek için küçük bir bölüm oku
                    if (remainingSize >= 4096)
                    {
                        IntPtr testAddress = (IntPtr)(long)memInfo.StartOfMemoryRange;
                        try
                        {
                            byte[] testBuffer = new byte[4096];
                            uint ntStatus = NtReadVirtualMemory(hProcess, testAddress, testBuffer, 4096, out IntPtr testBytesReadPtr);

                            if (ntStatus != 0)
                            {
                                regionReadable = false;
                                Console.WriteLine($"[WARNING] Bölge test edilemedi, atlanıyor: 0x{memInfo.StartOfMemoryRange:X} ({memInfo.Memory.DataSize} bytes)");
                            }
                        }
                        catch
                        {
                            regionReadable = false;
                            Console.WriteLine($"[WARNING] Bölge test edilemedi, atlanıyor: 0x{memInfo.StartOfMemoryRange:X} ({memInfo.Memory.DataSize} bytes)");
                        }
                    }

                    if (regionReadable)
                    {
                        validRegions.Add(memInfo);
                        Console.WriteLine($"[DEBUG] Bölge 0x{memInfo.StartOfMemoryRange:X} okunabilir olarak işaretlendi");
                    }
                }

                Console.WriteLine($"[INFO] {validRegions.Count} geçerli bölge bulundu, {memoryRegions.Count - validRegions.Count} bölge atlandı");

                // Memory64List header - Use correct MINIDUMP_MEMORY64_LIST structure
                // BaseRva: RVA where raw memory data begins (from start of file)
                uint descriptorCount = (uint)validRegions.Count;
                ulong memoryDataBaseRva = streamBaseRva +
                    (ulong)Marshal.SizeOf(typeof(MINIDUMP_MEMORY64_LIST)) +
                    (ulong)(descriptorCount * Marshal.SizeOf(typeof(MINIDUMP_MEMORY_DESCRIPTOR64)));

                MINIDUMP_MEMORY64_LIST memory64List = new MINIDUMP_MEMORY64_LIST
                {
                    NumberOfMemoryRanges = (ulong)validRegions.Count,
                    BaseRva = memoryDataBaseRva
                };

                Console.WriteLine($"[DEBUG] Memory64List BaseRva hesaplaması:");
                Console.WriteLine($"[DEBUG] - Stream base RVA: 0x{streamBaseRva:X}");
                Console.WriteLine($"[DEBUG] - Header size: 0x{Marshal.SizeOf(typeof(MINIDUMP_MEMORY64_LIST)):X}");
                Console.WriteLine($"[DEBUG] - Descriptor count: {descriptorCount}");
                Console.WriteLine($"[DEBUG] - Descriptor size: 0x{Marshal.SizeOf(typeof(MINIDUMP_MEMORY_DESCRIPTOR64)):X}");
                Console.WriteLine($"[DEBUG] - Calculated BaseRva: 0x{memoryDataBaseRva:X}");

                List<byte> memoryData = new List<byte>();
                memoryData.AddRange(StructToByteArray(memory64List));

                // Memory descriptor entries - Use correct MINIDUMP_MEMORY_DESCRIPTOR64 structure
                // Bölgeleri adres sırasına göre sırala (önemli!)
                var sortedRegions = validRegions.OrderBy(r => r.StartOfMemoryRange).ToList();

                // RVA hesaplamaları için offset'leri ayarla
                uint currentDataOffset = streamBaseRva +
                    (uint)Marshal.SizeOf(typeof(MINIDUMP_MEMORY64_LIST)) +
                    (uint)(sortedRegions.Count * Marshal.SizeOf(typeof(MINIDUMP_MEMORY_DESCRIPTOR64)));

                Console.WriteLine($"[DEBUG] Memory64List RVA hesaplamaları:");
                Console.WriteLine($"[DEBUG] - Stream base RVA: 0x{streamBaseRva:X}");
                Console.WriteLine($"[DEBUG] - Header size: 0x{Marshal.SizeOf(typeof(MINIDUMP_MEMORY64_LIST)):X}");
                Console.WriteLine($"[DEBUG] - Descriptor size: 0x{Marshal.SizeOf(typeof(MINIDUMP_MEMORY_DESCRIPTOR64)):X}");
                Console.WriteLine($"[DEBUG] - Initial data offset: 0x{currentDataOffset:X}");

                foreach (var region in sortedRegions)
                {
                    // RVA'yi güncelle (kopya oluşturarak)
                    var memInfoCopy = new Win32.Memory64Info
                    {
                        StartOfMemoryRange = region.StartOfMemoryRange,
                        Memory = new MINIDUMP_LOCATION_DESCRIPTOR
                        {
                            DataSize = region.Memory.DataSize,
                            Rva = currentDataOffset
                        }
                    };

                    MINIDUMP_MEMORY_DESCRIPTOR64 descriptor = new MINIDUMP_MEMORY_DESCRIPTOR64
                    {
                        StartOfMemoryRange = memInfoCopy.StartOfMemoryRange,
                        DataSize = memInfoCopy.Memory.DataSize
                    };
                    memoryData.AddRange(StructToByteArray(descriptor));

                    Console.WriteLine($"[DEBUG] Bölge 0x{memInfoCopy.StartOfMemoryRange:X}: DataSize=0x{memInfoCopy.Memory.DataSize:X}, RVA=0x{currentDataOffset:X}");

                    // Sonraki bölge için RVA'yi güncelle
                    currentDataOffset += memInfoCopy.Memory.DataSize;
                }

                // Şimdi sadece geçerli bölgeleri oku (sıralı olarak!)
                foreach (var memInfo in sortedRegions)
                {
                    long remainingSize = (long)memInfo.Memory.DataSize;
                    long currentOffset = 0;
                    long regionReadSize = 0;

                    while (remainingSize > 0)
                    {
                        int chunkSize = (int)Math.Min(remainingSize, MAX_CHUNK_SIZE);
                        IntPtr chunkAddress = IntPtr.Add((IntPtr)(long)memInfo.StartOfMemoryRange, (int)currentOffset);

                        try
                        {
                            byte[] buffer = new byte[chunkSize];
                            uint ntStatus = NtReadVirtualMemory(hProcess, chunkAddress, buffer, chunkSize, out IntPtr bytesReadPtr);

                            uint bytesRead = (uint)bytesReadPtr.ToInt64();

                            if (ntStatus == 0 && bytesRead == chunkSize)
                            {
                                memoryData.AddRange(buffer);
                                regionReadSize += chunkSize;
                                totalReadSize += chunkSize;
                            }
                            else
                            {
                                // Bu bölge artık okunamıyor, kalan kısmı atla
                                Console.WriteLine($"[WARNING] Bölge okunurken sorun: 0x{chunkAddress:X}, chunk atlanıyor");
                                break;
                            }
                        }
                        catch (Exception ex)
                        {
                            // Bölge artık okunamıyor, kalan kısmı atla
                            Console.WriteLine($"[WARNING] Bölge okunurken hata: {ex.Message}, chunk atlanıyor");
                            break;
                        }

                        remainingSize -= chunkSize;
                        currentOffset += chunkSize;
                    }

                    if (regionReadSize > 0)
                    {
                        Console.WriteLine($"[INFO] Bölge okundu: 0x{memInfo.StartOfMemoryRange:X} - {regionReadSize / (1024 * 1024)} MB");
                    }
                }

                Console.WriteLine($"[SUCCESS] Toplam {totalReadSize / (1024 * 1024)} MB bellek verisi okundu");

                return new MinidumpStream
                {
                    StreamType = MINIDUMP_STREAM_TYPE_Memory64List,
                    Data = memoryData.ToArray()
                };
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[WARNING] Memory64List oluşturma hatası: {ex.Message}");
                // Boş stream döndür
                return new MinidumpStream
                {
                    StreamType = MINIDUMP_STREAM_TYPE_Memory64List,
                    Data = new byte[0]
                };
            }
        }

        /// <summary>
        /// MiscInfo stream'i oluşturur (MiniDumpMiscInfo4 formatında)
        /// </summary>
        private static MinidumpStream CreateMiscInfoStream(ProcessInfoData processInfo)
        {
            // TIME_ZONE_INFORMATION yapısı için Windows API çağrısı
            TIME_ZONE_INFORMATION timeZone = new TIME_ZONE_INFORMATION();
            uint result = GetTimeZoneInformation(out timeZone);

            // CPU bilgileri için SYSTEM_INFO al
            SYSTEM_INFO sysInfo = new SYSTEM_INFO();
            GetSystemInfo(out sysInfo);

            // Gerçek işlem zamanlarını al (UserTime ve KernelTime)
            uint processUserTime = 0;
            uint processKernelTime = 0;
            if (processInfo.UserTime != IntPtr.Zero)
            {
                processUserTime = (uint)processInfo.UserTime.ToInt64();
            }
            if (processInfo.KernelTime != IntPtr.Zero)
            {
                processKernelTime = (uint)processInfo.KernelTime.ToInt64();
            }

            // Gerçek CPU frekans bilgilerini almaya çalış (varsayılan değerler fallback)
            uint processorMaxMhz = 4008; // Modern CPU için gerçekçi değer
            uint processorCurrentMhz = 4008;
            uint processorMhzLimit = 4008;
            try
            {
                // CPU frekansını almak için Windows Management Instrumentation (WMI) kullanabiliriz
                // Veya registry'den okuma yapılabilir
                Microsoft.Win32.RegistryKey powerKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"HARDWARE\DESCRIPTION\System\CentralProcessor\0");
                if (powerKey != null)
                {
                    object mhz = powerKey.GetValue("~MHz");
                    if (mhz != null)
                    {
                        processorMaxMhz = (uint)(int)mhz;
                        processorCurrentMhz = processorMaxMhz;
                        processorMhzLimit = processorMaxMhz;
                    }
                    powerKey.Close();
                }
            }
            catch
            {
                // Registry erişim hatası durumunda varsayılan değerleri kullan
                Console.WriteLine("[DEBUG] CPU MHz bilgisi alınamadı, varsayılan değer kullanılıyor");
            }

            // Gerçek Windows versiyon bilgilerini al
            string buildString = "Unknown";
            string dbgBldStr = "Unknown";
            try
            {
                // Windows registry'den gerçek build bilgilerini almaya çalış
                Microsoft.Win32.RegistryKey key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
                if (key != null)
                {
                    object productName = key.GetValue("ProductName");
                    object currentBuild = key.GetValue("CurrentBuild");
                    object ubr = key.GetValue("UBR");

                    if (productName != null && currentBuild != null)
                    {
                        buildString = $"{productName} Build {currentBuild}";
                        if (ubr != null)
                        {
                            buildString += $".{ubr}";
                        }
                    }
                    else
                    {
                        // Registry'den alınamadıysa, ProductName kullanma
                        buildString = "";
                    }

                    object buildLab = key.GetValue("BuildLab");
                    if (buildLab != null)
                    {
                        // BuildLab varsa kullan, ama kullanıcı dbghelp versiyonunu istiyor
                        Console.WriteLine($"[DEBUG] BuildLab found: {buildLab}");
                    }
                    // DbgBldStr olarak sabit dbghelp versiyonu kullan
                    dbgBldStr = "dbghelp.amd64,6.3.9600.16384";

                    key.Close();
                }
            }
            catch
            {
                // Registry erişim hatası durumunda varsayılan değerler - Boş bırak
                buildString = "";
                dbgBldStr = "";
            }

            var miscInfo4 = new Win32.MINIDUMP_MISC_INFO_4
            {
                SizeOfInfo = (uint)Marshal.SizeOf(typeof(Win32.MINIDUMP_MISC_INFO_4)),
                Flags1 = 0x000001F7, // Tüm MiscInfo flag'leri: PROCESS_ID | PROCESS_TIMES | PROCESSOR_POWER_INFO | PROCESS_INTEGRITY | PROCESS_EXECUTE_FLAGS | TIMEZONE | PROTECTED_PROCESS | BUILDSTRING
                ProcessId = processInfo.ProcessId,
                ProcessCreateTime = (uint)(processInfo.CreateTime.ToInt64() & 0xFFFFFFFF),
                ProcessUserTime = processUserTime,
                ProcessKernelTime = processKernelTime,
                ProcessorMaxMhz = processorMaxMhz,
                ProcessorCurrentMhz = processorCurrentMhz,
                ProcessorMhzLimit = processorMhzLimit,
                ProcessorMaxIdleState = 1,
                ProcessorCurrentIdleState = 1,
                ProcessIntegrityLevel = 0x00003000, // HIGH_INTEGRITY (örnek - gerçek sistemden alınabilir)
                ProcessExecuteFlags = 0x0000000D, // DEP_ENABLE | SEH_ENABLE | NX_ENABLE (örnek değer)
                ProtectedProcess = 0, // Not protected
                TimeZoneId = result, // TIME_ZONE_ID_STANDARD, TIME_ZONE_ID_DAYLIGHT vb.
                TimeZone = timeZone,
                BuildString = buildString,
                DbgBldStr = dbgBldStr
            };

            // Eğer parsing problemi varsa MINIDUMP_MISC_INFO_2 kullan (Windows XP uyumlu)
            // SizeOfInfo'a göre hangi struct kullanılacağını belirle
            byte[] miscData;
            if (miscInfo4.SizeOfInfo == (uint)Marshal.SizeOf(typeof(Win32.MINIDUMP_MISC_INFO_2)))
            {
                // MINIDUMP_MISC_INFO_2 kullan (sadece temel bilgiler)
                var miscInfo2 = new Win32.MINIDUMP_MISC_INFO_2
                {
                    SizeOfInfo = (uint)Marshal.SizeOf(typeof(Win32.MINIDUMP_MISC_INFO_2)),
                    Flags1 = 0x00000002, // PROCESS_ID | PROCESS_TIMES
                    ProcessId = processInfo.ProcessId,
                    ProcessCreateTime = (uint)(processInfo.CreateTime.ToInt64() & 0xFFFFFFFF),
                    ProcessUserTime = processUserTime,
                    ProcessKernelTime = processKernelTime,
                    ProcessorMaxMhz = processorMaxMhz,
                    ProcessorCurrentMhz = processorCurrentMhz,
                    ProcessorMhzLimit = processorMhzLimit,
                    ProcessorMaxIdleState = 1,
                    ProcessorCurrentIdleState = 1
                };
                miscData = StructToByteArray(miscInfo2);
            }
            else
            {
                // MINIDUMP_MISC_INFO_4 kullan (tam özellikler)
                miscData = StructToByteArray(miscInfo4);
            }

            Console.WriteLine($"[DEBUG] MiscInfo oluşturuldu:");
            Console.WriteLine($"  - ProcessId: {miscInfo4.ProcessId}");
            Console.WriteLine($"  - ProcessCreateTime: {miscInfo4.ProcessCreateTime}");
            Console.WriteLine($"  - ProcessUserTime: {miscInfo4.ProcessUserTime}");
            Console.WriteLine($"  - ProcessKernelTime: {miscInfo4.ProcessKernelTime}");
            Console.WriteLine($"  - ProcessorMaxMhz: {miscInfo4.ProcessorMaxMhz}");
            Console.WriteLine($"  - BuildString: {miscInfo4.BuildString}");
            Console.WriteLine($"  - DbgBldStr: {miscInfo4.DbgBldStr}");

            return new MinidumpStream
            {
                StreamType = MINIDUMP_STREAM_TYPE_MiscInfo,
                Data = miscData
            };
        }

        /// <summary>
        /// MemoryInfoList stream'i oluşturur (Bellek bölgelerinin detaylı bilgileri)
        /// </summary>
        private static MinidumpStream CreateMemoryInfoListStream(IntPtr hProcess)
        {
            Console.WriteLine($"[DEBUG] MemoryInfoList stream oluşturuluyor");

            List<MemoryInfo> memoryInfoList = new List<MemoryInfo>();

            // Bellek bölgelerini tara
            IntPtr memAddress = IntPtr.Zero;
            long maxAddress = 0x7FFFFFFEFFFF;

            Console.WriteLine("[INFO] Bellek bölgeleri taranıyor (MemoryInfo)...");

            while ((long)memAddress < maxAddress)
            {
                MEMORY_BASIC_INFORMATION mbi = new MEMORY_BASIC_INFORMATION();
                uint ntStatus = NtQueryVirtualMemory(hProcess, memAddress, MemoryBasicInformation, out mbi, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION)), out _);

                if (ntStatus != 0)
                    break;

                // Tüm bölgeleri dahil et (committed olsun olmasın)
                MemoryInfo memInfo = new MemoryInfo
                {
                    BaseAddress = (ulong)mbi.BaseAddress.ToInt64(),
                    AllocationBase = (ulong)mbi.AllocationBase.ToInt64(),
                    AllocationProtect = (uint)mbi.AllocationProtect,
                    __alignment1 = 0,
                    RegionSize = (ulong)mbi.RegionSize.ToInt64(),
                    State = (uint)mbi.State,
                    Protect = (uint)mbi.Protect,
                    Type = (uint)mbi.Type,
                    __alignment2 = 0
                };
                memoryInfoList.Add(memInfo);

                memAddress = (IntPtr)((ulong)memAddress + (ulong)mbi.RegionSize);

                // Progress reporting
                if (memoryInfoList.Count % 1000 == 0)
                {
                    Console.WriteLine($"[INFO] {memoryInfoList.Count} bellek bölgesi tarandı (MemoryInfo)");
                }
            }

            Console.WriteLine($"[INFO] Toplam {memoryInfoList.Count} bellek bölgesi bulundu (MemoryInfo)");

            // MemoryInfoListStream header - DÜZELTİLMİŞ FORMAT
            MemoryInfoListStream memoryInfoListHeader = new MemoryInfoListStream
            {
                SizeOfHeader = (uint)Marshal.SizeOf(typeof(MemoryInfoListStream)),
                SizeOfEntry = (uint)Marshal.SizeOf(typeof(MemoryInfo)),
                NumberOfEntries = (ulong)memoryInfoList.Count
            };

            List<byte> memoryInfoData = new List<byte>();
            memoryInfoData.AddRange(StructToByteArray(memoryInfoListHeader));

            // MemoryInfo entries
            foreach (var memInfo in memoryInfoList)
            {
                memoryInfoData.AddRange(StructToByteArray(memInfo));
            }

            Console.WriteLine($"[DEBUG] MemoryInfoList stream boyutu: {memoryInfoData.Count} bytes");
            Console.WriteLine($"[DEBUG] - Header: {Marshal.SizeOf(typeof(MemoryInfoListStream))} bytes (SizeOfHeader: {memoryInfoListHeader.SizeOfHeader}, SizeOfEntry: {memoryInfoListHeader.SizeOfEntry})");
            Console.WriteLine($"[DEBUG] - MemoryInfo entries: {memoryInfoList.Count * Marshal.SizeOf(typeof(MemoryInfo))} bytes");
            Console.WriteLine($"[DEBUG] - Toplam: {memoryInfoData.Count} bytes");

            return new MinidumpStream
            {
                StreamType = MINIDUMP_STREAM_TYPE_MemoryInfoList,
                Data = memoryInfoData.ToArray()
            };
        }

        /// <summary>
        /// Exception stream'i oluşturur (MINIDUMP_EXCEPTION_STREAM formatında)
        /// </summary>
        private static MinidumpStream CreateExceptionStream(uint exceptionThreadId, uint streamBaseRva = 0)
        {
            Console.WriteLine($"[DEBUG] Exception stream oluşturuluyor, thread ID: {exceptionThreadId}");

            // Basit bir exception oluştur (örnek amaçlı)
            MINIDUMP_EXCEPTION exception = new MINIDUMP_EXCEPTION
            {
                ExceptionCode = 0xC0000005, // STATUS_ACCESS_VIOLATION
                ExceptionFlags = 0,
                ExceptionRecord = 0,
                ExceptionAddress = 0x0000000000000000, // Bilinmiyor
                NumberParameters = 0,
                __unusedAlignment = 0,
                ExceptionInformation = new ulong[15] // Boş parametreler
            };

            // Exception RVA hesapla (CONTEXT için)
            uint exceptionContextRva = streamBaseRva + (uint)Marshal.SizeOf(typeof(MINIDUMP_EXCEPTION_STREAM));

            MINIDUMP_EXCEPTION_STREAM exceptionStream = new MINIDUMP_EXCEPTION_STREAM
            {
                ThreadId = exceptionThreadId,
                __alignment = 0,
                ExceptionRecord = exception,
                ThreadContext = new MINIDUMP_LOCATION_DESCRIPTOR
                {
                    DataSize = (uint)Marshal.SizeOf(typeof(CONTEXT)),
                    Rva = exceptionContextRva
                }
            };

            // Boş CONTEXT ekle (exception anındaki register durumu bilinmiyor)
            CONTEXT emptyContext = new CONTEXT { ContextFlags = 0x10001F };

            List<byte> exceptionData = new List<byte>();
            exceptionData.AddRange(StructToByteArray(exceptionStream));
            exceptionData.AddRange(StructToByteArray(emptyContext));

            Console.WriteLine($"[DEBUG] Exception stream boyutu: {exceptionData.Count} bytes");
            Console.WriteLine($"[DEBUG] Exception: Code=0x{exception.ExceptionCode:X}, Address=0x{exception.ExceptionAddress:X}");

            return new MinidumpStream
            {
                StreamType = MINIDUMP_STREAM_TYPE_Exception,
                Data = exceptionData.ToArray()
            };
        }

        /// <summary>
        /// Struct'ı byte array'e çevirir
        /// </summary>
        private static byte[] StructToByteArray<T>(T structInstance) where T : struct
        {
            int structSize = Marshal.SizeOf(structInstance);
            byte[] byteArray = new byte[structSize];
            IntPtr ptr = Marshal.AllocHGlobal(structSize);
            try
            {
                Marshal.StructureToPtr(structInstance, ptr, true);
                Marshal.Copy(ptr, byteArray, 0, structSize);
            }
            finally
            {
                Marshal.FreeHGlobal(ptr);
            }
            return byteArray;
        }
    }

    /// <summary>
    /// Minidump stream'ini temsil eden struct
    /// </summary>
    internal struct MinidumpStream
    {
        public uint StreamType;
        public byte[] Data;
    }

}