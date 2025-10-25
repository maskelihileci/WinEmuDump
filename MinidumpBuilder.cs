using System;
using System.Collections.Generic;
using System.IO;
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
        /// <param name="threadList">Thread bilgileri listesi</param>
        /// <param name="handleList">Handle bilgileri listesi</param>
        /// <param name="moduleList">Modül bilgileri listesi</param>
        /// <param name="systemInfo">Sistem bilgileri</param>
        /// <param name="outputPath">Çıktı dosyası yolu</param>
        /// <returns>Başarılı ise true, aksi halde false</returns>
        public static bool BuildAdvancedMinidump(IntPtr hProcess, ProcessInfoData processInfo, List<ThreadInfo> threadList,
            List<HandleInfo> handleList, List<ModuleInfo> moduleList, SystemInfoData systemInfo, string outputPath)
        {
            try
            {
                Console.WriteLine("[INFO] Gelişmiş minidump oluşturma başlatıldı");

                // Stream'leri hazırlama
                List<MinidumpStream> streams = new List<MinidumpStream>();
                int handleStreamIndex = -1;

                // SystemInfo Stream
                streams.Add(CreateSystemInfoStream(systemInfo));

                // ThreadList Stream
                if (threadList.Count > 0)
                {
                    streams.Add(CreateThreadListStream(threadList));
                }

                // HandleList Stream (placeholder)
                if (handleList.Count > 0)
                {
                    handleStreamIndex = streams.Count;
                    streams.Add(CreateHandleListStream(handleList, 0)); // Geçici RVA = 0
                }

                // ModuleList Stream
                if (moduleList.Count > 0)
                {
                    streams.Add(CreateModuleListStream(moduleList));
                }

                // Memory64List Stream (Full memory)
                streams.Add(CreateMemory64ListStream(hProcess));

                // MiscInfo Stream
                streams.Add(CreateMiscInfoStream(processInfo));

                // Minidump header oluştur
                MinidumpHeader header = new MinidumpHeader
                {
                    Signature = 0x504d444d, // "PMDM"
                    Version = 0xa793,
                    NumberOfStreams = (ushort)streams.Count,
                    StreamDirectoryRva = 0x20,
                    TimeDateStamp = (IntPtr)DateTime.Now.ToFileTime()
                };

                // Stream directory oluştur ve HandleStream RVA'larını düzelt
                List<byte> streamDirectoryBytes = new List<byte>();
                uint currentOffset = (uint)(Marshal.SizeOf(typeof(MinidumpHeader)) + streams.Count * Marshal.SizeOf(typeof(MinidumpStreamDirectoryEntry)));

                for (int i = 0; i < streams.Count; i++)
                {
                    var stream = streams[i];
                    
                    // Offset taşma kontrolü
                    if (currentOffset + (uint)stream.Data.Length < currentOffset)
                    {
                        Console.WriteLine($"[ERROR] Offset taşması algılandı! Stream: {stream.StreamType}, Size: {stream.Data.Length}");
                        return false;
                    }

                    // Handle stream'i için RVA'ları düzelt
                    if (i == handleStreamIndex)
                    {
                        Console.WriteLine($"[DEBUG] Handle stream RVA düzeltiliyor, base offset: 0x{currentOffset:X}");
                        streams[i] = CreateHandleListStream(handleList, currentOffset);
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
        /// SystemInfo stream'i oluşturur
        /// </summary>
        private static MinidumpStream CreateSystemInfoStream(SystemInfoData systemInfo)
        {
            SystemInfoStream stream = new SystemInfoStream
            {
                ProcessorArchitecture = systemInfo.ProcessorArchitecture,
                ProcessorLevel = (ushort)systemInfo.ProcessorLevel,
                ProcessorRevision = (ushort)systemInfo.ProcessorRevision,
                NumberOfProcessors = systemInfo.ProcessorCount,
                MajorVersion = systemInfo.MajorVersion,
                MinorVersion = systemInfo.MinorVersion,
                BuildNumber = systemInfo.BuildNumber,
                PlatformId = systemInfo.PlatformId
            };

            return new MinidumpStream
            {
                StreamType = MINIDUMP_STREAM_TYPE_SystemInfo,
                Data = StructToByteArray(stream)
            };
        }

        /// <summary>
        /// ThreadList stream'i oluşturur
        /// </summary>
        private static MinidumpStream CreateThreadListStream(List<ThreadInfo> threadList)
        {
            List<byte> threadData = new List<byte>();
            threadData.AddRange(BitConverter.GetBytes((uint)threadList.Count));

            foreach (var threadInfo in threadList)
            {
                threadData.AddRange(StructToByteArray(threadInfo));
            }

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
        /// ModuleList stream'i oluşturur
        /// </summary>
        private static MinidumpStream CreateModuleListStream(List<ModuleInfo> moduleList)
        {
            List<byte> moduleData = new List<byte>();
            moduleData.AddRange(BitConverter.GetBytes((uint)moduleList.Count));

            foreach (var moduleInfo in moduleList)
            {
                moduleData.AddRange(StructToByteArray(moduleInfo));
            }

            return new MinidumpStream
            {
                StreamType = MINIDUMP_STREAM_TYPE_ModuleList,
                Data = moduleData.ToArray()
            };
        }

        /// <summary>
        /// Memory64List stream'i oluşturur (Full memory dump)
        /// </summary>
        private static MinidumpStream CreateMemory64ListStream(IntPtr hProcess)
        {
            try
            {
                // Bellek bölgelerini tara
                List<Memory64Info> memoryRegions = new List<Memory64Info>();
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

                    // Okunabilir ve committed bellek bölgeleri
                    if (mbi.Protect != PAGE_NOACCESS && mbi.State == MEM_COMMIT)
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

                        Memory64Info memInfo = new Memory64Info
                        {
                            Address = mbi.BaseAddress,
                            Size = mbi.RegionSize
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

                // Memory64List header
                Memory64ListStream memory64List = new Memory64ListStream
                {
                    NumberOfEntries = (ulong)memoryRegions.Count,
                    MemoryRegionsBaseAddress = (uint)(Marshal.SizeOf(typeof(Memory64ListStream)) + memoryRegions.Count * Marshal.SizeOf(typeof(Memory64Info)))
                };

                List<byte> memoryData = new List<byte>();
                memoryData.AddRange(StructToByteArray(memory64List));

                // Memory info entries
                foreach (var memInfo in memoryRegions)
                {
                    memoryData.AddRange(StructToByteArray(memInfo));
                }

                // Raw memory data - Büyük bölgeleri parçalara bölerek oku
                const int MAX_CHUNK_SIZE = 1024 * 1024; // 1MB chunks
                long totalReadSize = 0;

                foreach (var memInfo in memoryRegions)
                {
                    long remainingSize = (long)memInfo.Size;
                    long currentOffset = 0;
                    long regionReadSize = 0;

                    while (remainingSize > 0)
                    {
                        int chunkSize = (int)Math.Min(remainingSize, MAX_CHUNK_SIZE);
                        IntPtr chunkAddress = IntPtr.Add(memInfo.Address, (int)currentOffset);

                        try
                        {
                            byte[] buffer = new byte[chunkSize];
                            uint ntStatus = NtReadVirtualMemory(hProcess, chunkAddress, buffer, chunkSize, out _);

                            if (ntStatus == 0)
                            {
                                memoryData.AddRange(buffer);
                                regionReadSize += chunkSize;
                                totalReadSize += chunkSize;
                            }
                            else
                            {
                                // Okunamayan bölge için sıfırlarla doldur
                                memoryData.AddRange(new byte[chunkSize]);
                                Console.WriteLine($"[WARNING] Bellek bölgesi okunamadı: 0x{chunkAddress:X} ({chunkSize} bytes)");
                            }
                        }
                        catch (Exception ex)
                        {
                            // Okunamayan bölge için sıfırlarla doldur
                            memoryData.AddRange(new byte[chunkSize]);
                            Console.WriteLine($"[WARNING] Bellek bölgesi okunurken hata: {ex.Message}");
                        }

                        remainingSize -= chunkSize;
                        currentOffset += chunkSize;

                        // Progress reporting per region
                        if (regionReadSize % (10 * 1024 * 1024) == 0 && regionReadSize > 0) // Her 10MB'da rapor
                        {
                            Console.WriteLine($"[INFO] Bölge okunuyor: 0x{memInfo.Address:X} - {regionReadSize / (1024 * 1024)} MB okundu");
                        }
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
        /// MiscInfo stream'i oluşturur
        /// </summary>
        private static MinidumpStream CreateMiscInfoStream(ProcessInfoData processInfo)
        {
            MiscInfoStream miscInfo = new MiscInfoStream
            {
                SizeOfInfo = (uint)Marshal.SizeOf(typeof(MiscInfoStream)),
                Flags1 = 0x00000001, // MiniDumpMisc1
                ProcessId = processInfo.ProcessId,
                ProcessCreateTime = (uint)(processInfo.CreateTime.ToInt64() & 0xFFFFFFFF),
                ProcessUserTime = 0,
                ProcessKernelTime = 0
            };

            return new MinidumpStream
            {
                StreamType = MINIDUMP_STREAM_TYPE_MiscInfo,
                Data = StructToByteArray(miscInfo)
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