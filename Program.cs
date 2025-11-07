using System;
using System.Diagnostics;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using static WinEmuDump.Win32;
using static WinEmuDump.NativeApi;
using WinEmuDump.Helpers;


namespace WinEmuDump
{
    internal class Program
    {
        static void EnableDebugPrivileges()
        {
            IntPtr currentProcess = Process.GetCurrentProcess().Handle;
            IntPtr tokenHandle = IntPtr.Zero;
            try
            {
                uint ntstatus = NtOpenProcessToken(currentProcess, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, ref tokenHandle);
                if (ntstatus != 0)
                {
                    Console.WriteLine("[-] Error calling NtOpenProcessToken. NTSTATUS: 0x" + ntstatus.ToString("X"));
                    Environment.Exit(-1);
                }

                TOKEN_PRIVILEGES tokenPrivileges = new TOKEN_PRIVILEGES
                {
                    PrivilegeCount = 1,
                    Luid = new LUID { LowPart = 20, HighPart = 0 }, // LookupPrivilegeValue(null, "SeDebugPrivilege", ref luid);
                    Attributes = 0x00000002
                };

                ntstatus = NtAdjustPrivilegesToken(tokenHandle, false, ref tokenPrivileges, (uint)Marshal.SizeOf(typeof(TOKEN_PRIVILEGES)), IntPtr.Zero, IntPtr.Zero);
                if (ntstatus != 0)
                {
                    Console.WriteLine("[-] Error calling NtAdjustPrivilegesToken. NTSTATUS: 0x" + ntstatus.ToString("X") + ". Maybe you need to calculate the LowPart of the LUID using LookupPrivilegeValue");
                    Environment.Exit(-1);
                }
            }
            finally
            {
                if (tokenHandle != IntPtr.Zero)
                {
                    NtClose(tokenHandle);
                }
            }
        }




        public unsafe static IntPtr CustomGetModuleHandle(IntPtr hProcess, String dll_name)
        {
            uint process_basic_information_size = 48;
            int peb_offset = 0x8;
            int ldr_offset = 0x18;
            int inInitializationOrderModuleList_offset = 0x30;
            int flink_dllbase_offset = 0x20;
            int flink_buffer_offset = 0x50;
            // If 32-bit process these offsets change
            if (IntPtr.Size == 4)
            {
                process_basic_information_size = 24;
                peb_offset = 0x4;
                ldr_offset = 0x0c;
                inInitializationOrderModuleList_offset = 0x1c;
                flink_dllbase_offset = 0x18;
                flink_buffer_offset = 0x30;
            }

            // Create byte array with the size of the PROCESS_BASIC_INFORMATION structure
            byte[] pbi_byte_array = new byte[process_basic_information_size];

            // Create a PROCESS_BASIC_INFORMATION structure in the byte array
            IntPtr pbi_addr = IntPtr.Zero;
            fixed (byte* p = pbi_byte_array)
            {
                pbi_addr = (IntPtr)p;

                uint ntstatus = NtQueryInformationProcess(hProcess, 0x0, pbi_addr, process_basic_information_size, out uint ReturnLength);
                if (ntstatus != 0)
                {
                    Console.WriteLine("[-] Error calling NtQueryInformationProcess. NTSTATUS: 0x" + ntstatus.ToString("X"));
                }
                Console.WriteLine("[+] Process_Basic_Information Address: \t\t0x" + pbi_addr.ToString("X"));
            }

            // Get PEB Base Address
            IntPtr peb_pointer = pbi_addr + peb_offset;
            Console.WriteLine("[+] PEB Address Pointer:\t\t\t0x" + peb_pointer.ToString("X"));
            IntPtr pebaddress = Marshal.ReadIntPtr(peb_pointer);
            Console.WriteLine("[+] PEB Address:\t\t\t\t0x" + pebaddress.ToString("X"));

            // Get Ldr 
            IntPtr ldr_pointer = pebaddress + ldr_offset;
            IntPtr ldr_adress = MemoryHelper.ReadRemoteIntPtr(hProcess, ldr_pointer);
            if (ldr_adress == IntPtr.Zero) {
                Console.WriteLine("[-] PEB structure is not readable.");
                Environment.Exit(0);
            }
            
            IntPtr InInitializationOrderModuleList = ldr_adress + inInitializationOrderModuleList_offset;
            Console.WriteLine("[+] InInitializationOrderModuleList:\t\t0x" + InInitializationOrderModuleList.ToString("X"));
            IntPtr next_flink = MemoryHelper.ReadRemoteIntPtr(hProcess, InInitializationOrderModuleList);

            IntPtr dll_base = (IntPtr)1337;
            while (dll_base != IntPtr.Zero)
            {
                next_flink = next_flink - 0x10;
                // Get DLL base address
                dll_base = MemoryHelper.ReadRemoteIntPtr(hProcess, (next_flink + flink_dllbase_offset));
                IntPtr buffer = MemoryHelper.ReadRemoteIntPtr(hProcess, (next_flink + flink_buffer_offset));

                string base_dll_name = MemoryHelper.ReadRemoteUnicodeString(hProcess, buffer);

                next_flink = MemoryHelper.ReadRemoteIntPtr(hProcess, (next_flink + 0x10));
                
                // Compare with DLL name we are searching
                if (dll_name.ToLower() == base_dll_name.ToLower())
                {
                    return dll_base;
                }
            }
            return IntPtr.Zero;
        }


        static void Main(string[] args)
        {
            Console.WriteLine("[INFO] Windows Emülatörü için Gelişmiş Minidump Oluşturma Aracı");
            Console.WriteLine("[INFO] FullMemory, Thread, Handles, ModuleInfo, SystemInfo içerir");
            Console.WriteLine();

            // Check binary is correctly compiled
            if (!Environment.Is64BitProcess)
            {
                Console.WriteLine("[-] Dosya 64-bit binary olarak derlenmelidir.");
                Environment.Exit(-1);
            }

            // Parse command line arguments
            string targetProcess = ParseArguments(args);
            if (string.IsNullOrEmpty(targetProcess))
            {
                ShowUsage();
                Environment.Exit(0);
            }

            // Get process PID
            int processPID = GetProcessPID(targetProcess);
            if (processPID == 0)
            {
                Console.WriteLine($"[-] Process '{targetProcess}' bulunamadı.");
                Environment.Exit(0);
            }
            Console.WriteLine($"[+] Process PID: {processPID}");

            // Get SeDebugPrivilege
            Console.WriteLine("[INFO] SeDebugPrivilege ayarlanıyor...");
            EnableDebugPrivileges();

            // Get process handle with NtOpenProcess
            IntPtr processHandle = IntPtr.Zero;
            CLIENT_ID client_id = new CLIENT_ID
            {
                UniqueProcess = (IntPtr)processPID,
                UniqueThread = IntPtr.Zero
            };
            OBJECT_ATTRIBUTES objAttr = new OBJECT_ATTRIBUTES();

            uint ntstatus = NtOpenProcess(ref processHandle, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_DUP_HANDLE | PROCESS_VM_OPERATION, ref objAttr, ref client_id);
            if (ntstatus != 0)
            {
                Console.WriteLine($"[-] NtOpenProcess hatası. NTSTATUS: 0x{ntstatus:X}");
                Environment.Exit(-1);
            }
            Console.WriteLine($"[+] Process handle: {processHandle}");

            try
            {
                // Sistem bilgilerini topla
                Console.WriteLine("[INFO] Sistem bilgileri toplanıyor...");
                SystemInfoData systemInfo;
                if (!SystemInfoHelper.CollectSystemInfo(processHandle, out systemInfo))
                {
                    Console.WriteLine("[WARNING] Sistem bilgileri toplanamadı, devam ediliyor...");
                }

                // İşlem bilgilerini topla
                Console.WriteLine("[INFO] İşlem bilgileri toplanıyor...");
                ProcessInfoData processInfo;
                if (!SystemInfoHelper.CollectProcessInfo(processHandle, out processInfo))
                {
                    Console.WriteLine("[WARNING] İşlem bilgileri toplanamadı");
                    processInfo = new ProcessInfoData { ProcessId = (uint)processPID, ImageName = targetProcess };
                }

                // Thread bilgilerini topla
                Console.WriteLine("[INFO] Thread bilgileri toplanıyor...");
                List<MinidumpThreadInfo> threadList = new List<MinidumpThreadInfo>();
                if (!MinidumpBuilder.CollectAdvancedThreadInformation(processHandle, out threadList))
                {
                    Console.WriteLine("[WARNING] Thread bilgileri toplanamadı - eski yöntem kullanılıyor");
                    // Fallback: Eski thread toplama yöntemini kullan
                    List<ThreadInfo> oldThreadList = new List<ThreadInfo>();
                    if (ThreadHelper.CollectThreadInformation(processHandle, out oldThreadList))
                    {
                        Console.WriteLine($"[INFO] Eski yöntemle {oldThreadList.Count} thread bulundu");
                        // Eski ThreadInfo'yu MinidumpThreadInfo'ya çevir (şimdilik TEB=0, Stack=0 ile)
                        foreach (var oldThread in oldThreadList)
                        {
                            threadList.Add(new MinidumpThreadInfo
                            {
                                ThreadId = oldThread.ThreadId,
                                TebAddress = 0, // Bilinmiyor
                                StackBase = 0,  // Bilinmiyor
                                StackSize = 0,  // Bilinmiyor
                                Context = new CONTEXT() // Boş context
                            });
                        }
                    }
                }
                else
                {
                    Console.WriteLine($"[INFO] Gelişmiş yöntemle {threadList.Count} thread bulundu");
                }

                // Handle bilgilerini topla
                Console.WriteLine("[INFO] Sistem handle'ları toplanıyor...");
                List<HandleInfo> handleList = new List<HandleInfo>();
                if (!HandleHelper.CollectSystemHandles(processHandle, out handleList))
                {
                    Console.WriteLine("[WARNING] Handle bilgileri toplanamadı");
                }

                // Modül bilgilerini topla
                Console.WriteLine("[INFO] Modül bilgileri toplanıyor...");
                List<ModuleInfo> moduleList = CollectModuleInformation(processHandle);

                // Minidump dosya adını belirle
                string dumpfile = $"advanced_dump_{processPID}_{DateTime.Now.ToString("yyyyMMdd_HHmmss")}.dmp";
                if (args.Length > 1)
                {
                    dumpfile = args[1];
                }

                // Gelişmiş minidump oluştur
                Console.WriteLine("[INFO] Gelişmiş minidump oluşturuluyor...");
                if (MinidumpBuilder.BuildAdvancedMinidump(processHandle, processInfo, threadList, handleList, moduleList, systemInfo, dumpfile))
                {
                    Console.WriteLine($"[SUCCESS] Gelişmiş minidump başarıyla oluşturuldu: {dumpfile}");
                    Console.WriteLine("[INFO] İçerik:");
                    Console.WriteLine($"  - SystemInfo: Windows {systemInfo.MajorVersion}.{systemInfo.MinorVersion} Build {systemInfo.BuildNumber}");
                    Console.WriteLine($"  - ThreadList: {threadList.Count} thread (TEB + Stack + Context)");
                    Console.WriteLine($"  - ThreadInfoList: {threadList.Count} thread info");
                    Console.WriteLine($"  - Exception: {(threadList.Count > 0 ? "var" : "yok")}");
                    Console.WriteLine($"  - HandleList: {handleList.Count} handle");
                    Console.WriteLine($"  - HandleOperationList: boş liste");
                    Console.WriteLine($"  - ModuleList: {moduleList.Count} modül");
                    Console.WriteLine($"  - UnloadedModuleList: boş liste");
                    Console.WriteLine($"  - Memory64List: Full memory dump");
                    Console.WriteLine($"  - MemoryInfoList: Bellek bölgeleri detayları");
                    Console.WriteLine($"  - MiscInfo: Process {processInfo.ProcessId}");
                    Console.WriteLine($"  - CommentStreamA/W: Metadata");
                    Console.WriteLine($"  - ThreadNamesStream: Thread isimleri");
                    Console.WriteLine($"  - FunctionTableStream: boş liste");
                    Console.WriteLine($"  - SystemMemoryInfo: Sistem belleği");
                    Console.WriteLine($"  - ProcessVmCounters: VM sayaçları");
                    Console.WriteLine($"  - TokenStream: boş liste");
                    Console.WriteLine($"  - JavaScriptDataStream: boş liste");
                    Console.WriteLine($"  - IptTraceStream: boş liste");

                    // Kod doğrulama testi
                    if (ValidateDumpFile(dumpfile))
                    {
                        Console.WriteLine($"[SUCCESS] Dosya doğrulama testi başarılı!");
                    }
                    else
                    {
                        Console.WriteLine($"[WARNING] Dosya doğrulama testinde sorunlar var ama dosya oluşturuldu");
                    }
                }
                else
                {
                    Console.WriteLine("[-] Gelişmiş minidump oluşturma başarısız!");
                    Environment.Exit(-1);
                }
            }
            finally
            {
                // Close process handle
                if (processHandle != IntPtr.Zero)
                {
                    ntstatus = NtClose(processHandle);
                    if (ntstatus != 0)
                    {
                        Console.WriteLine($"[-] Process handle kapatılamadı. NTSTATUS: 0x{ntstatus:X}");
                    }
                }
            }
        }

        /// <summary>
        /// Komut satırı argümanlarını ayrıştırır
        /// </summary>
        static string ParseArguments(string[] args)
        {
            if (args.Length == 0)
            {
                // İnteraktif mod - kullanıcıdan işlem adı iste
                Console.Write("Hedef işlem adı (örn: notepad, lsass, explorer): ");
                return Console.ReadLine()?.Trim();
            }
            else if (args.Length >= 1)
            {
                // İlk argüman işlem adı
                return args[0];
            }

            return null;
        }

        /// <summary>
        /// Kullanım bilgilerini gösterir
        /// </summary>
        static void ShowUsage()
        {
            Console.WriteLine("Kullanım:");
            Console.WriteLine("  NativeDump.exe [işlem_adı] [çıktı_dosyası]");
            Console.WriteLine();
            Console.WriteLine("Örnekler:");
            Console.WriteLine("  NativeDump.exe notepad");
            Console.WriteLine("  NativeDump.exe lsass dump.dmp");
            Console.WriteLine("  NativeDump.exe explorer mydump.dmp");
            Console.WriteLine();
            Console.WriteLine("İnteraktif mod için argüman olmadan çalıştırın.");
        }

        /// <summary>
        /// İşlem adından PID'yi alır
        /// </summary>
        static int GetProcessPID(string processName)
        {
            try
            {
                // Önce tam isim ile ara
                Process[] processes = Process.GetProcessesByName(processName);
                if (processes.Length > 0)
                {
                    return processes[0].Id;
                }

                // PID olarak yorumla
                if (int.TryParse(processName, out int pid))
                {
                    Process process = Process.GetProcessById(pid);
                    return process.Id;
                }
            }
            catch
            {
                // Hata durumunda devam et
            }

            return 0;
        }

        /// <summary>
        /// Modül bilgilerini toplar
        /// </summary>
        static List<ModuleInfo> CollectModuleInformation(IntPtr hProcess)
        {
            List<ModuleInfo> moduleList = new List<ModuleInfo>();

            try
            {
                // Ana modülü al
                Process process = Process.GetProcessById((int)Kernel32Api.GetProcessId(hProcess));
                IntPtr baseAddress = process.MainModule.BaseAddress;
                int moduleSize = process.MainModule.ModuleMemorySize;

                ModuleInfo mainModule = new ModuleInfo
                {
                    BaseAddress = baseAddress,
                    Size = (IntPtr)moduleSize,
                    Timestamp = 0,
                    Checksum = 0,
                    ModuleNameRva = 0,
                    ImageName = Marshal.StringToHGlobalUni(process.MainModule.FileName)
                };

                moduleList.Add(mainModule);

                // Diğer modüller
                foreach (ProcessModule module in process.Modules)
                {
                    if (module.BaseAddress != baseAddress) // Ana modülü tekrar ekleme
                    {
                        ModuleInfo modInfo = new ModuleInfo
                        {
                            BaseAddress = module.BaseAddress,
                            Size = (IntPtr)module.ModuleMemorySize,
                            Timestamp = 0,
                            Checksum = 0,
                            ModuleNameRva = 0,
                            ImageName = Marshal.StringToHGlobalUni(module.FileName)
                        };

                        moduleList.Add(modInfo);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[WARNING] Modül bilgileri toplanırken hata: {ex.Message}");
            }

            return moduleList;
        }

        // GetProcessIdFromHandle, LoadLibrary, GetProcAddress fonksiyonları Api/Kernel32Api.cs'e taşındı

        /// <summary>
        /// Oluşturulan dump dosyasının temel doğrulamasını yapar
        /// </summary>
        private static bool ValidateDumpFile(string dumpPath)
        {
            try
            {
                Console.WriteLine("[INFO] Dump dosyası doğrulanıyor...");

                // Dosya varlığını kontrol et
                if (!System.IO.File.Exists(dumpPath))
                {
                    Console.WriteLine("[ERROR] Dump dosyası bulunamadı!");
                    return false;
                }

                // Dosya boyutunu kontrol et
                var fileInfo = new System.IO.FileInfo(dumpPath);
                if (fileInfo.Length < 1024) // Minimum 1KB
                {
                    Console.WriteLine($"[WARNING] Dump dosyası çok küçük: {fileInfo.Length} bytes");
                    return false;
                }

                // Temel header kontrolü
                using (var fs = new System.IO.FileStream(dumpPath, System.IO.FileMode.Open, System.IO.FileAccess.Read))
                using (var reader = new System.IO.BinaryReader(fs))
                {
                    // Signature kontrolü (PMDM)
                    uint signature = reader.ReadUInt32();
                    if (signature != 0x504d444d)
                    {
                        Console.WriteLine($"[ERROR] Geçersiz signature: 0x{signature:X}");
                        return false;
                    }

                    // Version kontrolü
                    uint version = reader.ReadUInt32();
                    Console.WriteLine($"[INFO] Minidump versiyonu: 0x{version:X}");

                    // Stream sayısı
                    uint streamCount = reader.ReadUInt32();
                    Console.WriteLine($"[INFO] Stream sayısı: {streamCount}");

                    if (streamCount == 0 || streamCount > 50)
                    {
                        Console.WriteLine($"[WARNING] Şüpheli stream sayısı: {streamCount}");
                        return false;
                    }
                }

                Console.WriteLine($"[SUCCESS] Temel doğrulama başarılı - Dosya boyutu: {fileInfo.Length / (1024*1024.0):F2} MB");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ERROR] Dosya doğrulama hatası: {ex.Message}");
                return false;
            }
        }

        // GetProcessIdDelegate fonksiyonu artık kullanılmıyor - Api/Kernel32Api.cs'teki GetProcessId kullanılıyor
    }
}