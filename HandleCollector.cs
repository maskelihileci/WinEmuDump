using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using static WinEmuDump.Win32;

namespace WinEmuDump
{
    internal class HandleCollector
    {
        // HandleCollector.cs - Sistem handle'larını toplama işlevi
        // Bu dosya NtQuerySystemInformation kullanarak sistem handle'larını toplar

        // Static object type cache - ObjectTypeIndex -> TypeName mapping
        // Artık "statik" sabit eşlemelere güvenmiyoruz. Her index için ilk karşılaşmada
        // handle'dan tip bilgisini sorgulayıp cache'liyoruz.
        private static Dictionary<byte, string> _objectTypeMap = new Dictionary<byte, string>();
        private static readonly object _mapLock = new object();

        /// <summary>
        /// İşlemin sahip olduğu tüm sistem handle'larını ve özelliklerini toplar
        /// </summary>
        /// <param name="hProcess">Hedef işlemin handle'ı</param>
        /// <param name="handleList">Toplanan handle bilgilerini içeren çıkış listesi</param>
        /// <returns>Başarılı ise true, aksi halde false</returns>
        public static bool CollectSystemHandles(IntPtr hProcess, out List<HandleInfo> handleList)
        {
            handleList = new List<HandleInfo>();

            try
            {
                // Sistem handle listesi için buffer boyutu
                uint bufferSize = 0x10000; // 64KB başlangıç boyutu
                IntPtr buffer = IntPtr.Zero;

                while (true)
                {
                    buffer = Marshal.AllocHGlobal((int)bufferSize);
                    if (buffer == IntPtr.Zero)
                    {
                        Console.WriteLine("[ERROR] Bellek tahsis edilemedi");
                        return false;
                    }

                    uint returnLength;
                    uint ntStatus = NtQuerySystemInformation(SystemHandleInformation, buffer, bufferSize, out returnLength);

                    if (ntStatus == 0xC0000004) // STATUS_INFO_LENGTH_MISMATCH
                    {
                        Marshal.FreeHGlobal(buffer);
                        bufferSize = returnLength + 0x1000; // Ek buffer ekle
                        continue;
                    }
                    else if (ntStatus != 0)
                    {
                        Marshal.FreeHGlobal(buffer);
                        Console.WriteLine($"[ERROR] NtQuerySystemInformation başarısız. NTSTATUS: 0x{ntStatus:X}");
                        return false;
                    }

                    break;
                }

                try
                {
                    // SYSTEM_HANDLE_INFORMATION yapısını oku
                    SYSTEM_HANDLE_INFORMATION handleInfo = Marshal.PtrToStructure<SYSTEM_HANDLE_INFORMATION>(buffer);
                    IntPtr handleArrayPtr = IntPtr.Add(buffer, 8); // Doğru offset: NumberOfHandles (4 byte) + padding/alignment (4 byte)

                    Console.WriteLine($"[INFO] Sistemde toplam {handleInfo.NumberOfHandles} handle bulundu");

                    // İşlem ID'sini al
                    int processId = GetProcessIdFromHandle(hProcess);
                    Console.WriteLine($"[DEBUG] Hedef process PID: {processId}");

                    // Her handle için döngü
                    for (int i = 0; i < handleInfo.NumberOfHandles; i++)
                    {
                        try
                        {
                            SYSTEM_HANDLE_TABLE_ENTRY_INFO handleEntry = Marshal.PtrToStructure<SYSTEM_HANDLE_TABLE_ENTRY_INFO>(
                                IntPtr.Add(handleArrayPtr, i * Marshal.SizeOf(typeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO)))
                            );

                            // Debug loglama - ilk 5 handle için
                            if (i < 5)
                            {
                                Console.WriteLine($"[DEBUG] Handle {i}: PID={handleEntry.UniqueProcessId}, HandleValue=0x{handleEntry.HandleValue:X}, TypeIndex={handleEntry.ObjectTypeIndex}, GrantedAccess={handleEntry.GrantedAccess:X}");
                            }

                            // Bu handle bizim işlemimize ait mi kontrol et - type casting düzeltmesi
                            if (handleEntry.UniqueProcessId == (ushort)processId)
                            {
                                HandleInfo handleInfoStruct = new HandleInfo
                                {
                                    HandleValue = handleEntry.HandleValue,
                                    GrantedAccess = handleEntry.GrantedAccess,
                                    ObjectTypeIndex = handleEntry.ObjectTypeIndex,
                                    HandleAttributes = handleEntry.HandleAttributes,
                                    ObjectPointer = handleEntry.Object
                                };

                                // Handle türünü belirlemeye çalış - cache tabanlı, güvenilir yöntem
                                if (GetHandleTypeName(hProcess, handleEntry, out string typeName))
                                {
                                    handleInfoStruct.TypeName = typeName;
                                }

                                // Object name'i belirlemeye çalış (tüm handle'lar için dene)
                                if (GetHandleObjectName(hProcess, handleEntry, out string objectName))
                                {
                                    handleInfoStruct.ObjectName = objectName;
                                }

                                handleList.Add(handleInfoStruct);
                            }
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"[WARNING] Handle {i} işlenirken hata: {ex.Message}");
                            // Devam et, diğer handle'ları işle
                        }
                    }

                    Console.WriteLine($"[INFO] İşlem için {handleList.Count} handle bilgisi toplandı");
                    return true;
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ERROR] Sistem handle'ları toplanamadı: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Handle türünü belirler (daha güvenilir: ilk önce cache, yoksa handle üzerinden sorgula ve cache'le)
        /// </summary>
        private static bool GetHandleTypeName(IntPtr targetProcessHandle, SYSTEM_HANDLE_TABLE_ENTRY_INFO handleEntry, out string typeName)
        {
            typeName = "Unknown";

            try
            {
                lock (_mapLock)
                {
                    if (_objectTypeMap.TryGetValue(handleEntry.ObjectTypeIndex, out var cached))
                    {
                        typeName = cached;
                        return true;
                    }
                }

                // Cache'de yoksa, handle'ı duplicate edip NtQueryObject(ObjectTypeInformation) ile tip bilgisini al
                string resolved = QueryTypeFromHandle(targetProcessHandle, handleEntry.HandleValue);
                if (!string.IsNullOrEmpty(resolved))
                {
                    lock (_mapLock)
                    {
                        // Overwrite veya ekle
                        _objectTypeMap[handleEntry.ObjectTypeIndex] = resolved;
                    }

                    typeName = resolved;
                    return true;
                }

                // Eğer tip halen alınamadıysa - çok sınırlı ve güvenilir fallback (sadece bazı genel tipleri gösterir)
                var fallback = new Dictionary<byte, string>
                {
                    { 0x02, "Directory" },
                    { 0x03, "SymbolicLink" },
                    { 0x04, "Token" },
                    { 0x05, "Process" },
                    { 0x06, "Thread" },
                    { 0x07, "Job" },
                    { 0x08, "Event" },
                    { 0x09, "EventPair" },
                    { 0x0A, "Mutant" },
                    { 0x0B, "Callback" },
                    { 0x0C, "Semaphore" },
                    { 0x0D, "Timer" },
                    { 0x13, "File" },
                    { 0x32, "EtwRegistration" }, // 👈 eklendi
                };


                if (fallback.TryGetValue(handleEntry.ObjectTypeIndex, out var fb))
                {
                    typeName = fb;
                    return true;
                }

                // Son çare: index'i döndür
                typeName = $"Type_{handleEntry.ObjectTypeIndex}";
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[WARNING] Handle türü belirlenirken hata: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Verilen hedef süreçten verilen handle değerini duplicate edip NtQueryObject ile ObjectTypeInformation alır.
        /// Bu yöntem, ObjectTypeIndex'e sabit bir isim atamaya göre çok daha güvenilirdir.
        /// </summary>
        private static string QueryTypeFromHandle(IntPtr targetProcessHandle, uint handleValue)
        {
            IntPtr duplicated = IntPtr.Zero;
            try
            {
                bool dupOk = DuplicateHandle(
                    targetProcessHandle,
                    (IntPtr)handleValue,
                    GetCurrentProcess(),
                    out duplicated,
                    0,
                    false,
                    2 // DUPLICATE_SAME_ACCESS
                );

                if (!dupOk || duplicated == IntPtr.Zero)
                {
                    // DuplicateHandle bazen başarısız olabilir (örn. farklı yetkiler, kapanmış handle, vs.)
                    return null;
                }

                // İlk olarak 0 uzunluğu ile bilgi talep et - gerekli bufferSize'ı al
                const uint ObjectTypeInformation = 2;
                uint returnLength = 0;
                uint status = NtQueryObject(duplicated, ObjectTypeInformation, IntPtr.Zero, 0, out returnLength);

                if (returnLength == 0 || returnLength > 0x10000)
                {
                    // Anormal durum
                    return null;
                }

                IntPtr buffer = Marshal.AllocHGlobal((int)returnLength);
                try
                {
                    status = NtQueryObject(duplicated, ObjectTypeInformation, buffer, returnLength, out returnLength);
                    if (status != 0 || returnLength == 0)
                        return null;

                    // OBJECT_TYPE_INFORMATION içinde TypeName UNICODE_STRING ile başlar.
                    // UNICODE_STRING: USHORT Length; USHORT MaximumLength; PVOID Buffer;
                    short nameLen = Marshal.ReadInt16(buffer, 0);
                    // short nameMax = Marshal.ReadInt16(buffer, 2);
                    IntPtr nameBuffer = Marshal.ReadIntPtr(buffer, IntPtr.Size == 8 ? 8 : 4);

                    if (nameBuffer == IntPtr.Zero || nameLen <= 0)
                        return null;

                    byte[] nameBytes = new byte[nameLen];
                    Marshal.Copy(nameBuffer, nameBytes, 0, nameLen);
                    string typeName = System.Text.Encoding.Unicode.GetString(nameBytes).TrimEnd('\0');
                    return typeName;
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
            catch
            {
                return null;
            }
            finally
            {
                if (duplicated != IntPtr.Zero)
                {
                    NtClose(duplicated);
                }
            }
        }

        /// <summary>
        /// Handle object name'ini belirler (File path, Registry key, etc.)
        /// (Mevcut implementasyonunuzu korudum, küçük güvenlik kontrolü eklendi)
        /// </summary>
        private static bool GetHandleObjectName(IntPtr hProcess, SYSTEM_HANDLE_TABLE_ENTRY_INFO handleEntry, out string objectName)
        {
            objectName = null;

            try
            {
                // DuplicateHandle kullan
                IntPtr duplicatedHandle = IntPtr.Zero;

                if (!DuplicateHandle(
                    hProcess,
                    (IntPtr)handleEntry.HandleValue,
                    GetCurrentProcess(),
                    out duplicatedHandle,
                    0,
                    false,
                    2)) // DUPLICATE_SAME_ACCESS
                {
                    return false;
                }

                try
                {
                    const uint ObjectNameInformation = 1;
                    uint returnLength = 0;

                    // İlk çağrı - buffer boyutu belirleme
                    uint ntStatus = NtQueryObject(duplicatedHandle, ObjectNameInformation, IntPtr.Zero, 0, out returnLength);

                    if (returnLength == 0 || returnLength > 0x10000) // 64KB limit
                    {
                        return false;
                    }

                    IntPtr buffer = Marshal.AllocHGlobal((int)returnLength);
                    try
                    {
                        ntStatus = NtQueryObject(duplicatedHandle, ObjectNameInformation, buffer, returnLength, out returnLength);
                        if (ntStatus == 0 && returnLength > 0)
                        {
                            short nameLength = Marshal.ReadInt16(buffer, 0);
                            IntPtr nameBuffer = Marshal.ReadIntPtr(buffer, IntPtr.Size == 8 ? 8 : 4);

                            if (nameBuffer != IntPtr.Zero && nameLength > 0)
                            {
                                byte[] nameBytes = new byte[nameLength];
                                Marshal.Copy(nameBuffer, nameBytes, 0, nameLength);
                                objectName = System.Text.Encoding.Unicode.GetString(nameBytes).TrimEnd('\0');
                                return true;
                            }
                        }
                    }
                    finally
                    {
                        if (buffer != IntPtr.Zero)
                            Marshal.FreeHGlobal(buffer);
                    }
                }
                finally
                {
                    if (duplicatedHandle != IntPtr.Zero)
                        NtClose(duplicatedHandle);
                }

                return false;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[DEBUG] GetHandleObjectName exception: {ex.Message}");
                return false;
            }
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool DuplicateHandle(
            IntPtr hSourceProcessHandle,
            IntPtr hSourceHandle,
            IntPtr hTargetProcessHandle,
            out IntPtr lpTargetHandle,
            uint dwDesiredAccess,
            bool bInheritHandle,
            uint dwOptions);

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
                return System.Diagnostics.Process.GetCurrentProcess().Id;
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
    /// Handle bilgilerini tutan struct
    /// </summary>
    public struct HandleInfo
    {
        public uint HandleValue;
        public uint GrantedAccess;
        public byte ObjectTypeIndex;
        public byte HandleAttributes;
        public IntPtr ObjectPointer;
        public string TypeName;
        public string ObjectName;  // Object name (File path, Registry key, etc.)
    }
}
