using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

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

///////////////// EXTENDED STRUCTS FOR ADVANCED MINIDUMP /////////////////

[StructLayout(LayoutKind.Sequential)]
public struct SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
    public ushort UniqueProcessId;
    public ushort CreatorBackTraceIndex;
    public byte ObjectTypeIndex;
    public byte HandleAttributes;
    public ushort HandleValue;
    public IntPtr Object;
    public uint GrantedAccess;
    public ushort CreatorBackTraceIndex2; // Windows 7+ için ek alan
}

[StructLayout(LayoutKind.Sequential)]
public struct SYSTEM_HANDLE_INFORMATION
{
    public uint NumberOfHandles;
    public SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles;
}

namespace WinEmuDump.Helpers
{
    /// <summary>
    /// Handle işlemleri için yardımcı fonksiyonlar
    /// HandleCollector.cs içindeki fonksiyonların yardımcı sınıfa taşınmış hali
    /// Kompakt ve tekrar kullanılabilir tasarım için ortak handle operasyonları
    /// </summary>
    internal static class HandleHelper
    {
        // Source File #2 (HandleHelper.cs)

        // Static object type cache - ObjectTypeIndex -> TypeName mapping
        // NtQueryObject ile dinamik olarak doldurulur.
        private static readonly Dictionary<byte, string> _objectTypeMap = new Dictionary<byte, string>();
        private static readonly object _mapLock = new object();

        /// <summary>
        /// Hedef işlemin sahip olduğu tüm sistem handle'larını ve özelliklerini toplar.
        /// NtQuerySystemInformation(SystemHandleInformation) kullanır.
        /// </summary>
        /// <param name="hProcess">Hedef işlemin handle'ı</param>
        /// <param name="handleList">Toplanan handle bilgilerini içeren çıkış listesi</param>
        /// <returns>Başarılı ise true, aksi halde false</returns>
        public static bool CollectSystemHandles(IntPtr hProcess, out List<HandleInfo> handleList)
        {
            handleList = new List<HandleInfo>();

            try
            {
                // Sistem handle listesi için başlangıç buffer boyutu
                uint bufferSize = 0x10000; // 64KB
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
                    uint SystemHandleInformation = 16;
                    uint ntStatus = NativeApi.NtQuerySystemInformation(SystemHandleInformation, buffer, bufferSize, out returnLength);

                    if (ntStatus == 0xC0000004) // STATUS_INFO_LENGTH_MISMATCH
                    {
                        Marshal.FreeHGlobal(buffer);
                        bufferSize = returnLength + 0x1000; // Biraz artır
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
                    IntPtr handleArrayPtr = IntPtr.Add(buffer, 8); // NumberOfHandles (4) + alignment (4)

                    Console.WriteLine($"[INFO] Sistemde toplam {handleInfo.NumberOfHandles} handle bulundu");

                    // Hedef işlemin PID'sini al
                    int processId = (int)Kernel32Api.GetProcessId(hProcess);
                    Console.WriteLine($"[DEBUG] Hedef process PID: {processId}");

                    for (int i = 0; i < handleInfo.NumberOfHandles; i++)
                    {
                        try
                        {
                            var handleEntry = Marshal.PtrToStructure<SYSTEM_HANDLE_TABLE_ENTRY_INFO>(
                                IntPtr.Add(handleArrayPtr, i * Marshal.SizeOf(typeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO)))
                            );

                            // Debug: ilk birkaç handle için log
                            if (i < 5)
                            {
                                Console.WriteLine($"[DEBUG] Handle {i}: PID={handleEntry.UniqueProcessId}, HandleValue=0x{handleEntry.HandleValue:X}, TypeIndex={handleEntry.ObjectTypeIndex}, GrantedAccess={handleEntry.GrantedAccess:X}");
                            }

                            // Hedef işleme ait olanları filtrele
                            if (handleEntry.UniqueProcessId == (ushort)processId)
                            {
                                var handleInfoStruct = new HandleInfo
                                {
                                    HandleValue = handleEntry.HandleValue,
                                    GrantedAccess = handleEntry.GrantedAccess,
                                    ObjectTypeIndex = handleEntry.ObjectTypeIndex,
                                    HandleAttributes = handleEntry.HandleAttributes,
                                    ObjectPointer = handleEntry.Object
                                };

                                // Tür adı
                                if (GetHandleTypeName(hProcess, handleEntry, out string typeName))
                                    handleInfoStruct.TypeName = typeName;

                                // Obje adı
                                if (GetHandleObjectName(hProcess, handleEntry, out string objectName))
                                    handleInfoStruct.ObjectName = objectName;

                                handleList.Add(handleInfoStruct);
                            }
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"[WARNING] Handle {i} işlenirken hata: {ex.Message}");
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
        /// Handle türünü belirler (önce cache, yoksa NtQueryObject ile çöz ve cache'e yaz).
        /// </summary>
        private static bool GetHandleTypeName(IntPtr targetProcessHandle, SYSTEM_HANDLE_TABLE_ENTRY_INFO handleEntry, out string typeName)
        {
            typeName = "Unknown";

            try
            {
                // Önce cache
                lock (_mapLock)
                {
                    if (_objectTypeMap.TryGetValue(handleEntry.ObjectTypeIndex, out var cached))
                    {
                        typeName = cached;
                        return true;
                    }
                }

                // Cache'de yoksa handle üzerinden sorgula
                string resolved = QueryTypeFromHandle(targetProcessHandle, handleEntry.HandleValue);
                if (!string.IsNullOrEmpty(resolved))
                {
                    lock (_mapLock)
                    {
                        _objectTypeMap[handleEntry.ObjectTypeIndex] = resolved;
                    }

                    typeName = resolved;
                    return true;
                }

                // Sınırlı fallback eşlemeleri
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
                    { 0x32, "EtwRegistration" }
                };

                if (fallback.TryGetValue(handleEntry.ObjectTypeIndex, out var fb))
                {
                    typeName = fb;
                    return true;
                }

                // Son çare
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
        /// Verilen handle değerini duplicate edip NtQueryObject(ObjectTypeInformation) ile tip adını döndürür.
        /// </summary>
        private static string QueryTypeFromHandle(IntPtr targetProcessHandle, uint handleValue)
        {
            IntPtr duplicated = IntPtr.Zero;

            try
            {
                bool dupOk = Kernel32Api.DuplicateHandle(
                    targetProcessHandle,
                    (IntPtr)handleValue,
                    Kernel32Api.GetCurrentProcess(),
                    out duplicated,
                    0,
                    false,
                    2 // DUPLICATE_SAME_ACCESS
                );

                if (!dupOk || duplicated == IntPtr.Zero)
                    return null;

                const uint ObjectTypeInformation = 2;
                uint returnLength = 0;
                uint status = NativeApi.NtQueryObject(duplicated, ObjectTypeInformation, IntPtr.Zero, 0, out returnLength);

                if (returnLength == 0 || returnLength > 0x10000)
                    return null;

                IntPtr buffer = Marshal.AllocHGlobal((int)returnLength);
                try
                {
                    status = NativeApi.NtQueryObject(duplicated, ObjectTypeInformation, buffer, returnLength, out returnLength);
                    if (status != 0 || returnLength == 0)
                        return null;

                    // OBJECT_TYPE_INFORMATION içindeki UNICODE_STRING TypeName'i oku
                    short nameLen = Marshal.ReadInt16(buffer, 0);
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
                    NativeApi.NtClose(duplicated);
            }
        }

        /// <summary>
        /// Handle object name'ini belirler (dosya yolu, registry key vb.).
        /// </summary>
        private static bool GetHandleObjectName(IntPtr hProcess, SYSTEM_HANDLE_TABLE_ENTRY_INFO handleEntry, out string objectName)
        {
            objectName = null;

            try
            {
                IntPtr duplicatedHandle = IntPtr.Zero;

                if (!Kernel32Api.DuplicateHandle(
                    hProcess,
                    (IntPtr)handleEntry.HandleValue,
                    Kernel32Api.GetCurrentProcess(),
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

                    uint ntStatus = NativeApi.NtQueryObject(duplicatedHandle, ObjectNameInformation, IntPtr.Zero, 0, out returnLength);
                    if (returnLength == 0 || returnLength > 0x10000)
                        return false;

                    IntPtr buffer = Marshal.AllocHGlobal((int)returnLength);
                    try
                    {
                        ntStatus = NativeApi.NtQueryObject(duplicatedHandle, ObjectNameInformation, buffer, returnLength, out returnLength);
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
                        NativeApi.NtClose(duplicatedHandle);
                }

                return false;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[DEBUG] GetHandleObjectName exception: {ex.Message}");
                return false;
            }
        }
    }
}