using System;

namespace WinEmuDump.Helpers
{
    /// <summary>
    /// Remote memory okuma işlemleri için yardımcı fonksiyonlar
    /// Program.cs ve PeCollector.cs'den birleştirilmiş duplicate kodlar
    /// </summary>
    internal static class MemoryHelper
    {
        /// <summary>
        /// Remote process'ten IntPtr değeri okur
        /// Program.cs'den alınmış, optimize edilmiş versiyon
        /// </summary>
        /// <param name="hProcess">Hedef process handle'ı</param>
        /// <param name="memAddress">Okunacak bellek adresi</param>
        /// <returns>Okunan IntPtr değeri</returns>
        public static IntPtr ReadRemoteIntPtr(IntPtr hProcess, IntPtr memAddress)
        {
            byte[] buffer = new byte[IntPtr.Size]; // 4 bytes for 32-bit, 8 bytes for 64-bit
            uint ntStatus = NativeApi.NtReadVirtualMemory(hProcess, memAddress, buffer, buffer.Length, out _);
            
            if (ntStatus != 0)
            {
                Console.WriteLine($"[-] ReadRemoteIntPtr error. NTSTATUS: 0x{ntStatus:X}");
                return IntPtr.Zero;
            }
            
            return IntPtr.Size == 4 
                ? (IntPtr)BitConverter.ToInt32(buffer, 0)
                : (IntPtr)BitConverter.ToInt64(buffer, 0);
        }

        /// <summary>
        /// Remote process'ten güvenli memory okuma
        /// PeCollector.cs'den alınmış, try-catch ile güçlendirilmiş versiyon
        /// </summary>
        /// <param name="hProcess">Hedef process handle'ı</param>
        /// <param name="baseAddress">Okunacak bellek adresi</param>
        /// <param name="buffer">Veri alınacak buffer</param>
        /// <param name="size">Okunacak boyut</param>
        /// <returns>NTSTATUS değeri (0 = başarılı)</returns>
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
        /// Remote process'ten Unicode string okur (null-terminated)
        /// Program.cs'den alınmış, optimize edilmiş versiyon
        /// </summary>
        /// <param name="hProcess">Hedef process handle'ı</param>
        /// <param name="memAddress">String'in bulunduğu bellek adresi</param>
        /// <param name="maxLength">Maksimum okunacak karakter sayısı (default: 256)</param>
        /// <returns>Okunan Unicode string</returns>
        public static string ReadRemoteUnicodeString(IntPtr hProcess, IntPtr memAddress, int maxLength = 256)
        {
            try
            {
                byte[] buffer = new byte[maxLength * 2]; // Unicode = 2 bytes per char
                uint ntStatus = NativeApi.NtReadVirtualMemory(hProcess, memAddress, buffer, buffer.Length, out _);
                
                if (ntStatus != 0)
                {
                    Console.WriteLine($"[-] ReadRemoteUnicodeString error. NTSTATUS: 0x{ntStatus:X}");
                    return string.Empty;
                }
                
                // Null-terminated Unicode string'i parse et
                string unicodeString = "";
                for (int i = 0; i < buffer.Length - 1; i += 2)
                {
                    if (buffer[i] == 0 && buffer[i + 1] == 0) 
                        break;
                    unicodeString += BitConverter.ToChar(buffer, i);
                }
                
                return unicodeString;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[WARNING] ReadRemoteUnicodeString error: {ex.Message}");
                return string.Empty;
            }
        }
    }
}