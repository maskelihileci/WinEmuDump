using System;
using System.Runtime.InteropServices;

namespace WinEmuDump.Helpers
{
    /// <summary>
    /// String işleme fonksiyonları
    /// Program.cs ve HandleCollector.cs'den birleştirilmiş string operasyonları
    /// </summary>
    internal static class StringHelper
    {
        /// <summary>
        /// Remote process'ten null-terminated Unicode string okur
        /// Program.cs'den alınmış (ReadRemoteWStr)
        /// </summary>
        /// <param name="hProcess">Hedef process handle'ı</param>
        /// <param name="memAddress">String'in bulunduğu bellek adresi</param>
        /// <returns>Okunan Unicode string</returns>
        public static string ReadRemoteUnicodeString(IntPtr hProcess, IntPtr memAddress)
        {
            try
            {
                byte[] buffer = new byte[256]; // 256 karakter limit
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

        /// <summary>
        /// Remote process'ten null-terminated ASCII string okur
        /// </summary>
        /// <param name="hProcess">Hedef process handle'ı</param>
        /// <param name="memAddress">String'in bulunduğu bellek adresi</param>
        /// <param name="maxLength">Maksimum karakter sayısı (default: 256)</param>
        /// <returns>Okunan ASCII string</returns>
        public static string ReadRemoteAsciiString(IntPtr hProcess, IntPtr memAddress, int maxLength = 256)
        {
            try
            {
                byte[] buffer = new byte[maxLength];
                uint ntStatus = NativeApi.NtReadVirtualMemory(hProcess, memAddress, buffer, buffer.Length, out _);
                
                if (ntStatus != 0)
                {
                    Console.WriteLine($"[-] ReadRemoteAsciiString error. NTSTATUS: 0x{ntStatus:X}");
                    return string.Empty;
                }
                
                // Null-terminated ASCII string'i parse et
                int nullIndex = Array.IndexOf(buffer, (byte)0);
                if (nullIndex >= 0)
                {
                    return System.Text.Encoding.ASCII.GetString(buffer, 0, nullIndex);
                }
                else
                {
                    return System.Text.Encoding.ASCII.GetString(buffer).TrimEnd('\0');
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[WARNING] ReadRemoteAsciiString error: {ex.Message}");
                return string.Empty;
            }
        }

        /// <summary>
        /// UNICODE_STRING yapısından string değerini alır
        /// HandleCollector.cs'den alınmış (QueryTypeFromHandle'daki kısım)
        /// </summary>
        /// <param name="unicodeStringPtr">UNICODE_STRING yapısının pointer'ı</param>
        /// <returns>Parse edilen string</returns>
        public static string ParseUnicodeString(IntPtr unicodeStringPtr)
        {
            try
            {
                // UNICODE_STRING: USHORT Length; USHORT MaximumLength; PVOID Buffer;
                short nameLen = Marshal.ReadInt16(unicodeStringPtr, 0);
                IntPtr nameBuffer = Marshal.ReadIntPtr(unicodeStringPtr, IntPtr.Size == 8 ? 8 : 4);

                if (nameBuffer == IntPtr.Zero || nameLen <= 0)
                    return string.Empty;

                byte[] nameBytes = new byte[nameLen];
                Marshal.Copy(nameBuffer, nameBytes, 0, nameLen);
                return System.Text.Encoding.Unicode.GetString(nameBytes).TrimEnd('\0');
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[WARNING] ParseUnicodeString error: {ex.Message}");
                return string.Empty;
            }
        }

        /// <summary>
        /// Byte array'den null-terminated string'i güvenli şekilde alır
        /// </summary>
        /// <param name="bytes">Byte array</param>
        /// <param name="encoding">Encoding (default: ASCII)</param>
        /// <returns>Parse edilen string</returns>
        public static string SafeGetString(byte[] bytes, System.Text.Encoding encoding = null)
        {
            if (bytes == null || bytes.Length == 0)
                return string.Empty;

            encoding = encoding ?? System.Text.Encoding.ASCII;

            try
            {
                int nullIndex = Array.IndexOf(bytes, (byte)0);
                if (nullIndex >= 0)
                {
                    return encoding.GetString(bytes, 0, nullIndex);
                }
                else
                {
                    return encoding.GetString(bytes).TrimEnd('\0');
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[WARNING] SafeGetString error: {ex.Message}");
                return string.Empty;
            }
        }

        /// <summary>
        /// String'i byte array'e null terminator ile çevirir
        /// </summary>
        /// <param name="str">Çevrilecek string</param>
        /// <param name="encoding">Encoding (default: ASCII)</param>
        /// <returns>Null-terminated byte array</returns>
        public static byte[] StringToNullTerminatedBytes(string str, System.Text.Encoding encoding = null)
        {
            if (string.IsNullOrEmpty(str))
                return new byte[] { 0 };

            encoding = encoding ?? System.Text.Encoding.ASCII;
            
            byte[] stringBytes = encoding.GetBytes(str);
            byte[] result = new byte[stringBytes.Length + 1];
            Array.Copy(stringBytes, result, stringBytes.Length);
            result[stringBytes.Length] = 0; // Null terminator
            
            return result;
        }
    }
}