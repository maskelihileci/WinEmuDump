using System;
using System.Runtime.InteropServices;

namespace WinEmuDump.Helpers
{
    /// <summary>
    /// Yapı (struct) işlemleri için yardımcı fonksiyonlar
    /// CreateFile.cs ve MinidumpBuilder.cs'den birleştirilmiş duplicate kodlar
    /// </summary>
    internal static class StructHelper
    {
        /// <summary>
        /// Yapıyı byte array'e çevirir
        /// CreateFile.cs ve MinidumpBuilder.cs'deki duplicate fonksiyonların birleştirilmiş versiyonu
        /// Exception safety ile güvenli hale getirilmiş - Güvenli Marshal versiyonu
        /// </summary>
        /// <typeparam name="T">Yapı tipi</typeparam>
        /// <param name="structInstance">Çevrilecek yapı örneği</param>
        /// <returns>Yapının byte array temsili</returns>
        public static byte[] StructToByteArray<T>(T structInstance) where T : struct
        {
            int structSize = Marshal.SizeOf(typeof(T));
            byte[] byteArray = new byte[structSize];
            IntPtr ptr = Marshal.AllocHGlobal(structSize);

            try
            {
                Marshal.StructureToPtr(structInstance, ptr, true);
                Marshal.Copy(ptr, byteArray, 0, structSize);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ERROR] StructToByteArray hatası - Type: {typeof(T).Name}, Size: {structSize}, Error: {ex.Message}");
                throw;
            }
            finally
            {
                Marshal.FreeHGlobal(ptr);
            }

            return byteArray;
        }

        /// <summary>
        /// Byte array'den yapıya çevirir
        /// MinidumpBuilder.cs'den alınmış - Güvenli Marshal versiyonu
        /// </summary>
        /// <typeparam name="T">Yapı tipi</typeparam>
        /// <param name="data">Byte array verisi</param>
        /// <returns>Yapı örneği</returns>
        public static T StructToStruct<T>(byte[] data) where T : struct
        {
            int structSize = Marshal.SizeOf(typeof(T));
            if (data.Length < structSize)
                throw new ArgumentException($"Data length {data.Length} is less than struct size {structSize}");

            IntPtr ptr = Marshal.AllocHGlobal(structSize);
            try
            {
                Marshal.Copy(data, 0, ptr, structSize);
                return Marshal.PtrToStructure<T>(ptr);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ERROR] StructToStruct hatası - Type: {typeof(T).Name}, Size: {structSize}, Error: {ex.Message}");
                throw;
            }
            finally
            {
                Marshal.FreeHGlobal(ptr);
            }
        }
    }
}