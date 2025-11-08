using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

/// <summary>
/// PROCESS_BASIC_INFORMATION yapısı - Process bilgileri için
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct PROCESS_BASIC_INFORMATION
{
    public IntPtr Reserved1;
    public IntPtr PebBaseAddress;
    public IntPtr Reserved2;
    public IntPtr Reserved3;
    public IntPtr UniqueProcessId;
    public IntPtr Reserved4;
}


namespace WinEmuDump.Helpers
{
    /// <summary>
    /// Process işlemleri için yardımcı fonksiyonlar
    /// ThreadCollector.cs'den birleştirilmiş duplicate kodlar
    /// </summary>
    internal static class ProcessHelper
    {
        /// <summary>
        /// Process handle'ından process ID'sini çıkarır
        /// ThreadCollector.cs'deki duplicate fonksiyonların birleştirilmiş versiyonu
        /// Exception safety ve fallback mekanizması ile güçlendirilmiş
        /// </summary>
        /// <param name="hProcess">Process handle'ı</param>
        /// <returns>Process ID</returns>
        public static int GetProcessIdFromHandle(IntPtr hProcess)
        {
            try
            {
                // Önce Kernel32Api.GetProcessId kullanmayı dene (en güvenilir yöntem)
                return (int)Kernel32Api.GetProcessId(hProcess);
            }
            catch
            {
                try
                {
                    // Fallback: NtQueryInformationProcess ile ProcessBasicInformation al
                    return GetProcessIdViaNtQuery(hProcess);
                }
                catch
                {
                    // Son çare: Mevcut process ID'sini döndür (eğer aynı process ise)
                    try
                    {
                        return Process.GetCurrentProcess().Id;
                    }
                    catch
                    {
                        // En son çare: 0 döndür
                        Console.WriteLine("[WARNING] GetProcessIdFromHandle: Tüm yöntemler başarısız, 0 döndürülüyor");
                        return 0;
                    }
                }
            }
        }

        /// <summary>
        /// NtQueryInformationProcess kullanarak ProcessBasicInformation'dan PID alır
        /// Fallback yöntem olarak kullanılır
        /// </summary>
        /// <param name="hProcess">Process handle'ı</param>
        /// <returns>Process ID</returns>
        private static int GetProcessIdViaNtQuery(IntPtr hProcess)
        {
            try
            {
                // PROCESS_BASIC_INFORMATION boyutunu tahmin et (64-bit vs 32-bit)
                int pbiSize = Environment.Is64BitProcess ? 48 : 24;

                IntPtr pbiPtr = Marshal.AllocHGlobal(pbiSize);
                try
                {
                    uint ntStatus = NativeApi.NtQueryInformationProcess(hProcess, 0, pbiPtr, (uint)pbiSize, out uint returnLength);

                    if (ntStatus == 0 && returnLength >= (uint)Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION)))
                    {
                        // PROCESS_BASIC_INFORMATION'dan UniqueProcessId'yi oku
                        // Offset 0: ExitStatus (4/8 bytes)
                        // Offset 4/8: PebBaseAddress (4/8 bytes) 
                        // Offset 8/16: AffinityMask (4/8 bytes)
                        // Offset 12/24: BasePriority (4/8 bytes)
                        // Offset 16/32: UniqueProcessId (4/8 bytes)
                        // Offset 20/40: InheritedFromUniqueProcessId (4/8 bytes)

                        int processIdOffset = Environment.Is64BitProcess ? 32 : 16;
                        return Environment.Is64BitProcess
                            ? Marshal.ReadInt32(pbiPtr, processIdOffset)
                            : Marshal.ReadInt32(pbiPtr, processIdOffset);
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(pbiPtr);
                }
            }
            catch
            {
                // NtQueryInformationProcess başarısız oldu
            }

            throw new InvalidOperationException("Process ID alınamadı");
        }

        /// <summary>
        /// Process handle'ının geçerli olup olmadığını kontrol eder
        /// </summary>
        /// <param name="hProcess">Process handle'ı</param>
        /// <returns>Geçerli ise true</returns>
        public static bool IsValidProcessHandle(IntPtr hProcess)
        {
            return hProcess != IntPtr.Zero && hProcess != new IntPtr(-1);
        }

        /// <summary>
        /// Process'in çalışıp çalışmadığını kontrol eder
        /// </summary>
        /// <param name="hProcess">Process handle'ı</param>
        /// <returns>Çalışıyorsa true</returns>
        public static bool IsProcessRunning(IntPtr hProcess)
        {
            try
            {
                if (!IsValidProcessHandle(hProcess))
                    return false;

                int processId = GetProcessIdFromHandle(hProcess);
                if (processId == 0)
                    return false;

                Process process = Process.GetProcessById(processId);
                return !process.HasExited;
            }
            catch
            {
                return false;
            }
        }
    }
}