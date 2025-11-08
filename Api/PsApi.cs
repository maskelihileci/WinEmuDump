using System;
using System.Runtime.InteropServices;
using System.Text;

namespace WinEmuDump
{
    /// <summary>
    /// PSAPI fonksiyonları - psapi.dll'den gelen process ve memory API'leri
    /// </summary>
    internal class PsApi
    {

        [DllImport("psapi.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool EnumProcessModules(IntPtr hProcess, IntPtr[] lphModule, uint cb, out uint lpcbNeeded);

        [DllImport("psapi.dll", SetLastError = true)]
        public static extern uint GetModuleBaseName(IntPtr hProcess, IntPtr hModule, StringBuilder lpBaseName, uint nSize);

        [DllImport("psapi.dll", SetLastError = true)]
        public static extern uint GetModuleFileNameEx(IntPtr hProcess, IntPtr hModule, StringBuilder lpFilename, uint nSize);
    }
}