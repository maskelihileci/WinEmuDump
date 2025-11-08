using System;
using System.Runtime.InteropServices;

namespace WinEmuDump
{
    /// <summary>
    /// Kernel32 API fonksiyonları - kernel32.dll'den gelen Windows API'leri
    /// </summary>
    internal class Kernel32Api
    {
        [DllImport("kernel32.dll")]
        public static extern bool IsWow64Process(IntPtr hProcess, out bool Wow64Process);

        [DllImport("kernel32.dll")]
        public static extern bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX lpBuffer);

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll")]
        public static extern void GetSystemInfo(out SYSTEM_INFO lpSystemInfo);

        [DllImport("kernel32.dll")]
        public static extern uint GetTimeZoneInformation(out Win32.TIME_ZONE_INFORMATION lpTimeZoneInformation);

        [DllImport("kernel32.dll")]
        public static extern uint GetProcessId(IntPtr Process);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint SetThreadDescription(IntPtr hThread, IntPtr lpThreadDescription);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint GetThreadDescription(IntPtr hThread, out IntPtr lpThreadDescription);

        [DllImport("kernel32.dll")]
        public static extern IntPtr LoadLibrary(string dllName);

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procedureName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool DuplicateHandle(
            IntPtr hSourceProcessHandle,
            IntPtr hSourceHandle,
            IntPtr hTargetProcessHandle,
            out IntPtr lpTargetHandle,
            uint dwDesiredAccess,
            bool bInheritHandle,
            uint dwOptions);
    }
}