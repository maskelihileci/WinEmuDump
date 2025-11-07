using System;
using System.Runtime.InteropServices;

namespace WinEmuDump
{
    /// <summary>
    /// Native API fonksiyonları - ntdll.dll'den gelen düşük seviye Windows API'leri
    /// </summary>
    internal class NativeApi
    {
        [DllImport("ntdll.dll")]
        public static extern uint NtOpenProcess(ref IntPtr ProcessHandle, uint DesiredAccess, ref Win32.OBJECT_ATTRIBUTES ObjectAttributes, ref Win32.CLIENT_ID processId);

        [DllImport("ntdll.dll")]
        public static extern uint NtReadVirtualMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("ntdll.dll")]
        public static extern uint NtQueryVirtualMemory(IntPtr hProcess, IntPtr lpAddress, uint MemoryInformationClass, out Win32.MEMORY_BASIC_INFORMATION MemoryInformation, uint MemoryInformationLength, out uint ReturnLength);

        [DllImport("ntdll.dll")]
        public static extern uint NtOpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, ref IntPtr TokenHandle);

        [DllImport("ntdll.dll")]
        public static extern uint NtAdjustPrivilegesToken(IntPtr TokenHandle, bool DisableAllPrivileges, ref Win32.TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

        [DllImport("ntdll.dll")]
        public static extern uint NtClose(IntPtr hObject);

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern uint RtlGetVersion(ref Win32.OSVERSIONINFOEX lpVersionInformation);

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern uint NtQueryInformationProcess(IntPtr processHandle, int processInformationClass, IntPtr pbi, uint processInformationLength, out uint returnLength);

        [DllImport("ntdll.dll")]
        public static extern uint NtQuerySystemInformation(uint SystemInformationClass, IntPtr SystemInformation, uint SystemInformationLength, out uint ReturnLength);

        [DllImport("ntdll.dll")]
        public static extern uint NtOpenThread(ref IntPtr ThreadHandle, uint DesiredAccess, ref Win32.OBJECT_ATTRIBUTES ObjectAttributes, ref Win32.CLIENT_ID ClientId);

        [DllImport("ntdll.dll")]
        public static extern uint NtGetContextThread(IntPtr ThreadHandle, ref Win32.CONTEXT Context);

        [DllImport("ntdll.dll")]
        public static extern uint NtQueryInformationThread(IntPtr ThreadHandle, uint ThreadInformationClass, IntPtr ThreadInformation, uint ThreadInformationLength, out uint ReturnLength);

        [DllImport("ntdll.dll")]
        public static extern uint NtQueryInformationThread(IntPtr ThreadHandle, uint ThreadInformationClass, ref IntPtr ThreadInformation, uint ThreadInformationLength, out uint ReturnLength);

        [DllImport("ntdll.dll")]
        public static extern uint NtQueryObject(IntPtr Handle, uint ObjectInformationClass, IntPtr ObjectInformation, uint ObjectInformationLength, out uint ReturnLength);

        [DllImport("ntdll.dll")]
        public static extern uint NtSuspendThread(IntPtr ThreadHandle, out uint PreviousSuspendCount);

        [DllImport("ntdll.dll")]
        public static extern uint NtResumeThread(IntPtr ThreadHandle, out uint PreviousSuspendCount);

        [DllImport("ntdll.dll")]
        public static extern uint NtSuspendProcess(IntPtr ProcessHandle);

        [DllImport("ntdll.dll")]
        public static extern uint NtResumeProcess(IntPtr ProcessHandle);
    }
}