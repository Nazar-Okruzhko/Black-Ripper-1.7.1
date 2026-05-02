// =============================================================================
//  injhelper.cs  –  C# .NET Cross-arch APC injection helper
//
//  Requirments:
//    intruder.dll is pre-compiled and placed alongside this launcher.
//    d3dwrap.dll is pre-compiled and placed alongside this launcher.
//    injhelper.exe is pre-compiled and placed alongside this launcher.
//
//  Exit codes:
//    0  = success
//    1  = bad arguments
//    2  = VirtualAllocEx failed
//    3  = WriteProcessMemory failed
//    4  = QueueUserAPC failed
//    5  = OpenProcess failed
//
//  Build x64 (.NET 4-8):
//    dotnet build injhelper.csproj -c Release -p:PlatformTarget=x64
//    dotnet build BlackRipper_171.csproj -c Release -p:PlatformTarget=x64
//
//  Build x86 (.NET 4-8):
//    dotnet build injhelper.csproj -c Release -p:PlatformTarget=x86
//    dotnet build BlackRipper_171.csproj -c Release -p:PlatformTarget=x86
//
//  The helper: 
//    1. Gets called by the Launcher (BlackExploit_171.exe) for cross-arch targets:
//    -  injhelper.exe <pid> <tid> <dllpath>
//    Consists of 1 class: InjHelper.
//
// =============================================================================
 
using System;
using System.Runtime.InteropServices;
using System.Text;
 
// ===========================================================================
// P/Invoke
// ===========================================================================
static class InjHelper
{
    const uint PROCESS_ALL_ACCESS = 0x001FFFFF;
    const uint MEM_COMMIT         = 0x1000;
    const uint MEM_RESERVE        = 0x2000;
    const uint MEM_RELEASE        = 0x8000;
    const uint PAGE_READWRITE     = 0x04;
 
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
 
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenThread(uint access, bool inherit, uint tid);
 
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAllocEx(
        IntPtr hProc, IntPtr addr, uint size, uint type, uint protect);
 
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool WriteProcessMemory(
        IntPtr hProc, IntPtr addr, byte[] buf, uint size, out uint written);
 
    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    static extern IntPtr GetProcAddress(IntPtr hMod, string name);
 
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr GetModuleHandle(string name);
 
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, UIntPtr data);
 
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool VirtualFreeEx(IntPtr hProc, IntPtr addr, uint size, uint type);
 
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr h);
 
    // THREAD_SET_CONTEXT = 0x0010
    const uint THREAD_SET_CONTEXT = 0x0010;
 
    // 1. Entry point -----------------------------------------------------------
    static int Main(string[] args)
    {
        if (args.Length < 3)
        {
            Console.Error.WriteLine("Usage: injhelper.exe <pid> <tid> <dllpath>");
            return 1;
        }
 
        if (!uint.TryParse(args[0], out uint pid) ||
            !uint.TryParse(args[1], out uint tid))
        {
            Console.Error.WriteLine("Invalid pid/tid");
            return 1;
        }
 
        string dllPath = args[2].Trim('"');
 
        // 2. Open target process & thread -------------------------------------
        IntPtr hProc = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
        if (hProc == IntPtr.Zero)
        {
            Console.Error.WriteLine(
                $"OpenProcess failed (0x{Marshal.GetLastWin32Error():X8})");
            return 5;
        }
 
        IntPtr hThread = OpenThread(THREAD_SET_CONTEXT, false, tid);
        if (hThread == IntPtr.Zero)
        {
            Console.Error.WriteLine(
                $"OpenThread failed (0x{Marshal.GetLastWin32Error():X8})");
            CloseHandle(hProc);
            return 5;
        }
 
        int result = InjectApc(hProc, hThread, dllPath);
 
        CloseHandle(hThread);
        CloseHandle(hProc);
        return result;
    }
 
    // 3. APC injection (same logic as KInject.InjectApc in the main launcher) --
    static int InjectApc(IntPtr hProc, IntPtr hThread, string dllPath)
    {
        byte[] pathBytes = Encoding.Unicode.GetBytes(dllPath + "\0");
        uint   size      = (uint)pathBytes.Length;
 
        IntPtr pMem = VirtualAllocEx(hProc, IntPtr.Zero, size,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (pMem == IntPtr.Zero)
        {
            Console.Error.WriteLine(
                $"VirtualAllocEx failed (0x{Marshal.GetLastWin32Error():X8})");
            return 2;
        }
 
        if (!WriteProcessMemory(hProc, pMem, pathBytes, size, out _))
        {
            Console.Error.WriteLine(
                $"WriteProcessMemory failed (0x{Marshal.GetLastWin32Error():X8})");
            VirtualFreeEx(hProc, pMem, 0, MEM_RELEASE);
            return 3;
        }
 
        IntPtr hK32  = GetModuleHandle("kernel32.dll");
        IntPtr pLoad = GetProcAddress(hK32, "LoadLibraryW");
 
        if (!QueueUserAPC(pLoad, hThread, (UIntPtr)(ulong)pMem))
        {
            Console.Error.WriteLine(
                $"QueueUserAPC failed (0x{Marshal.GetLastWin32Error():X8})");
            VirtualFreeEx(hProc, pMem, 0, MEM_RELEASE);
            return 4;
        }
 
        return 0;   // success – memory intentionally NOT freed (LoadLibraryW will read it)
    }
}
 
