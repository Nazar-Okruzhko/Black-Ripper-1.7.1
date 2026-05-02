// =============================================================================
//  NinjaRipper 1.7.1  -  C# .NET Single-File Launcher
//
//  Requirments:
//    intruder.dll is pre-compiled and placed alongside this launcher.
//    d3dwrap.dll is pre-compiled and placed alongside this launcher.
//    injhelper.exe is pre-compiled and placed alongside this launcher.
//
//  Build x64 (.NET 4-8):
//    dotnet build injhelper.csproj -c Release -p:PlatformTarget=x64
//    dotnet build BlackRipper_171.csproj -c Release -p:PlatformTarget=x64
//
//  Build x86 (.NET 4-8):
//    dotnet build injhelper.csproj -c Release -p:PlatformTarget=x86
//    dotnet build BlackRipper_171.csproj -c Release -p:PlatformTarget=x86
//
//  The launcher:
//    1. Shows a Win32-Forms GUI (the original dialog)
//    2. Saves/Loads settings in the same registry key as the C++ version
//    3. Injects intruder.dll via APC Injection (QueueUserAPC), same mechanism as KInject
//    4. The code tries intruder.dll first, then intruder32/64.dll as fallback.
//    5. Falls back to injhelper.exe for cross-arch targets
//    Consists of 8 classes: Dlu, NativeApi, NRSettings, KInject, SettingsForm, AboutForm, MainForm, Program.
// =============================================================================
 
using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows.Forms;
using Microsoft.Win32;
 
// ===========================================================================
//  DLU - a small pixel helper  (8 pt "MS Shell Dlg" at 96 DPI)
// ===========================================================================
static class Dlu
{
    public static int   X(int d) => d * 6 / 4;
    public static int   Y(int d) => d * 13 / 8;
    public static Point P(int x, int y) => new Point(X(x), Y(y));
    public static Size  S(int w, int h) => new Size(X(w), Y(h));
}
 
// ===========================================================================
//  P/Invoke
// ===========================================================================
static class NativeApi
{
    public const uint CREATE_SUSPENDED   = 0x00000004;
    public const uint PROCESS_ALL_ACCESS = 0x001FFFFF;
    public const uint MEM_COMMIT         = 0x1000;
    public const uint MEM_RESERVE        = 0x2000;
    public const uint MEM_RELEASE        = 0x8000;
    public const uint PAGE_READWRITE     = 0x04;
    public const uint SCS_32BIT_BINARY   = 0;
    public const uint SCS_64BIT_BINARY   = 6;
 
    [StructLayout(LayoutKind.Sequential)]
    public struct STARTUPINFO
    {
        public int    cb;
        public string lpReserved, lpDesktop, lpTitle;
        public int    dwX, dwY, dwXSize, dwYSize;
        public int    dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public short  wShowWindow, cbReserved2;
        public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }
 
    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess, hThread;
        public uint   dwProcessId, dwThreadId;
    }
 
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern bool CreateProcess(
        string lpApp, string lpCmd, IntPtr pPA, IntPtr pTA, bool bInherit,
        uint dwFlags, IntPtr lpEnv, string lpDir,
        ref STARTUPINFO lpSI, out PROCESS_INFORMATION lpPI);
 
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr VirtualAllocEx(IntPtr h,IntPtr a,uint s,uint t,uint p);
 
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool WriteProcessMemory(IntPtr h,IntPtr a,byte[] b,uint s,out uint w);
 
    [DllImport("kernel32.dll", CharSet=CharSet.Ansi, SetLastError=true)]
    public static extern IntPtr GetProcAddress(IntPtr hMod, string name);
 
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern IntPtr GetModuleHandle(string name);
 
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool QueueUserAPC(IntPtr pfn, IntPtr hThread, UIntPtr data);
 
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern uint ResumeThread(IntPtr h);
 
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr h);
 
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool VirtualFreeEx(IntPtr h,IntPtr a,uint s,uint t);
 
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern bool GetBinaryType(string app, out uint type);
 
    // Used by the process watcher to detect silent crashes
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern uint WaitForSingleObject(IntPtr hObject, uint dwMilliseconds);
 
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);
 
    public const uint WAIT_OBJECT_0  = 0x00000000;
    public const uint STILL_ACTIVE   = 0x00000103;
    public const uint INFINITE        = 0xFFFFFFFF;
}
 
 
// ===========================================================================
//  Logger  --  writes a timestamped log to BlackRipper.log next to the EXE
//  Open it in Notepad after a failed launch to see exactly where it died.
// ===========================================================================
static class Logger
{
    static readonly string _path =
        System.IO.Path.Combine(
            AppDomain.CurrentDomain.BaseDirectory,
            "BlackRipper.log");
    static readonly object _lock = new object();
 
    public static void Init()
    {
        // Truncate old log on each launcher start
        try { System.IO.File.WriteAllText(_path, ""); } catch {}
        Log($"=== BlackRipper 1.7.1  PID={System.Diagnostics.Process.GetCurrentProcess().Id}" +
            $"  arch={( Environment.Is64BitProcess ? "x64" : "x86" )} ===");
        Log($"BaseDir : {AppDomain.CurrentDomain.BaseDirectory}");
    }
 
    public static void Log(string msg)
    {
        lock (_lock)
        {
            try
            {
                System.IO.File.AppendAllText(
                    _path,
                    $"[{DateTime.Now:HH:mm:ss.fff}] {msg}\r\n");
            }
            catch { /* never let logging crash the launcher */ }
        }
    }
 
    public static void LogErr(string msg) => Log("[ERR] " + msg);
 
    /// <summary>Shows the log in Notepad so the user can see it immediately.</summary>
    public static void OpenLog()
    {
        try
        {
            System.Diagnostics.Process.Start(
                new System.Diagnostics.ProcessStartInfo("notepad.exe", _path)
                { UseShellExecute = true });
        }
        catch { }
    }
}
 
 
// ===========================================================================
//  NRSettings ? mirrors KSettings / registry exactly
// ===========================================================================
class NRSettings
{
    const string REG = @"SOFTWARE\black_ninja\NinjaRipper";
 
    public string PrevEXE="", PrevArg="", PrevDir="", OutDir="";
    public string IntruderDir="";   // replaces IntruderDir32/64 for flat layout
 
    public uint RipKey=121, TextureRipKey=120, ForcedRipKey=123, SpecKeys=0;
    public uint DontOverwriteOutDir=1, DonateShowVersion=0;
    public uint SaveShaders=0, SaveDDrawSurfaces=0, DebugD3D=0;
    public uint Downscale=2, DownscaleWidth=4096, DownscaleHeight=4096;
    public uint MinPresentInterval=10000, usForcedRipInterval=10000000;
 
    static bool Is64() => Environment.Is64BitProcess;
 
    public void Load()
    {
        using var k = Registry.CurrentUser.OpenSubKey(REG);
        if (k == null) { SetDefaultOutDir(); SetDefaultIntruderDir(); return; }
 
        string exeKey = Is64() ? "PrevEXE64" : "PrevEXE";
        string argKey = Is64() ? "PrevArg64" : "PrevArg";
        string dirKey = Is64() ? "PrevDir64" : "PrevDir";
 
        PrevEXE = Str(k, exeKey); PrevArg = Str(k, argKey); PrevDir = Str(k, dirKey);
        OutDir  = Str(k, "OutDir");
        if (string.IsNullOrEmpty(OutDir)) SetDefaultOutDir();
 
        // Read old IntruderDir32/64 from registry but ignore them ? we use root dir
        RipKey           = Dw(k,"RipKey",121);
        TextureRipKey    = Dw(k,"TextureRipKey",120);
        ForcedRipKey     = Dw(k,"ForcedRipKey",123);
        SpecKeys         = Dw(k,"SpecKeys",0);
        DontOverwriteOutDir = Dw(k,"DontOverwriteOutDir",1);
        DonateShowVersion   = Dw(k,"DonateShowVersion",0);
        SaveShaders         = Dw(k,"SaveShaders",0);
        SaveDDrawSurfaces   = Dw(k,"SaveDDrawSurfaces",0);
        DebugD3D            = Dw(k,"DebugD3D",0);
        Downscale           = Dw(k,"Downscale",2);
        DownscaleWidth      = Dw(k,"DownscaleWidth",4096);
        DownscaleHeight     = Dw(k,"DownscaleHeight",4096);
        MinPresentInterval  = Dw(k,"MinPresentInterval",10000);
        usForcedRipInterval = Dw(k,"usForcedRipInterval",10000000);
 
        SetDefaultIntruderDir();
    }
 
    public void Save()
    {
        using var k = Registry.CurrentUser.CreateSubKey(REG);
        string exeKey = Is64() ? "PrevEXE64" : "PrevEXE";
        string argKey = Is64() ? "PrevArg64" : "PrevArg";
        string dirKey = Is64() ? "PrevDir64" : "PrevDir";
        k.SetValue(exeKey, PrevEXE); k.SetValue(argKey, PrevArg); k.SetValue(dirKey, PrevDir);
        k.SetValue("OutDir", OutDir);
        // Write IntruderDir32/64 as the root dir so C++ version still works
        k.SetValue("IntruderDir32", IntruderDir);
        k.SetValue("IntruderDir64", IntruderDir);
        k.SetValue("RipKey",          (int)RipKey,          RegistryValueKind.DWord);
        k.SetValue("TextureRipKey",   (int)TextureRipKey,   RegistryValueKind.DWord);
        k.SetValue("ForcedRipKey",    (int)ForcedRipKey,    RegistryValueKind.DWord);
        k.SetValue("SpecKeys",        (int)SpecKeys,        RegistryValueKind.DWord);
        k.SetValue("DontOverwriteOutDir",(int)DontOverwriteOutDir,RegistryValueKind.DWord);
        k.SetValue("DonateShowVersion",  (int)DonateShowVersion,  RegistryValueKind.DWord);
        k.SetValue("SaveShaders",     (int)SaveShaders,     RegistryValueKind.DWord);
        k.SetValue("SaveDDrawSurfaces",(int)SaveDDrawSurfaces,RegistryValueKind.DWord);
        k.SetValue("DebugD3D",        (int)DebugD3D,        RegistryValueKind.DWord);
        k.SetValue("Downscale",       (int)Downscale,       RegistryValueKind.DWord);
        k.SetValue("DownscaleWidth",  (int)DownscaleWidth,  RegistryValueKind.DWord);
        k.SetValue("DownscaleHeight", (int)DownscaleHeight, RegistryValueKind.DWord);
        k.SetValue("MinPresentInterval",(int)MinPresentInterval,RegistryValueKind.DWord);
        k.SetValue("usForcedRipInterval",(int)usForcedRipInterval,RegistryValueKind.DWord);
    }
 
    void SetDefaultIntruderDir() =>
        IntruderDir = AppDomain.CurrentDomain.BaseDirectory;
 
    void SetDefaultOutDir() =>
        OutDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            "NinjaRipper");
 
    static string Str(RegistryKey k, string n) => k?.GetValue(n) as string ?? "";
    static uint   Dw(RegistryKey k, string n, uint def)
    {
        var v = k?.GetValue(n);
        return v is int i ? (uint)i : def;
    }
}
 
// ===========================================================================
//  KInject ? flat-layout APC injection
// ===========================================================================
class KInject
{
    public enum Status
    {
        OK=0, ErrorCreateProcess, ErrorVirtualAlloc, ErrorWriteMemory,
        ErrorQueueAPC, ErrorBinaryFormat, ErrorHelperProcess,
        ErrorHelperFailed, ErrorHelperTimeout, ErrorDllNotFound,
    }
 
    readonly string _root;  // same dir as EXE
    public int Win32Error { get; private set; }
 
    public KInject(string rootDir) => _root = rootDir.TrimEnd('\\', '/') + "\\";
 
    // FIX 1: resolve intruder.dll from root dir only, no subfolder logic
    string ResolveDll(bool target64)
    {
        // Try exact: intruder.dll
        string plain = Path.Combine(_root, "intruder.dll");
        if (File.Exists(plain)) return plain;
 
        // Try arch-suffixed variants (for dual-arch setups without subfolders)
        string arch  = Path.Combine(_root, target64 ? "intruder64.dll" : "intruder32.dll");
        if (File.Exists(arch)) return arch;
 
        return plain; // return the expected path for the error message
    }
 
    string ResolveHelper()
    {
        string h = Path.Combine(_root, "injhelper.exe");
        return File.Exists(h) ? h : null;
    }
 
    public Status CreateAndInject(string exe, string args, string workDir)
    {
        Logger.Log($"CreateAndInject: exe='{exe}' args='{args}' workDir='{workDir}'");
 
        if (!NativeApi.GetBinaryType(exe, out uint tgtType))
        {
            Win32Error = Marshal.GetLastWin32Error();
            Logger.LogErr($"GetBinaryType failed (0x{Win32Error:X8})");
            return Status.ErrorBinaryFormat;
        }
 
        bool self64 = Environment.Is64BitProcess;
        bool tgt64  = tgtType == NativeApi.SCS_64BIT_BINARY;
        Logger.Log($"Launcher arch={( self64 ? "x64" : "x86" )}  " +
                   $"Target arch={( tgt64 ? "x64" : "x86" )}");
 
        string dll = ResolveDll(tgt64);
        Logger.Log($"intruder.dll resolved -> '{dll}'  exists={File.Exists(dll)}");
 
        if (!File.Exists(dll))
        {
            Logger.LogErr("intruder.dll not found -- aborting");
            MessageBox.Show(
                $"intruder.dll not found.\n\nExpected next to the launcher:\n  {dll}\n\n" +
                $"Place the {(tgt64?"x64":"x86")} build of intruder.dll in:\n  {_root}",
                "Ninja Ripper", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return Status.ErrorDllNotFound;
        }
 
        // FIX: if workDir is empty, default to the game's own directory so it
        //      can find its own DLLs and data files. A missing workDir is the
        //      most common reason the game silently crashes right after launch.
        if (string.IsNullOrWhiteSpace(workDir))
        {
            workDir = Path.GetDirectoryName(exe);
            Logger.Log($"workDir was empty -- defaulting to exe dir: '{workDir}'");
        }
 
        var si = new NativeApi.STARTUPINFO { cb = Marshal.SizeOf<NativeApi.STARTUPINFO>() };
        string cmd = $"\"{exe}\"";
        if (!string.IsNullOrEmpty(args)) cmd += " " + args;
        Logger.Log($"CreateProcess cmd='{cmd}'  workDir='{workDir}'");
 
        if (!NativeApi.CreateProcess(exe, cmd, IntPtr.Zero, IntPtr.Zero,
                false, NativeApi.CREATE_SUSPENDED, IntPtr.Zero,
                workDir, ref si, out var pi))
        {
            Win32Error = Marshal.GetLastWin32Error();
            Logger.LogErr($"CreateProcess FAILED (0x{Win32Error:X8})");
            return Status.ErrorCreateProcess;
        }
        Logger.Log($"CreateProcess OK  PID={pi.dwProcessId}  TID={pi.dwThreadId}");
 
        Status st = (self64 == tgt64)
            ? InjectApc(pi.hProcess, pi.hThread, dll)
            : HelperInject(pi.dwProcessId, pi.dwThreadId, dll);
 
        Logger.Log($"Injection status: {st}");
 
        NativeApi.ResumeThread(pi.hThread);
        Logger.Log("ResumeThread called -- game is running");
 
        // Hand the process handle off to a background watcher.
        // The watcher closes the handle when done.
        IntPtr hProcForWatch = pi.hProcess;
        System.Threading.ThreadPool.QueueUserWorkItem(_ =>
            WatchProcess(hProcForWatch, pi.dwProcessId, exe));
 
        NativeApi.CloseHandle(pi.hThread);
        // NOTE: hProcess is intentionally NOT closed here -- WatchProcess owns it.
        return st;
    }
 
    // Watches the child process for ~8 seconds after launch and alerts if it dies.
    static void WatchProcess(IntPtr hProcess, uint pid, string exeName)
    {
        try
        {
            // Give the game 8 s to settle (show its splash, load its DLLs, etc.)
            uint waitResult = NativeApi.WaitForSingleObject(hProcess, 8000);
 
            NativeApi.GetExitCodeProcess(hProcess, out uint exitCode);
            NativeApi.CloseHandle(hProcess);
 
            if (waitResult == NativeApi.WAIT_OBJECT_0)
            {
                // Process exited within 8 s -- almost certainly a crash
                string hint = exitCode switch {
                    0xC0000135 => "\n\nHint 0xC0000135: A DLL the game needs was not found.\n" +
                                  "Check that the working-directory (Dir field) points to the game folder.",
                    0xC0000005 => "\n\nHint 0xC0000005: Access Violation -- intruder.dll may have crashed\n" +
                                  "inside the game process. Check BlackRipper.log for details.",
                    0xC000007B => "\n\nHint 0xC000007B: Bad Image -- you are probably mixing 32-bit and\n" +
                                  "64-bit binaries. Make sure intruder.dll matches the game's bitness.",
                    _ => ""
                };
 
                string msg = $"Game process (PID {pid}) exited {exitCode} seconds after launch.\n" +
                             $"Exit code: 0x{exitCode:X8}{hint}\n\n" +
                             $"Full details written to BlackRipper.log";
 
                Logger.LogErr($"Game PID {pid} exited early -- code=0x{exitCode:X8}");
 
                // Show on the UI thread
                System.Windows.Forms.Form owner = null;
                foreach (System.Windows.Forms.Form f in System.Windows.Forms.Application.OpenForms)
                { owner = f; break; }
 
                if (owner != null && !owner.IsDisposed)
                    owner.Invoke((System.Windows.Forms.MethodInvoker)(() =>
                        System.Windows.Forms.MessageBox.Show(
                            owner, msg, "Game crashed / exited early",
                            System.Windows.Forms.MessageBoxButtons.OK,
                            System.Windows.Forms.MessageBoxIcon.Warning)));
                else
                    System.Windows.Forms.MessageBox.Show(
                        msg, "Game crashed / exited early",
                        System.Windows.Forms.MessageBoxButtons.OK,
                        System.Windows.Forms.MessageBoxIcon.Warning);
            }
            else
            {
                // Still running after 8 s -- good
                Logger.Log($"Game PID {pid} still running after 8 s -- injection looks healthy");
            }
        }
        catch (Exception ex)
        {
            Logger.LogErr($"WatchProcess exception: {ex.Message}");
            try { NativeApi.CloseHandle(hProcess); } catch { }
        }
    }
 
    public Status CreateProcess(string exe, string args, string workDir)
    {
        var si = new NativeApi.STARTUPINFO { cb = Marshal.SizeOf<NativeApi.STARTUPINFO>() };
        string cmd = $"\"{exe}\"";
        if (!string.IsNullOrEmpty(args)) cmd += " " + args;
        if (!NativeApi.CreateProcess(exe, cmd, IntPtr.Zero, IntPtr.Zero,
                false, 0, IntPtr.Zero,
                string.IsNullOrEmpty(workDir) ? null : workDir,
                ref si, out _))
        { Win32Error = Marshal.GetLastWin32Error(); return Status.ErrorCreateProcess; }
        return Status.OK;
    }
 
    Status InjectApc(IntPtr hProc, IntPtr hThread, string dllPath)
    {
        Logger.Log($"InjectApc: writing '{dllPath}' into remote process");
        byte[] bytes = Encoding.Unicode.GetBytes(dllPath + "\0");
        uint   size  = (uint)bytes.Length;
 
        IntPtr pMem = NativeApi.VirtualAllocEx(hProc, IntPtr.Zero, size,
            NativeApi.MEM_COMMIT | NativeApi.MEM_RESERVE, NativeApi.PAGE_READWRITE);
        if (pMem == IntPtr.Zero)
        {
            Win32Error = Marshal.GetLastWin32Error();
            Logger.LogErr($"VirtualAllocEx failed (0x{Win32Error:X8})");
            return Status.ErrorVirtualAlloc;
        }
        Logger.Log($"VirtualAllocEx OK -> 0x{pMem.ToInt64():X}");
 
        if (!NativeApi.WriteProcessMemory(hProc, pMem, bytes, size, out _))
        {
            Win32Error = Marshal.GetLastWin32Error();
            Logger.LogErr($"WriteProcessMemory failed (0x{Win32Error:X8})");
            NativeApi.VirtualFreeEx(hProc, pMem, 0, NativeApi.MEM_RELEASE);
            return Status.ErrorWriteMemory;
        }
        Logger.Log("WriteProcessMemory OK");
 
        IntPtr hK32  = NativeApi.GetModuleHandle("kernel32.dll");
        IntPtr pLoad = NativeApi.GetProcAddress(hK32, "LoadLibraryW");
        Logger.Log($"LoadLibraryW addr = 0x{pLoad.ToInt64():X}");
 
        if (!NativeApi.QueueUserAPC(pLoad, hThread, (UIntPtr)(ulong)pMem))
        {
            Win32Error = Marshal.GetLastWin32Error();
            Logger.LogErr($"QueueUserAPC failed (0x{Win32Error:X8})");
            NativeApi.VirtualFreeEx(hProc, pMem, 0, NativeApi.MEM_RELEASE);
            return Status.ErrorQueueAPC;
        }
        Logger.Log("QueueUserAPC OK -- DLL will load when main thread enters alertable wait");
        return Status.OK;
    }
 
    // Cross-arch: call injhelper.exe (also next to the EXE)
    Status HelperInject(uint pid, uint tid, string dllPath)
    {
        string helper = ResolveHelper();
        if (helper == null) return Status.ErrorHelperProcess;
 
        var psi = new ProcessStartInfo(helper, $"{pid} {tid} \"{dllPath}\"")
        { UseShellExecute=false, CreateNoWindow=true };
        var proc = Process.Start(psi);
        if (proc == null) return Status.ErrorHelperProcess;
        if (!proc.WaitForExit(10000)) return Status.ErrorHelperTimeout;
        return proc.ExitCode == 0 ? Status.OK : Status.ErrorHelperFailed;
    }
 
    public static string StatusString(Status s, int w=0) => s switch
    {
        Status.OK                  => "OK",
        Status.ErrorCreateProcess  => $"CreateProcess failed (0x{w:X8})",
        Status.ErrorVirtualAlloc   => $"VirtualAllocEx failed (0x{w:X8})",
        Status.ErrorWriteMemory    => $"WriteProcessMemory failed (0x{w:X8})",
        Status.ErrorQueueAPC       => $"QueueUserAPC failed (0x{w:X8})",
        Status.ErrorBinaryFormat   => "Not a valid Win32/64 EXE",
        Status.ErrorHelperProcess  => "injhelper.exe not found next to launcher",
        Status.ErrorHelperFailed   => "injhelper.exe reported failure",
        Status.ErrorHelperTimeout  => "injhelper.exe timed out",
        Status.ErrorDllNotFound    => "intruder.dll not found (see details above)",
        _                          => "Unknown error"
    };
 
    static readonly string[] WrapperDlls = {"d3d9.dll","d3d8.dll","d3d11.dll","ddraw.dll"};
    public static string FindWrapperInDir(string dir)
    {
        foreach (var dll in WrapperDlls)
            if (File.Exists(Path.Combine(dir, dll))) return dll;
        return null;
    }
}
 
enum WrapMode { Intruder=0, D3D11, D3D9, D3D8, DDraw }
 
// ===========================================================================
//  Settings Dialog
// ===========================================================================
class SettingsForm : Form
{
    NRSettings   _s;
    ComboBox     _ripKey, _texKey, _forcedKey;
    CheckBox     _saveShaders, _saveDdraw, _ctrl, _shift, _alt;
    NumericUpDown _interval;
    ToolTip      _tip = new ToolTip{ShowAlways=true};
 
    public SettingsForm(NRSettings s)
    {
        _s = s;
        Text="Settings"; FormBorderStyle=FormBorderStyle.FixedDialog;
        ClientSize=new Size(Dlu.X(283), Dlu.Y(144));
        StartPosition=FormStartPosition.CenterParent;
        ShowInTaskbar = false;
        MaximizeBox=MinimizeBox=false;
        try { Icon=Icon.ExtractAssociatedIcon(Application.ExecutablePath); } catch{}
 
        var grp = new GroupBox { Text="Rip keys select",
            Location=Dlu.P(7,7), Size=Dlu.S(269,66) };
 
        _ripKey    = KeyCb(28,23,33); SelectKey(_ripKey,    s.RipKey);
        _texKey    = KeyCb(107,23,33);SelectKey(_texKey,    s.TextureRipKey);
        _forcedKey = KeyCb(181,23,33);SelectKey(_forcedKey, s.ForcedRipKey);
 
        _tip.SetToolTip(_ripKey,    "Meshes + textures rip key");
        _tip.SetToolTip(_texKey,    "Textures + (and DDRAW surfaces) rip key");
        _tip.SetToolTip(_forcedKey, "Forced rip key");
 
        //_tip.SetToolTip(_saveShaders, "Save shaders disassembly");
        //_tip.SetToolTip(_saveDdraw,   "Save DirectDraw surfaces (Sprites in DirectX1 - DirectX7 2D games)");
//
        _ctrl  = Chk("+Ctrl", 23,52,37); _ctrl.Checked  =(s.SpecKeys&1)!=0;
        _shift = Chk("+Shift",66,52,38); _shift.Checked =(s.SpecKeys&2)!=0;
        _alt   = Chk("+Alt", 111,52,37); _alt.Checked   =(s.SpecKeys&4)!=0;
 
        _saveShaders = Chk("Save shaders (for experts)", 23,80,101);
        _saveDdraw   = Chk("Save DirectDraw surfaces (DX1-DX7)", 23,98,164);
        _saveShaders.Checked=s.SaveShaders!=0;
        _saveDdraw.Checked  =s.SaveDDrawSurfaces!=0;
 
        _interval = new NumericUpDown { Location=Dlu.P(219,78), Size=Dlu.S(24,12),
            Minimum=1,Maximum=300, TextAlign=HorizontalAlignment.Center,
            Value=Math.Max(1,Math.Min(300,s.usForcedRipInterval/1000000)) };
 
        var ok     = new Button{Text="OK",    DialogResult=DialogResult.OK,
            Location=Dlu.P(141,120),Size=Dlu.S(62,17)};
        var cancel = new Button{Text="Cancel",DialogResult=DialogResult.Cancel,
            Location=Dlu.P(214,120),Size=Dlu.S(62,17)};
        ok.Click+=(_,__)=>Apply();
 
        Controls.AddRange(new Control[]{
            Lbl("All",11,25,13,8), Lbl("Textures",65,25,36,8), Lbl("Forced",144,25,35,8),
            _ripKey,_texKey,_forcedKey,
            _ctrl,_shift,_alt,
            _saveShaders,_saveDdraw,
            Lbl("Forced rip interval:",147,80,69,8),
            _interval,
            new Label{Text="sec",AutoSize=false,Location=Dlu.P(249,80),Size=Dlu.S(20,8)},
            ok,cancel,
            grp  // GroupBox at the END ? lowest z-order ? at the back, never covers inner controls
        });
        grp.SendToBack();  // extra safety: push grp behind all siblings
        AcceptButton=ok; CancelButton=cancel;
    }
 
    void Apply()
    {
        _s.RipKey=KeyFromCb(_ripKey); _s.TextureRipKey=KeyFromCb(_texKey);
        _s.ForcedRipKey=KeyFromCb(_forcedKey);
        _s.SpecKeys=(uint)((_ctrl.Checked?1:0)|(_shift.Checked?2:0)|(_alt.Checked?4:0));
        _s.SaveShaders=(uint)(_saveShaders.Checked?1:0);
        _s.SaveDDrawSurfaces=(uint)(_saveDdraw.Checked?1:0);
        _s.usForcedRipInterval=(uint)_interval.Value*1000000;
        _s.Save();
    }
 
    static ComboBox KeyCb(int x,int y,int w){
        var cb=new ComboBox{DropDownStyle=ComboBoxStyle.DropDownList,
            Location=Dlu.P(x,y),Width=Dlu.X(w)};
        for(int i=1;i<=12;i++) cb.Items.Add($"F{i}");
        for(int i=0;i<=9; i++) cb.Items.Add($"{i}");
        for(char c='A';c<='Z';c++) cb.Items.Add($"{c}");
        return cb;
    }
    static void SelectKey(ComboBox cb,uint vk){
        int i=vk>=0x70&&vk<=0x7B?(int)(vk-0x70):vk>=0x30&&vk<=0x39?12+(int)(vk-0x30):vk>=0x41&&vk<=0x5A?22+(int)(vk-0x41):0;
        cb.SelectedIndex=i;
    }
    static uint KeyFromCb(ComboBox cb){
        int i=cb.SelectedIndex;
        return i<=11?(uint)(0x70+i):i<=21?(uint)(0x30+(i-12)):(uint)(0x41+(i-22));
    }
    static CheckBox Chk(string t,int x,int y,int w)=>
        new CheckBox{Text=t,AutoSize=false,Location=Dlu.P(x,y),Size=Dlu.S(w,10)};
    static Label Lbl(string t,int x,int y,int w,int h)=>
        new Label{Text=t,AutoSize=false,TextAlign=ContentAlignment.MiddleRight,
            Location=Dlu.P(x,y),Size=Dlu.S(w,h)};
}
 
// ===========================================================================
//  About Dialog
// ===========================================================================
class AboutForm : Form
{
    public AboutForm()
    {
        Text="About / Donate"; FormBorderStyle=FormBorderStyle.FixedDialog;
        ClientSize=new Size(Dlu.X(222),Dlu.Y(154));
        StartPosition=FormStartPosition.CenterParent;
        ShowInTaskbar = false;
        MaximizeBox=MinimizeBox=false;
        try{Icon=Icon.ExtractAssociatedIcon(Application.ExecutablePath);}catch{}
 
        var lblVer=new Label{
            Text="Black Ripper 1.7.1",
            Font=new Font("Arial",10,FontStyle.Bold),
            AutoSize=false,TextAlign=ContentAlignment.MiddleCenter,
            BackColor=Color.Transparent,
            Location=new Point(0, Dlu.Y(19)),
            Size=new Size(ClientSize.Width, Dlu.Y(10))
        };
 
        var grpOuter=new GroupBox{Text="",Location=Dlu.P(7,6),Size=Dlu.S(208,115)};
 
        var lblAuthor=new Label{
            Text="� black_ninja, 2017",
            AutoSize=false,TextAlign=ContentAlignment.MiddleLeft,
            Location=Dlu.P(77,41),Size=Dlu.S(80,8)
        };
 
        // FIX 6: real clickable hyperlink (IDC_HOMEPAGE=1018, SS_CENTER, 60,55)
        var font0=new Font("MS Shell Dlg",8f,FontStyle.Regular);
        var fontU=new Font("MS Shell Dlg",8f,FontStyle.Underline);
        var lblHome=new Label{
            Text="Home: cgig.ru/ninjaripper",
            AutoSize=false,TextAlign=ContentAlignment.MiddleCenter,
            Location=Dlu.P(60,55),Size=Dlu.S(104,8),
            Cursor=Cursors.Hand,ForeColor=Color.Blue,Font=font0
        };
        lblHome.MouseEnter+=(_,__)=>lblHome.Font=fontU;
        lblHome.MouseLeave+=(_,__)=>lblHome.Font=font0;
        lblHome.Click+=(_,__)=>{
            try{Process.Start(new ProcessStartInfo("http://cgig.ru/ninjaripper/")
                {UseShellExecute=true});}catch{}
        };
 
        // FIX 4: donation groupbox  19,68,185,46
        var grpDonate=new GroupBox{
            Text="Make a donation - support the development",
            Location=Dlu.P(19,68),Size=Dlu.S(185,46)
        };
 
        // Donate buttons  (original IDs: 1007=5$, 1006=10$, 1005=any)
        var b5  =Btn("Donate 5$",   21,85,60); b5.Click  +=(_,__)=>OpenUrl("https://www.paypal.com/donate");
        var b10 =Btn("Donate 10$",  82,85,60); b10.Click +=(_,__)=>OpenUrl("https://www.paypal.com/donate");
        var bAny=Btn("Donate any sum",143,85,60);bAny.Click+=(_,__)=>OpenUrl("https://www.paypal.com/donate");
 
        var ok=new Button{Text="OK",DialogResult=DialogResult.OK,
            Location=Dlu.P(7,127),Size=Dlu.S(208,20)};
 
        // lblVer added FIRST ? index 0 ? highest z-order ? renders on top of grpOuter
        Controls.AddRange(new Control[]{lblVer,lblAuthor,lblHome,b5,b10,bAny,ok,grpDonate,grpOuter});
        grpDonate.SendToBack(); grpOuter.SendToBack();
        AcceptButton=ok;
    }
    static Button Btn(string t,int x,int y,int w)=>
        new Button{Text=t,Location=Dlu.P(x,y),Size=Dlu.S(w,20)};
    static void OpenUrl(string url){
        try{Process.Start(new ProcessStartInfo(url){UseShellExecute=true});}catch{}
    }
}
 
// ===========================================================================
//  Main Window
// ===========================================================================
class MainForm : Form
{
    const string VERSION="Black Ripper 1.7.1";
    NRSettings _s=new NRSettings();
    TextBox  _exeTb, _argsTb, _dirTb, _outDirTb;
    CheckBox _dontOverwrite;
    ComboBox _wrapCombo;
    Button   _runBtn, _selExeBtn, _selOutBtn, _browseBtn, _aboutBtn, _settingsBtn;
    ToolTip  _tip=new ToolTip{ShowAlways=true};
 
    public MainForm()
    {
        Text=VERSION; FormBorderStyle=FormBorderStyle.FixedDialog;
        ClientSize=new Size(Dlu.X(303),Dlu.Y(154));
        StartPosition=FormStartPosition.CenterScreen;
        MinimizeBox=true; MaximizeBox=false; AllowDrop=true;
        try{Icon=Icon.ExtractAssociatedIcon(Application.ExecutablePath);}catch{}
        BuildUI(); LoadState();
        DragEnter+=(_,e)=>{if(e.Data.GetDataPresent(DataFormats.FileDrop))e.Effect=DragDropEffects.Copy;};
        DragDrop +=(_,e)=>{if(e.Data.GetData(DataFormats.FileDrop) is string[] f&&f.Length>0)SetExe(f[0]);};
    }
 
    void BuildUI()
    {
        SuspendLayout();
 
        var grpTop=new GroupBox{
            Text="Target (DX 11/9/8/7/6 application)",
            Location=Dlu.P(7,7),Size=Dlu.S(288,64),TabStop=false};
        var grpOut=new GroupBox{
            Text="Output Directory",
            Location=Dlu.P(7,74),Size=Dlu.S(288,48),TabStop=false};
 
        // Labels
        var lblExe =Lbl("Exe:",10,20,20,8);
        var lblArg =Lbl("Arg:",10,37,20,8);
        var lblDir =Lbl("Dir:",10,53,20,8);
        var lblODir=Lbl("Dir:",10,89,20,8);
 
        // Controls ? exact positions from original RC
        _exeTb    =new TextBox{ReadOnly=true,Enabled=false,Location=Dlu.P(32,19),Width=Dlu.X(160)};
        _selExeBtn=new Button {Text="...",Location=Dlu.P(195,19),Size=Dlu.S(17,13)};
        _selExeBtn.Click+=SelExe_Click;
 
        _argsTb =new TextBox{Location=Dlu.P(32,35),Width=Dlu.X(160)};
        _dirTb  =new TextBox{Location=Dlu.P(32,52),Width=Dlu.X(160)};
 
        _runBtn=new Button{Text="Run",Location=Dlu.P(217,16),Size=Dlu.S(72,32)};
        _runBtn.Click+=Run_Click;
 
        _wrapCombo=new ComboBox{DropDownStyle=ComboBoxStyle.DropDownList,
            Location=Dlu.P(217,52),Width=Dlu.X(72)};
        _wrapCombo.Items.AddRange(new object[]{
            "Intruder inject","D3D11 wrapper","D3D9 wrapper","D3D8 wrapper","DDRAW wrapper"});
        _wrapCombo.SelectedIndex=0;
 
        _outDirTb =new TextBox{ReadOnly=true,Enabled=false,Location=Dlu.P(32,88),Width=Dlu.X(160)};
        _selOutBtn=new Button {Text="...",Location=Dlu.P(195,88),Size=Dlu.S(17,13)};
        _selOutBtn.Click+=SelOut_Click;
 
        _browseBtn=new Button{Text="Browse",Location=Dlu.P(217,88),Size=Dlu.S(72,20)};
        _browseBtn.Click+=Browse_Click;
 
        _dontOverwrite=new CheckBox{Text="Don't change the path",AutoSize=false,
            Location=Dlu.P(32,106),Size=Dlu.S(112,10)};
 
        _settingsBtn=new Button{Text="Settings",      Location=Dlu.P(7,  127),Size=Dlu.S(72,20)};
        _aboutBtn   =new Button{Text="About / Donate",Location=Dlu.P(140,127),Size=Dlu.S(72,20)};
        var exitBtn =new Button{Text="Exit",          Location=Dlu.P(217,127),Size=Dlu.S(72,20)};
 
        _settingsBtn.Click+=(_,__)=>{using var d=new SettingsForm(_s);d.ShowDialog(this);};
        _aboutBtn.Click   +=(_,__)=>new AboutForm().ShowDialog(this);
        exitBtn.Click     +=(_,__)=>Close();
        // Log button -- instant visibility into what went wrong

        // FIX 7: Tooltips on every interactive control
        _tip.SetToolTip(_selExeBtn,   "Select traget file");
        _tip.SetToolTip(_argsTb,      "Command line arguments");
        _tip.SetToolTip(_dirTb,       "Work directory");
        _tip.SetToolTip(_runBtn,      "Run target");
        _tip.SetToolTip(_wrapCombo,   "Injection mode");
        _tip.SetToolTip(_selOutBtn,   "Select output directory");
        _tip.SetToolTip(_browseBtn,   "Browse output directory");
 
        Controls.AddRange(new Control[]{
            lblExe,lblArg,lblDir,lblODir,
            _exeTb,_selExeBtn,
            _argsTb,_dirTb,
            _runBtn,_wrapCombo,
            _outDirTb,_selOutBtn,_browseBtn,
            _dontOverwrite,
            _settingsBtn,_aboutBtn,exitBtn,
            grpOut,grpTop
        });
        grpTop.SendToBack(); grpOut.SendToBack();
        ResumeLayout(false);
    }
 
    static Label Lbl(string t,int x,int y,int w,int h)=>
        new Label{Text=t,AutoSize=false,TextAlign=ContentAlignment.MiddleRight,
            Location=Dlu.P(x,y),Size=Dlu.S(w,h)};
 
    void LoadState()
    {
        _s.Load();
        uint ver=1*10000+7*1000+1;
        if(_s.DonateShowVersion<ver){
            MessageBox.Show(
                "Welcome to Ninja Ripper 1.7.1\n\n"+
                "Due to active user support I've returned to supporting 64-bit game ripping.\n\n"+
                "WANT NEW VERSIONS? Please DONATE ? support the development.\n\n"+
                "First time? Read the tutorial first.",
                "Ninja Ripper",MessageBoxButtons.OK,MessageBoxIcon.Information);
            _s.DonateShowVersion=ver; _s.Save();
        }
        _exeTb.Text   =_s.PrevEXE;
        _argsTb.Text  =_s.PrevArg;
        _dirTb.Text   =_s.PrevDir;
        _outDirTb.Text=_s.OutDir;
        _dontOverwrite.Checked=_s.DontOverwriteOutDir!=0;
    }
 
    void SetExe(string path)
    {
        _exeTb.Text=path;
        string dir=Path.GetDirectoryName(path)+Path.DirectorySeparatorChar;
        _dirTb.Text=dir;
        if(!_dontOverwrite.Checked){_outDirTb.Text=dir;_s.OutDir=dir;}
    }
 
    void SelExe_Click(object s,EventArgs e){
        using var d=new OpenFileDialog{Filter="EXE Files|*.exe|All Files|*.*",Title="Select target EXE"};
        if(d.ShowDialog()==DialogResult.OK) SetExe(d.FileName);
    }
 
    void SelOut_Click(object s,EventArgs e){
        using var d=new FolderBrowserDialog{Description="Select output folder for ripped assets"};
        if(d.ShowDialog()==DialogResult.OK){_s.OutDir=d.SelectedPath;_outDirTb.Text=_s.OutDir;}
    }
 
    // FIX 2: Browse ? create dir first, then open in Explorer
    void Browse_Click(object s,EventArgs e){
        string dir=_outDirTb.Text.Trim();
        if(string.IsNullOrEmpty(dir))dir=_s.OutDir;
        if(string.IsNullOrEmpty(dir)){
            MessageBox.Show("No output directory set.","Ninja Ripper",MessageBoxButtons.OK,MessageBoxIcon.Information);
            return;
        }
        try{Directory.CreateDirectory(dir);}catch{}
        try{Process.Start(new ProcessStartInfo("explorer.exe",$"\"{dir}\""){UseShellExecute=true});}
        catch(Exception ex){MessageBox.Show($"Cannot open directory:\n{ex.Message}","Ninja Ripper",MessageBoxButtons.OK,MessageBoxIcon.Warning);}
    }
 
    void Run_Click(object s,EventArgs e){
        string exe=_exeTb.Text.Trim(),args=_argsTb.Text.Trim(),dir=_dirTb.Text.Trim();
        if(string.IsNullOrEmpty(exe)){Err("Select target EXE");return;}
        if(!File.Exists(exe)){Err("EXE not found:\n"+exe);return;}
        // If the Dir field is blank, default to the exe's own folder.
        // Without this the game process starts in the launcher's CWD and
        // cannot find its own DLLs, giving a silent 0xC0000135 crash.
        if(string.IsNullOrWhiteSpace(dir)) dir=Path.GetDirectoryName(exe);
        if(!NativeApi.GetBinaryType(exe,out uint bType)||
           (bType!=NativeApi.SCS_32BIT_BINARY&&bType!=NativeApi.SCS_64BIT_BINARY))
            {Err("Not a valid Win32/64 executable");return;}
 
        _s.PrevEXE=exe;_s.PrevArg=args;_s.PrevDir=dir;
        _s.DontOverwriteOutDir=(uint)(_dontOverwrite.Checked?1:0);
        _s.Save();
 
        var mode=(WrapMode)_wrapCombo.SelectedIndex;
        // FIX 1: use root dir, no subfolders
        var inj=new KInject(_s.IntruderDir);
        string exeDir=Path.GetDirectoryName(exe)+Path.DirectorySeparatorChar;
 
        if(mode==WrapMode.Intruder){
            string clash=KInject.FindWrapperInDir(exeDir);
            if(clash!=null){Err($"{exeDir}{clash}\nWrapper detected ? delete it before using Intruder mode.");return;}
            var st=inj.CreateAndInject(exe,args,dir);
            if(st!=KInject.Status.OK&&st!=KInject.Status.ErrorDllNotFound)
                MessageBox.Show(KInject.StatusString(st,inj.Win32Error),"Injection failed",MessageBoxButtons.OK,MessageBoxIcon.Error);
        }else{
            string wrapSrc=Path.Combine(_s.IntruderDir,"d3dwrap.dll");
            string wrapDll=mode switch{
                WrapMode.D3D11=>"d3d11.dll",WrapMode.D3D9=>"d3d9.dll",
                WrapMode.D3D8=>"d3d8.dll",WrapMode.DDraw=>"ddraw.dll",_=>null};
            if(!File.Exists(wrapSrc)){Err($"d3dwrap.dll not found next to launcher:\n{wrapSrc}");return;}
            string dst=Path.Combine(exeDir,wrapDll!);
            try{File.Copy(wrapSrc,dst,true);}
            catch(Exception ex){Err($"Wrapper copy error:\n{ex.Message}\nTry running as Administrator.");return;}
            inj.CreateProcess(exe,args,dir);
        }
    }
 
    static void Err(string m)=>MessageBox.Show(m,"Ninja Ripper",MessageBoxButtons.OK,MessageBoxIcon.Error);
}
 
// ===========================================================================
//  Entry point
// ===========================================================================
static class Program
{
    [STAThread]
    static void Main(string[] argv)
    {
        Logger.Init();
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        var s=new NRSettings(); s.Load();
        if(argv.Length==0){
            Application.Run(new MainForm());
        }else{
            string target=argv[0],args=argv.Length>=2?argv[1]:"";
            var inj=new KInject(s.IntruderDir);
            var st=inj.CreateAndInject(target,args,null);
            if(st!=KInject.Status.OK&&st!=KInject.Status.ErrorDllNotFound)
                MessageBox.Show(KInject.StatusString(st,inj.Win32Error),
                    "Injection failed",MessageBoxButtons.OK,MessageBoxIcon.Error);
        }
    }
}
