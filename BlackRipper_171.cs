// =============================================================================
//  NinjaRipper 1.7.1  -  C# .NET Single-File Launcher
//
//  Replaces NinjaRipper.exe (the C++ injector) completely.
//  intruder.dll is pre-compiled and placed alongside this launcher.
//  d3dwrap.dll is pre-compiled and placed alongside this launcher.
//  injhelper.exe is pre-compiled and placed alongside this launcher.
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
//    2. Saves/loads settings in the same registry key as the C++ version
//    3. Injects intruder.dll via APC Injection (QueueUserAPC), same mechanism as KInject
//    4. Falls back to injhelper.exe for cross-arch targets
// =============================================================================
 
using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows.Forms;
using Microsoft.Win32;
 
 
// -----------------------------------------------------------------------------
//  DLU ? pixel helper
//  8 pt "MS Shell Dlg" at 96 DPI  ?  baseX = 6, baseY = 13
//  px_x = dlu_x * 6 / 4     px_y = dlu_y * 13 / 8
// -----------------------------------------------------------------------------
static class Dlu
{
    public static int   X(int d) => d * 6 / 4;
    public static int   Y(int d) => d * 13 / 8;
    public static Point P(int x, int y) => new Point(X(x), Y(y));
    public static Size  S(int w, int h) => new Size(X(w), Y(h));
}
 
 
// -----------------------------------------------------------------------------
//  P/Invoke declarations
// -----------------------------------------------------------------------------
static class NativeApi
{
    public const uint CREATE_SUSPENDED  = 0x00000004;
    public const uint PROCESS_ALL_ACCESS = 0x001FFFFF;
    public const uint MEM_COMMIT   = 0x1000;
    public const uint MEM_RESERVE  = 0x2000;
    public const uint MEM_RELEASE  = 0x8000;
    public const uint PAGE_READWRITE = 0x04;
    public const uint SCS_32BIT_BINARY = 0;
    public const uint SCS_64BIT_BINARY = 6;
 
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
 
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool CreateProcess(
        string lpApp, string lpCmd, IntPtr pPA, IntPtr pTA, bool bInherit,
        uint dwFlags, IntPtr lpEnv, string lpDir,
        ref STARTUPINFO lpSI, out PROCESS_INFORMATION lpPI);
 
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAllocEx(
        IntPtr hProc, IntPtr addr, uint size, uint type, uint protect);
 
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteProcessMemory(
        IntPtr hProc, IntPtr addr, byte[] buf, uint size, out uint written);
 
    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    public static extern IntPtr GetProcAddress(IntPtr hMod, string name);
 
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr GetModuleHandle(string name);
 
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, UIntPtr data);
 
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint ResumeThread(IntPtr hThread);
 
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr h);
 
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualFreeEx(
        IntPtr hProc, IntPtr addr, uint size, uint type);
 
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool GetBinaryType(string app, out uint type);
 
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool TerminateProcess(IntPtr hProc, uint code);
 
    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    public static extern IntPtr ShellExecute(
        IntPtr hwnd, string op, string file, string param, string dir, int show);
 
    [DllImport("kernel32.dll")]
    public static extern bool IsWow64Process(IntPtr hProc, out bool wow64);
}
 
 
// -----------------------------------------------------------------------------
//  Settings – mirrors KSettings / registry key exactly
// -----------------------------------------------------------------------------
class NRSettings
{
    const string REG = @"SOFTWARE\black_ninja\NinjaRipper";
 
    public string PrevEXE  = "", PrevArg = "", PrevDir = "";
    public string OutDir   = "";
    public string IntruderDir32 = "", IntruderDir64 = "";
 
    public uint RipKey          = 121;   // F10
    public uint TextureRipKey   = 120;   // F9
    public uint ForcedRipKey    = 123;   // F12
    public uint SpecKeys        = 0;
    public uint DontOverwriteOutDir  = 1;
    public uint DonateShowVersion    = 0;
    public uint SaveShaders          = 0;
    public uint SaveDDrawSurfaces    = 0;
    public uint DebugD3D             = 0;
    public uint Downscale            = 2;
    public uint DownscaleWidth       = 4096;
    public uint DownscaleHeight      = 4096;
    public uint MinPresentInterval   = 10000;
    public uint usForcedRipInterval  = 10000000;
 
    static bool Is64() => Environment.Is64BitProcess;
 
    // -- Load -----------------------------------------------------------------
    public void Load()
    {
        using var k = Registry.CurrentUser.OpenSubKey(REG);
        if (k == null) { SetDefaultOutDir(); return; }
 
        string exeKey = Is64() ? "PrevEXE64" : "PrevEXE";
        string argKey = Is64() ? "PrevArg64" : "PrevArg";
        string dirKey = Is64() ? "PrevDir64" : "PrevDir";
 
        PrevEXE = Str(k, exeKey);
        PrevArg = Str(k, argKey);
        PrevDir = Str(k, dirKey);
        OutDir  = Str(k, "OutDir");
        if (string.IsNullOrEmpty(OutDir)) SetDefaultOutDir();
        IntruderDir32 = Str(k, "IntruderDir32");
        IntruderDir64 = Str(k, "IntruderDir64");
 
        RipKey          = Dw(k, "RipKey",           121);
        TextureRipKey   = Dw(k, "TextureRipKey",    120);
        ForcedRipKey    = Dw(k, "ForcedRipKey",     123);
        SpecKeys        = Dw(k, "SpecKeys",            0);
        DontOverwriteOutDir  = Dw(k, "DontOverwriteOutDir",  1);
        DonateShowVersion    = Dw(k, "DonateShowVersion",    0);
        SaveShaders          = Dw(k, "SaveShaders",          0);
        SaveDDrawSurfaces    = Dw(k, "SaveDDrawSurfaces",    0);
        DebugD3D             = Dw(k, "DebugD3D",             0);
        Downscale            = Dw(k, "Downscale",            2);
        DownscaleWidth       = Dw(k, "DownscaleWidth",    4096);
        DownscaleHeight      = Dw(k, "DownscaleHeight",   4096);
        MinPresentInterval   = Dw(k, "MinPresentInterval",  10000);
        usForcedRipInterval  = Dw(k, "usForcedRipInterval", 10000000);
    }
 
    // -- Save -----------------------------------------------------------------
    public void Save()
    {
        using var k = Registry.CurrentUser.CreateSubKey(REG);
        string exeKey = Is64() ? "PrevEXE64" : "PrevEXE";
        string argKey = Is64() ? "PrevArg64" : "PrevArg";
        string dirKey = Is64() ? "PrevDir64" : "PrevDir";
 
        k.SetValue(exeKey, PrevEXE); k.SetValue(argKey, PrevArg); k.SetValue(dirKey, PrevDir);
        k.SetValue("OutDir",           OutDir);
        k.SetValue("IntruderDir32",    IntruderDir32);
        k.SetValue("IntruderDir64",    IntruderDir64);
        k.SetValue("RipKey",           (int)RipKey,          RegistryValueKind.DWord);
        k.SetValue("TextureRipKey",    (int)TextureRipKey,   RegistryValueKind.DWord);
        k.SetValue("ForcedRipKey",     (int)ForcedRipKey,    RegistryValueKind.DWord);
        k.SetValue("SpecKeys",         (int)SpecKeys,        RegistryValueKind.DWord);
        k.SetValue("DontOverwriteOutDir",(int)DontOverwriteOutDir, RegistryValueKind.DWord);
        k.SetValue("DonateShowVersion",  (int)DonateShowVersion,   RegistryValueKind.DWord);
        k.SetValue("SaveShaders",      (int)SaveShaders,     RegistryValueKind.DWord);
        k.SetValue("SaveDDrawSurfaces",(int)SaveDDrawSurfaces,RegistryValueKind.DWord);
        k.SetValue("DebugD3D",         (int)DebugD3D,        RegistryValueKind.DWord);
        k.SetValue("Downscale",        (int)Downscale,       RegistryValueKind.DWord);
        k.SetValue("DownscaleWidth",   (int)DownscaleWidth,  RegistryValueKind.DWord);
        k.SetValue("DownscaleHeight",  (int)DownscaleHeight, RegistryValueKind.DWord);
        k.SetValue("MinPresentInterval",(int)MinPresentInterval, RegistryValueKind.DWord);
        k.SetValue("usForcedRipInterval",(int)usForcedRipInterval, RegistryValueKind.DWord);
    }
 
    // -- UpdateIntruderDirs + copy bundled DLLs -------------------------------
    //  Layout this tool expects at runtime:
    //    <root>\x86\intruder.dll    <root>\x86\d3dwrap.dll
    //    <root>\x64\intruder.dll    <root>\x64\d3dwrap.dll
    //
    //  Source (placed by you at build time):
    //    <root>\Intruder & Wrapper (Compiled)\         ? flat layout, OR
    //    <root>\Intruder & Wrapper (Compiled)\x86\     ? structured layout
    //    <root>\Intruder & Wrapper (Compiled)\x64\
    public void UpdateIntruderDirs()
    {
        string root = AppDomain.CurrentDomain.BaseDirectory;
        IntruderDir32 = Path.Combine(root, "x86") + Path.DirectorySeparatorChar;
        IntruderDir64 = Path.Combine(root, "x64") + Path.DirectorySeparatorChar;
        CopyBundledDlls(root);
    }
 
    static void CopyBundledDlls(string root)
    {
        string src = Path.Combine(root, "Intruder & Wrapper (Compiled)");
        if (!Directory.Exists(src)) return;
 
        string[] archs = { "x86", "x64" };
        string[] dlls  = { "intruder.dll", "d3dwrap.dll" };
 
        foreach (string arch in archs)
        {
            string dstDir = Path.Combine(root, arch);
            try { Directory.CreateDirectory(dstDir); } catch { continue; }
 
            string srcArch = Path.Combine(src, arch);
            bool structured = Directory.Exists(srcArch);
 
            foreach (string dll in dlls)
            {
                string srcFile = structured
                    ? Path.Combine(srcArch, dll)
                    : Path.Combine(src, dll);
                string dstFile = Path.Combine(dstDir, dll);
 
                if (File.Exists(srcFile) && !File.Exists(dstFile))
                    try { File.Copy(srcFile, dstFile); } catch { /* non-fatal */ }
            }
        }
    }
 
    void SetDefaultOutDir() =>
        OutDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            "NinjaRipper");
 
    static string Str(RegistryKey k, string name) =>
        k?.GetValue(name) as string ?? "";
 
    static uint Dw(RegistryKey k, string name, uint def)
    {
        var v = k?.GetValue(name);
        return v is int i ? (uint)i : def;
    }
}
 
 
// -----------------------------------------------------------------------------
//  KInject – C# port of the C++ KInject class
//  Injects intruder.dll via QueueUserAPC; falls back to injhelper.exe for
//  cross-arch targets (e.g. 64-bit launcher ? 32-bit game).
// -----------------------------------------------------------------------------
class KInject
{
    public enum Status
    {
        OK = 0,
        ErrorCreateProcess,
        ErrorVirtualAlloc,
        ErrorWriteMemory,
        ErrorQueueAPC,
        ErrorBinaryFormat,
        ErrorHelperProcess,
        ErrorHelperFailed,
        ErrorHelperTimeout,
        ErrorDllNotFound,
    }
 
    readonly string _dir32, _dir64;
    public int Win32Error { get; private set; }
 
    public KInject(string dir32, string dir64) { _dir32 = dir32; _dir64 = dir64; }
 
    static string IntruderPath(string dir) => Path.Combine(dir, "intruder.dll");
    static string HelperPath  (string dir) => Path.Combine(dir, "injhelper.exe");
 
    // -- CreateAndInject (Intruder mode) --------------------------------------
    public Status CreateAndInject(string exe, string args, string workDir)
    {
        if (!NativeApi.GetBinaryType(exe, out uint tgtType))
        {
            Win32Error = Marshal.GetLastWin32Error();
            return Status.ErrorBinaryFormat;
        }
 
        bool self64  = Environment.Is64BitProcess;
        bool tgt64   = tgtType == NativeApi.SCS_64BIT_BINARY;
        string dllDir  = tgt64 ? _dir64 : _dir32;
        string dllPath = IntruderPath(dllDir);
 
        if (!File.Exists(dllPath)) return Status.ErrorDllNotFound;
 
        var si = new NativeApi.STARTUPINFO { cb = Marshal.SizeOf<NativeApi.STARTUPINFO>() };
        string cmdLine = $"\"{exe}\"";
        if (!string.IsNullOrEmpty(args)) cmdLine += " " + args;
 
        if (!NativeApi.CreateProcess(exe, cmdLine, IntPtr.Zero, IntPtr.Zero,
                false, NativeApi.CREATE_SUSPENDED, IntPtr.Zero,
                string.IsNullOrEmpty(workDir) ? null : workDir,
                ref si, out var pi))
        {
            Win32Error = Marshal.GetLastWin32Error();
            return Status.ErrorCreateProcess;
        }
 
        Status st = (self64 == tgt64)
            ? InjectApc(pi.hProcess, pi.hThread, dllPath)
            : HelperInject(tgt64, pi.dwProcessId, pi.dwThreadId, dllPath);
 
        NativeApi.ResumeThread(pi.hThread);
        NativeApi.CloseHandle(pi.hThread);
        NativeApi.CloseHandle(pi.hProcess);
        return st;
    }
 
    // -- CreateProcess only (wrapper DLL mode) --------------------------------
    public Status CreateProcess(string exe, string args, string workDir)
    {
        var si = new NativeApi.STARTUPINFO { cb = Marshal.SizeOf<NativeApi.STARTUPINFO>() };
        string cmdLine = $"\"{exe}\"";
        if (!string.IsNullOrEmpty(args)) cmdLine += " " + args;
        if (!NativeApi.CreateProcess(exe, cmdLine, IntPtr.Zero, IntPtr.Zero,
                false, 0, IntPtr.Zero,
                string.IsNullOrEmpty(workDir) ? null : workDir,
                ref si, out _))
        {
            Win32Error = Marshal.GetLastWin32Error();
            return Status.ErrorCreateProcess;
        }
        return Status.OK;
    }
 
    // -- Same-arch APC injection -----------------------------------------------
    Status InjectApc(IntPtr hProc, IntPtr hThread, string dllPath)
    {
        byte[] pathBytes = Encoding.Unicode.GetBytes(dllPath + "\0");
        uint   size      = (uint)pathBytes.Length;
 
        IntPtr pMem = NativeApi.VirtualAllocEx(hProc, IntPtr.Zero, size,
            NativeApi.MEM_COMMIT | NativeApi.MEM_RESERVE, NativeApi.PAGE_READWRITE);
        if (pMem == IntPtr.Zero)
        { Win32Error = Marshal.GetLastWin32Error(); return Status.ErrorVirtualAlloc; }
 
        if (!NativeApi.WriteProcessMemory(hProc, pMem, pathBytes, size, out _))
        {
            Win32Error = Marshal.GetLastWin32Error();
            NativeApi.VirtualFreeEx(hProc, pMem, 0, NativeApi.MEM_RELEASE);
            return Status.ErrorWriteMemory;
        }
 
        IntPtr hK32  = NativeApi.GetModuleHandle("kernel32.dll");
        IntPtr pLoad = NativeApi.GetProcAddress(hK32, "LoadLibraryW");
 
        if (!NativeApi.QueueUserAPC(pLoad, hThread, (UIntPtr)(ulong)pMem))
        {
            Win32Error = Marshal.GetLastWin32Error();
            NativeApi.VirtualFreeEx(hProc, pMem, 0, NativeApi.MEM_RELEASE);
            return Status.ErrorQueueAPC;
        }
        return Status.OK;
    }
 
    // -- Cross-arch: delegate to injhelper.exe --------------------------------
    Status HelperInject(bool target64, uint pid, uint tid, string dllPath)
    {
        string helperDir = target64 ? _dir64 : _dir32;
        string helper    = HelperPath(helperDir);
        if (!File.Exists(helper)) return Status.ErrorHelperProcess;
 
        var psi = new ProcessStartInfo(helper, $"{pid} {tid} \"{dllPath}\"")
        { UseShellExecute = false, CreateNoWindow = true };
 
        var proc = Process.Start(psi);
        if (proc == null) return Status.ErrorHelperProcess;
        if (!proc.WaitForExit(10_000)) return Status.ErrorHelperTimeout;
        return proc.ExitCode == 0 ? Status.OK : Status.ErrorHelperFailed;
    }
 
    // -- Scan for pre-existing wrapper DLLs in a directory --------------------
    static readonly string[] WrapperDlls = { "d3d9.dll", "d3d8.dll", "d3d11.dll", "ddraw.dll" };
    public static string FindWrapperInDir(string dir)
    {
        foreach (var dll in WrapperDlls)
            if (File.Exists(Path.Combine(dir, dll))) return dll;
        return null;
    }
 
    public static string StatusString(Status s, int err = 0) => s switch
    {
        Status.OK                 => "OK",
        Status.ErrorCreateProcess => $"CreateProcess failed (0x{err:X8})",
        Status.ErrorVirtualAlloc  => $"VirtualAllocEx failed (0x{err:X8})",
        Status.ErrorWriteMemory   => $"WriteProcessMemory failed (0x{err:X8})",
        Status.ErrorQueueAPC      => $"QueueUserAPC failed (0x{err:X8})",
        Status.ErrorBinaryFormat  => "GetBinaryType failed – not a valid EXE",
        Status.ErrorHelperProcess => "Cannot start injhelper.exe",
        Status.ErrorHelperFailed  => "injhelper.exe reported failure",
        Status.ErrorHelperTimeout => "injhelper.exe timed out",
        Status.ErrorDllNotFound   => "intruder.dll not found in x86\\ or x64\\",
        _                         => "Unknown error"
    };
}
 
 
// -----------------------------------------------------------------------------
//  Settings Dialog
//     108 DIALOGEX  0, 0, 283, 144   "Settings"
// -----------------------------------------------------------------------------
class SettingsForm : Form
{
    //   control IDs:
    //   1012 = All-key combo      1013 = Texture-key combo   1014 = Forced-key combo
    //   1025 = +Ctrl              1026 = +Shift              1027 = +Alt
    //   1015 = Save shaders       1008 = Save DirectDraw surfaces
    //   1022 = updown (forced interval)
    //   1 = OK                    2 = Cancel
 
    NRSettings _s;
    ComboBox      _ripKey, _texKey, _forcedKey;
    CheckBox      _saveShaders, _saveDdraw, _ctrlKey, _shiftKey, _altKey;
    NumericUpDown _forceInterval;
 
    public SettingsForm(NRSettings s)
    {
        _s = s;
 
        // -- Form properties --------------------------------------------------
        Text            = "Settings";
        FormBorderStyle = FormBorderStyle.FixedDialog;
        ShowInTaskbar = false;
        //    283×144 DLU ? client 424×234 px
        ClientSize      = new Size(Dlu.X(283), Dlu.Y(144));
        StartPosition   = FormStartPosition.CenterParent;
        MaximizeBox = MinimizeBox = false;
 
        SuspendLayout();
 
        // -- GroupBox: "Rip keys select"  7,7, 269×66 DLU -------------------
        var grpRip = MakeGroupBox("Rip keys select", 7, 7, 269, 66);
 
        // -- Key-select labels (SS_RIGHT = right-aligned) ---------------------
        // "All"     11,25, 13×8
        var lblAll     = MakeLabel("All",      11, 25,  13, 8, ContentAlignment.MiddleRight);
        // "Textures" 65,25, 36×8
        var lblTex     = MakeLabel("Textures", 65, 25,  36, 8, ContentAlignment.MiddleRight);
        // "Forced"  144,25, 35×8
        var lblForced  = MakeLabel("Forced",  144, 25,  35, 8, ContentAlignment.MiddleRight);
 
        // -- Combo boxes (h = dropdown height, not control height) -------------
        // 1012 All key:     28,23, 33 wide
        _ripKey   = MakeCombo(28, 23, 33);
        // 1013 Texture key: 107,23, 33 wide
        _texKey   = MakeCombo(107, 23, 33);
        // 1014 Forced key:  181,23, 33 wide
        _forcedKey = MakeCombo(181, 23, 33);
 
        SelectKey(_ripKey,    s.RipKey);
        SelectKey(_texKey,    s.TextureRipKey);
        SelectKey(_forcedKey, s.ForcedRipKey);
 
        // -- Modifier checkboxes inside the GroupBox --------------------------
        // 1025 +Ctrl  23,52, 37×10
        _ctrlKey  = MakeCheck("+Ctrl",  23, 52, 37, 10, (s.SpecKeys & 0x1) != 0);
        // 1026 +Shift 66,52, 38×10
        _shiftKey = MakeCheck("+Shift", 66, 52, 38, 10, (s.SpecKeys & 0x2) != 0);
        // 1027 +Alt  111,52, 37×10
        _altKey   = MakeCheck("+Alt",  111, 52, 37, 10, (s.SpecKeys & 0x4) != 0);
 
        // -- Option checkboxes (below the GroupBox) ---------------------------
        // 1015 "Save shaders (for experts)"              23,80, 101×10
        _saveShaders = MakeCheck("Save shaders (for experts)",
                                 23, 80, 101, 10, s.SaveShaders != 0);
        // 1008 "Save DirectDraw surfaces (DX1-DX7)"     23,98, 164×10
        _saveDdraw   = MakeCheck("Save DirectDraw surfaces (DX1-DX7)",
                                 23, 98, 164, 10, s.SaveDDrawSurfaces != 0);
 
        // -- Forced rip interval label + NumericUpDown + "sec" ----------------
        // "Forced rip interval:"  SS_RIGHT  147,80, 69×8
        var lblInterval = MakeLabel("Forced rip interval:", 147, 80, 69, 8,
                                     ContentAlignment.MiddleRight);
        // 1022/1023: spin+buddy merged ? NumericUpDown at (219,78), total ~38 wide
        _forceInterval = new NumericUpDown
        {
            Minimum  = 1, Maximum = 300,
            Value    = Math.Max(1, Math.Min(300, s.usForcedRipInterval / 1_000_000)),
            Location = Dlu.P(219, 78),
            Width    = Dlu.X(13) + Dlu.X(10),   // static(13) + arrows(10)
        };
        // "sec"  249,80, 20×8
        var lblSec = MakeLabel("sec", 249, 80, 20, 8, ContentAlignment.MiddleLeft);
 
        // -- OK / Cancel -------------------------------------------------------
        // 1  OK     141,120, 62×17
        var ok = new Button
        {
            Text         = "OK",
            DialogResult = DialogResult.OK,
            Location     = Dlu.P(141, 120),
            Size         = Dlu.S(62, 17)
        };
        ok.Click += (_, __) => Apply();
 
        // 2  Cancel 214,120, 62×17
        var cancel = new Button
        {
            Text         = "Cancel",
            DialogResult = DialogResult.Cancel,
            Location     = Dlu.P(214, 120),
            Size         = Dlu.S(62, 17)
        };
 
        AcceptButton = ok;
        CancelButton = cancel;
 
        // Add GroupBox last so it is at the back of the Z-order when we
        // call SendToBack(), ensuring inner controls paint on top of it.
        Controls.AddRange(new Control[] {
            lblAll, lblTex, lblForced,
            _ripKey, _texKey, _forcedKey,
            _ctrlKey, _shiftKey, _altKey,
            _saveShaders, _saveDdraw,
            lblInterval, _forceInterval, lblSec,
            ok, cancel,
            grpRip
        });
        grpRip.SendToBack();
 
        ResumeLayout(false);
    }
 
    void Apply()
    {
        _s.RipKey        = KeyFromCombo(_ripKey);
        _s.TextureRipKey = KeyFromCombo(_texKey);
        _s.ForcedRipKey  = KeyFromCombo(_forcedKey);
        _s.SpecKeys      = (uint)((_ctrlKey.Checked  ? 1 : 0) |
                                   (_shiftKey.Checked ? 2 : 0) |
                                   (_altKey.Checked   ? 4 : 0));
        _s.SaveShaders        = (uint)(_saveShaders.Checked ? 1 : 0);
        _s.SaveDDrawSurfaces  = (uint)(_saveDdraw.Checked   ? 1 : 0);
        _s.usForcedRipInterval = (uint)_forceInterval.Value * 1_000_000;
        _s.Save();
    }
 
    // F1-F12 ? idx 0-11,  0-9 ? idx 12-21,  A-Z ? idx 22-47
    static ComboBox MakeCombo(int dluX, int dluY, int dluW)
    {
        var cb = new ComboBox
        {
            DropDownStyle = ComboBoxStyle.DropDownList,
            Location      = Dlu.P(dluX, dluY),
            Width         = Dlu.X(dluW)
        };
        for (int i = 1; i <= 12; i++) cb.Items.Add($"F{i}");
        for (int i = 0; i <=  9; i++) cb.Items.Add($"{i}");
        for (char c = 'A'; c <= 'Z'; c++) cb.Items.Add($"{c}");
        return cb;
    }
    static void SelectKey(ComboBox cb, uint vk)
    {
        int idx;
        if      (vk >= 0x70 && vk <= 0x7B) idx = (int)(vk - 0x70);
        else if (vk >= 0x30 && vk <= 0x39) idx = 12 + (int)(vk - 0x30);
        else if (vk >= 0x41 && vk <= 0x5A) idx = 22 + (int)(vk - 0x41);
        else idx = 0;
        cb.SelectedIndex = idx;
    }
    static uint KeyFromCombo(ComboBox cb)
    {
        int idx = cb.SelectedIndex;
        if (idx <= 11) return (uint)(0x70 + idx);
        if (idx <= 21) return (uint)(0x30 + (idx - 12));
        return                 (uint)(0x41 + (idx - 22));
    }
 
    // -- Factory helpers -------------------------------------------------------
    static GroupBox MakeGroupBox(string text, int x, int y, int w, int h) =>
        new GroupBox
        {
            Text     = text,
            Location = Dlu.P(x, y),
            Size     = Dlu.S(w, h),
            TabStop  = false
        };
 
    static Label MakeLabel(string text, int x, int y, int w, int h,
                            ContentAlignment align) =>
        new Label
        {
            Text      = text,
            AutoSize  = false,
            TextAlign = align,
            Location  = Dlu.P(x, y),
            Size      = Dlu.S(w, h)
        };
 
    static CheckBox MakeCheck(string text, int x, int y, int w, int h, bool chk) =>
        new CheckBox
        {
            Text     = text,
            Checked  = chk,
            AutoSize = false,
            Location = Dlu.P(x, y),
            Size     = Dlu.S(w, h)
        };
}
 
 
// -----------------------------------------------------------------------------
//  About / Donate Dialog
//     106 DIALOGEX  0, 0, 222, 154   "About / Donate"
// -----------------------------------------------------------------------------
class AboutForm : Form
{
    public AboutForm()
    {
        // -- Form properties --------------------------------------------------
        Text            = "About / Donate";
        FormBorderStyle = FormBorderStyle.FixedDialog;
        ShowInTaskbar = false;
        //    222×154 DLU ? client 333×250 px
        ClientSize      = new Size(Dlu.X(222), Dlu.Y(154));
        StartPosition   = FormStartPosition.CenterParent;   // closest to DS_CENTERMOUSE
        MaximizeBox = MinimizeBox = false;
 
        SuspendLayout();
 
        // -- Outer GroupBox (no title)  7,6, 208×115 -------------------------
        var grpOuter = new GroupBox
        {
            Text     = "",
            Location = Dlu.P(7, 6),
            Size     = Dlu.S(208, 115),
            TabStop  = false
        };
 
        // -- Title label (top area, added for visual completeness) -
        var lblTitle = new Label
        {
            Text      = "Ninja Ripper 1.7.1",
            AutoSize  = false,
            TextAlign = ContentAlignment.MiddleCenter,
            Font      = new Font("MS Shell Dlg", 9f, FontStyle.Bold),
            Location  = Dlu.P(8, 14),
            Size      = Dlu.S(206, 20)
        };
 
        // -- 1028  "© black_ninja, 2017"  SS_LEFT  77,41, 68×8 ---------------
        var lblCopy = new Label
        {
            Text      = "\xA9 black_ninja, 2017",
            AutoSize  = false,
            TextAlign = ContentAlignment.MiddleLeft,
            Location  = Dlu.P(77, 41),
            Size      = Dlu.S(68, 8)
        };
 
        // -- 1018  "Home: cgig.ru/ninjaripper"  SS_CENTER  60,55, 104×8 -----
        var lnkHome = new LinkLabel
        {
            Text      = "Home: cgig.ru/ninjaripper",
            AutoSize  = false,
            TextAlign = ContentAlignment.MiddleCenter,
            Location  = Dlu.P(60, 55),
            Size      = Dlu.S(104, 8)
        };
        lnkHome.LinkClicked += (_, __) =>
            NativeApi.ShellExecute(IntPtr.Zero, "open", "http://cgig.ru/ninjaripper/",
                                   "", "", 1);
 
        // -- Inner GroupBox "Make a donation - support the development"
        //    19,68, 185×46 ----------------------------------------------------
        var grpDonate = new GroupBox
        {
            Text     = "Make a donation - support the development",
            Location = Dlu.P(19, 68),
            Size     = Dlu.S(185, 46),
            TabStop  = false
        };
 
        // -- 1007  "Donate 5$"       21,85, 60×20 ----------------------------
        var btn5 = MakeDonateBtn("Donate 5$",  21, 85, 60);
        btn5.Click += (_, __) =>
            NativeApi.ShellExecute(IntPtr.Zero, "open", "https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=Y8868H7SDMN5S",
                                   "", "", 1);
 
        // -- 1006  "Donate 10$"      82,85, 60×20 ----------------------------
        var btn10 = MakeDonateBtn("Donate 10$", 82, 85, 60);
        btn10.Click += (_, __) =>
            NativeApi.ShellExecute(IntPtr.Zero, "open", "https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=5PEMD4A6PKMCL",
                                   "", "", 1);
 
        // -- 1005  "Donate any sum" 143,85, 60×20 ----------------------------
        var btnAny = MakeDonateBtn("Donate any sum", 143, 85, 60);
        btnAny.Click += (_, __) =>
            NativeApi.ShellExecute(IntPtr.Zero, "open", "https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=RUBGWHC8CKRGN",
                                   "", "", 1);
 
        // -- 1  "OK"  7,127, 208×20 -------------------------------------------
        var ok = new Button
        {
            Text         = "OK",
            DialogResult = DialogResult.OK,
            Location     = Dlu.P(7, 127),
            Size         = Dlu.S(208, 20)
        };
 
        AcceptButton = ok;
 
        Controls.AddRange(new Control[] {
            lblTitle, lblCopy, lnkHome,
            btn5, btn10, btnAny,
            ok,
            grpDonate,
            grpOuter
        });
        grpOuter.SendToBack();
        grpDonate.SendToBack();
 
        ResumeLayout(false);
    }
 
    static Button MakeDonateBtn(string text, int x, int y, int w) =>
        new Button
        {
            Text     = text,
            Location = Dlu.P(x, y),
            Size     = Dlu.S(w, 20)
        };
}
 
 
// -----------------------------------------------------------------------------
//  Main Window
//  101 DIALOGEX  0, 0, 303, 154   (caption = "")
//  WS_MINIMIZEBOX present ? MinimizeBox = true
//  WS_EX_ACCEPTFILES      ? AllowDrop = true
// -----------------------------------------------------------------------------
class MainForm : Form
{
    const string VERSION = "Black Ripper 1.7.1";
 
    NRSettings _s = new NRSettings();
 
    // Wrap mode matches C++ WRAP_* defines
    enum WrapMode { Intruder = 0, D3D11 = 1, D3D9 = 2, D3D8 = 3, DDraw = 4 }
 
    TextBox  _exeTb, _argsTb, _dirTb, _outDirTb;
    CheckBox _dontOverwrite;
    ComboBox _wrapCombo;
    Button   _runBtn, _selExeBtn, _selOutBtn, _browseBtn, _aboutBtn, _settingsBtn;
 
    public MainForm()
    {
        // -- Form properties --------------------------------------------------
        Text            = VERSION;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        //    303×154 DLU ? client 454×250 px
        ClientSize      = new Size(Dlu.X(303), Dlu.Y(154));
        StartPosition   = FormStartPosition.CenterScreen;
        MinimizeBox     = true;           // WS_MINIMIZEBOX
        MaximizeBox     = false;
        AllowDrop       = true;           // WS_EX_ACCEPTFILES
 
        // Embedded icon: ApplicationIcon in .csproj embeds 1.ico as a Win32
        // resource; ExtractAssociatedIcon recovers it at runtime.
        try { Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); }
        catch { /* fallback to default */ }
 
        BuildUI();
        LoadState();
 
        // -- Drag-and-drop -----------------------------------------------------
        DragEnter += (_, e) =>
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop))
                e.Effect = DragDropEffects.Copy;
        };
        DragDrop += (_, e) =>
        {
            if (e.Data.GetData(DataFormats.FileDrop) is string[] files && files.Length > 0)
                SetExe(files[0]);
        };
    }
 
    // -- Build UI with the exact same layout ---------------------------
    void BuildUI()
    {
        SuspendLayout();
 
        // -- GroupBox 1021 (no title)  7,7, 288×64 ---------------------------
        var grpTop = new GroupBox
        {
            Text     = "",
            Location = Dlu.P(7, 7),
            Size     = Dlu.S(288, 64),
            TabStop  = false
        };
 
        // -- GroupBox "Output Directory"  7,74, 288×48 ------------------------
        var grpOut = new GroupBox
        {
            Text     = "Output Directory",
            Location = Dlu.P(7, 74),
            Size     = Dlu.S(288, 48),
            TabStop  = false
        };
 
        // -- Labels (SS_RIGHT) ------------------------------------------------
        var lblExe  = MakeLbl("Exe:", 10, 20, 20, 8);
        var lblArg  = MakeLbl("Arg:", 10, 37, 20, 8);
        var lblDir  = MakeLbl("Dir:", 10, 53, 20, 8);
        var lblODir = MakeLbl("Dir:", 10, 89, 20, 8);
 
        // -- 1001  EXE textbox (disabled/read-only)  32,19, 160×12 ------------
        _exeTb = new TextBox
        {
            ReadOnly = true,
            Enabled = false,
            Location = Dlu.P(32, 19),
            Width    = Dlu.X(160)
        };
 
        // -- 1004  "..."  195,19, 17×13 ---------------------------------------
        _selExeBtn = new Button { Text = "...", Location = Dlu.P(195, 19), Size = Dlu.S(17, 13) };
        _selExeBtn.Click += SelExe_Click;
 
        // -- 1002  Args textbox  32,35, 160×12 --------------------------------
        _argsTb = new TextBox { Location = Dlu.P(32, 35), Width = Dlu.X(160) };
 
        // -- 1010  Dir textbox  32,52, 160×12 ---------------------------------
        _dirTb = new TextBox { Location = Dlu.P(32, 52), Width = Dlu.X(160) };
 
        // -- 1005  "Run"  217,16, 72×32 ---------------------------------------
        _runBtn = new Button { Text = "Run", Location = Dlu.P(217, 16), Size = Dlu.S(72, 32) };
        _runBtn.Click += Run_Click;
 
        // -- 1016  Wrap-mode combo  217,52, 72 wide ---------------------------
        _wrapCombo = new ComboBox
        {
            DropDownStyle = ComboBoxStyle.DropDownList,
            Location      = Dlu.P(217, 52),
            Width         = Dlu.X(72)
        };
        _wrapCombo.Items.AddRange(new object[] { "Intruder", "D3D11", "D3D9", "D3D8", "DDraw" });
        _wrapCombo.SelectedIndex = 0;
 
        // -- 1011  OutDir textbox (read-only)  32,88, 160×12 ------------------
        _outDirTb = new TextBox
        {
            ReadOnly = true,
            Enabled = false,
            Location = Dlu.P(32, 88),
            Width    = Dlu.X(160)
        };
 
        // -- 1006  "..."  195,88, 17×13 ---------------------------------------
        _selOutBtn = new Button { Text = "...", Location = Dlu.P(195, 88), Size = Dlu.S(17, 13) };
        _selOutBtn.Click += SelOut_Click;
 
        // -- 1007  "Browse"  217,88, 72×20 ------------------------------------
        _browseBtn = new Button { Text = "Browse", Location = Dlu.P(217, 88), Size = Dlu.S(72, 20) };
        _browseBtn.Click += (_, __) =>
            NativeApi.ShellExecute(Handle, "open", _s.OutDir, "", "", 1);
 
        // -- 1008  "Don't change the path"  32,106, 112×10 --------------------
        _dontOverwrite = new CheckBox
        {
            Text     = "Don't change the path",
            AutoSize = false,
            Location = Dlu.P(32, 106),
            Size     = Dlu.S(112, 10)
        };
 
        // -- 1012  "Settings"  7,127, 72×20 -----------------------------------
        _settingsBtn = new Button { Text = "Settings", Location = Dlu.P(7, 127), Size = Dlu.S(72, 20) };
        _settingsBtn.Click += (_, __) =>
        {
            using var dlg = new SettingsForm(_s);
            dlg.ShowDialog(this);
        };
 
        // -- 1009  "About / Donate"  140,127, 72×20 ---------------------------
        _aboutBtn = new Button { Text = "About / Donate", Location = Dlu.P(140, 127), Size = Dlu.S(72, 20) };
        _aboutBtn.Click += (_, __) => new AboutForm().ShowDialog(this);
 
        // -- 2  "Exit"  217,127, 72×20 ----------------------------------------
        var exitBtn = new Button { Text = "Exit", Location = Dlu.P(217, 127), Size = Dlu.S(72, 20) };
        exitBtn.Click += (_, __) => Close();
 
        // Add inner controls first, then GroupBoxes last so SendToBack()
        // pushes them behind everything — the correct WinForms Z-order fix.
        Controls.AddRange(new Control[] {
            lblExe, lblArg, lblDir, lblODir,
            _exeTb,    _selExeBtn,
            _argsTb,
            _dirTb,
            _runBtn,   _wrapCombo,
            _outDirTb, _selOutBtn, _browseBtn,
            _dontOverwrite,
            _settingsBtn, _aboutBtn, exitBtn,
            grpOut,
            grpTop
        });
        grpTop.SendToBack();
        grpOut.SendToBack();
 
        ResumeLayout(false);
    }
 
    static Label MakeLbl(string text, int x, int y, int w, int h) =>
        new Label
        {
            Text      = text,
            AutoSize  = false,
            TextAlign = ContentAlignment.MiddleRight,
            Location  = Dlu.P(x, y),
            Size      = Dlu.S(w, h)
        };
 
    // -- State -----------------------------------------------------------------
    void LoadState()
    {
        _s.Load();
        _s.UpdateIntruderDirs();    // also copies DLLs from Intruder & Wrapper (Compiled)\
 
        uint ver = 1 * 10000 + 7 * 1000 + 1;
        if (_s.DonateShowVersion < ver)
        {
            MessageBox.Show(
                "Welcome to Ninja Ripper 1.7.1\n\n" +
                "Due to active user support I've returned to supporting 64-bit game ripping.\n\n" +
                "WANT NEW VERSIONS? Please DONATE – support the development.\n\n" +
                "First time? Read the tutorial first.",
                "Ninja Ripper", MessageBoxButtons.OK, MessageBoxIcon.Information);
            _s.DonateShowVersion = ver;
            _s.Save();
        }
 
        _exeTb.Text    = _s.PrevEXE;
        _argsTb.Text   = _s.PrevArg;
        _dirTb.Text    = _s.PrevDir;
        _outDirTb.Text = _s.OutDir;
        _dontOverwrite.Checked = _s.DontOverwriteOutDir != 0;
    }
 
    void SetExe(string path)
    {
        _exeTb.Text = path;
        string dir  = Path.GetDirectoryName(path) + Path.DirectorySeparatorChar;
        _dirTb.Text = dir;
        if (!_dontOverwrite.Checked)
        {
            _outDirTb.Text = dir;
            _s.OutDir      = dir;
        }
    }
 
    // -- Browse / select handlers -----------------------------------------------
    void SelExe_Click(object s, EventArgs e)
    {
        using var dlg = new OpenFileDialog
        { Filter = "EXE Files|*.exe|All Files|*.*", Title = "Select target EXE" };
        if (dlg.ShowDialog() == DialogResult.OK) SetExe(dlg.FileName);
    }
 
    void SelOut_Click(object s, EventArgs e)
    {
        using var dlg = new FolderBrowserDialog();
        if (dlg.ShowDialog() == DialogResult.OK)
        {
            _s.OutDir      = dlg.SelectedPath;
            _outDirTb.Text = _s.OutDir;
        }
    }
 
    // -- Run -------------------------------------------------------------------
    void Run_Click(object s, EventArgs e)
    {
        string exe  = _exeTb.Text.Trim();
        string args = _argsTb.Text.Trim();
        string dir  = _dirTb.Text.Trim();
 
        if (string.IsNullOrEmpty(exe))
        { Err("Select target EXE"); return; }
        if (!File.Exists(exe))
        { Err("EXE not found"); return; }
        if (!NativeApi.GetBinaryType(exe, out uint bType) ||
            (bType != NativeApi.SCS_32BIT_BINARY && bType != NativeApi.SCS_64BIT_BINARY))
        { Err("Not a valid Win32/64 executable"); return; }
 
        _s.PrevEXE = exe; _s.PrevArg = args; _s.PrevDir = dir;
        _s.DontOverwriteOutDir = (uint)(_dontOverwrite.Checked ? 1 : 0);
        _s.Save();
 
        var mode   = (WrapMode)_wrapCombo.SelectedIndex;
        var inj    = new KInject(_s.IntruderDir32, _s.IntruderDir64);
        string exeDir = Path.GetDirectoryName(exe) + Path.DirectorySeparatorChar;
 
        if (mode == WrapMode.Intruder)
        {
            string clash = KInject.FindWrapperInDir(exeDir);
            if (clash != null)
            {
                Err($"{exeDir}{clash} wrapper detected – delete it manually before using Intruder mode.");
                return;
            }
            var st = inj.CreateAndInject(exe, args, dir);
            if (st != KInject.Status.OK)
                MessageBox.Show(KInject.StatusString(st, inj.Win32Error),
                    "Injection failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
        else
        {
            string srcDir = (bType == NativeApi.SCS_64BIT_BINARY)
                ? _s.IntruderDir64 : _s.IntruderDir32;
 
            string wrapDll = mode switch
            {
                WrapMode.D3D11 => "d3d11.dll",
                WrapMode.D3D9  => "d3d9.dll",
                WrapMode.D3D8  => "d3d8.dll",
                WrapMode.DDraw => "ddraw.dll",
                _              => null
            };
 
            string src = Path.Combine(srcDir, "d3dwrap.dll");
            string dst = Path.Combine(exeDir, wrapDll);
            try { File.Copy(src, dst, true); }
            catch (Exception ex)
            {
                Err($"Wrapper DLL copy error:\n{ex.Message}\n\nTry running as Administrator.");
                return;
            }
            inj.CreateProcess(exe, args, dir);
        }
    }
 
    static void Err(string msg) =>
        MessageBox.Show(msg, "Ninja Ripper", MessageBoxButtons.OK, MessageBoxIcon.Error);
}
 
 
// -----------------------------------------------------------------------------
//  Entry point – GUI or headless command-line injection
// -----------------------------------------------------------------------------
static class Program
{
    [STAThread]
    static void Main(string[] argv)
    {
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
 
        var s = new NRSettings();
        s.Load();
        s.UpdateIntruderDirs();   // copies bundled DLLs on first run
 
        if (argv.Length == 0)
        {
            Application.Run(new MainForm());
        }
        else
        {
            // Headless: BlackRipper.exe target.exe [args]
            string target = argv[0];
            string args   = argv.Length >= 2 ? argv[1] : "";
            var inj = new KInject(s.IntruderDir32, s.IntruderDir64);
            var st  = inj.CreateAndInject(target, args, null);
            if (st != KInject.Status.OK)
                MessageBox.Show(KInject.StatusString(st, inj.Win32Error),
                    "Injection failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }
}
 