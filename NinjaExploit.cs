using System;
using System.IO;
using System.Drawing;
using System.Windows.Forms;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
 
namespace NinjaRipper
{
    // =========================================================================
    //  CONSOLE MANAGER
    // =========================================================================
    static class ConsoleManager
    {
        [DllImport("kernel32.dll")]
        private static extern bool AllocConsole();
 
        [DllImport("kernel32.dll")]
        private static extern IntPtr GetConsoleWindow();
 
        public static void ShowConsole()
        {
            if (GetConsoleWindow() == IntPtr.Zero)
            {
                AllocConsole();
                Console.Title = "NinjaRipper Debug Console";
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("+----------------------------------------+");
                Console.WriteLine("¦    NinjaRipper Debug Console          ¦");
                Console.WriteLine("+----------------------------------------+");
                Console.ResetColor();
                Console.WriteLine();
            }
        }
 
        public static void Log(string message, ConsoleColor color = ConsoleColor.Gray)
        {
            var timestamp = DateTime.Now.ToString("HH:mm:ss.fff");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write($"[{timestamp}] ");
            Console.ForegroundColor = color;
            Console.WriteLine(message);
            Console.ResetColor();
        }
 
        public static void LogSuccess(string message) => Log($"$ {message}", ConsoleColor.Green);
        public static void LogError(string message) => Log($"$ {message}", ConsoleColor.Red);
        public static void LogWarning(string message) => Log($"$  {message}", ConsoleColor.Yellow);
        public static void LogInfo(string message) => Log($"$  {message}", ConsoleColor.Cyan);
    }
 
    // =========================================================================
    //  DEPENDENCY CHECKER
    // =========================================================================
    static class DependencyChecker
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr LoadLibraryW(string lpFileName);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool FreeLibrary(IntPtr hModule);
        
        public static bool CheckSystemDependencies()
        {
            Console.WriteLine();
            ConsoleManager.Log("---------------------------------------", ConsoleColor.Cyan);
            ConsoleManager.LogInfo("Checking system dependencies...");
            ConsoleManager.Log("---------------------------------------", ConsoleColor.Cyan);
            Console.WriteLine();
            
            var requiredDlls = new[]
            {
                ("MSVCR100.dll", "Visual C++ 2010 Runtime"),
                ("MSVCP100.dll", "Visual C++ 2010 Runtime C++"),
            };
            
            bool allFound = true;
            
            ConsoleManager.Log("Checking Visual C++ Runtime DLLs:");
            foreach (var (dll, name) in requiredDlls)
            {
                if (IsDllAvailable(dll))
                {
                    ConsoleManager.LogSuccess($"  {dll} ({name})");
                }
                else
                {
                    ConsoleManager.LogWarning($"  {dll} ({name}) - MISSING");
                    allFound = false;
                }
            }
            
            Console.WriteLine();
            
            if (!allFound)
            {
                ConsoleManager.LogError("+----------------------------------------+");
                ConsoleManager.LogError("¦  MISSING DEPENDENCIES DETECTED!        ¦");
                ConsoleManager.LogError("+----------------------------------------+");
                Console.WriteLine();
                ConsoleManager.LogError("intruder.dll requires Visual C++ Runtime DLLs!");
                ConsoleManager.LogError("Without these, the process WILL crash on DLL load.");
                Console.WriteLine();
                ConsoleManager.LogWarning("SOLUTION:");
                ConsoleManager.LogWarning("  Download and install:");
                ConsoleManager.LogWarning("  Microsoft Visual C++ 2010 Redistributable (x86)");
                ConsoleManager.LogWarning("  Link: https://www.microsoft.com/en-us/download/details.aspx?id=26999");
                Console.WriteLine();
                return false;
            }
            else
            {
                ConsoleManager.LogSuccess("$ All Visual C++ Runtime DLLs found!");
            }
            
            Console.WriteLine();
            return true;
        }
        
        public static bool CheckIntruderDependencies(string dllPath)
        {
            Console.WriteLine();
            ConsoleManager.Log("---------------------------------------", ConsoleColor.Cyan);
            ConsoleManager.LogInfo("Testing intruder.dll load...");
            ConsoleManager.Log("---------------------------------------", ConsoleColor.Cyan);
            Console.WriteLine();
            
            ConsoleManager.Log("Attempting to load intruder.dll...");
            
            IntPtr hModule = LoadLibraryW(dllPath);
            
            if (hModule == IntPtr.Zero)
            {
                var error = Marshal.GetLastWin32Error();
                Console.WriteLine();
                ConsoleManager.LogError("$ FAILED TO LOAD intruder.dll!");
                ConsoleManager.LogError($"Error code: {error}");
                
                string meaning = error switch
                {
                    126 => "ERROR_MOD_NOT_FOUND - Missing dependency DLL!",
                    127 => "ERROR_PROC_NOT_FOUND - Missing exported function",
                    193 => "ERROR_BAD_EXE_FORMAT - Not a valid DLL or wrong architecture",
                    _ => $"Win32 error {error}"
                };
                
                ConsoleManager.LogError($"Meaning: {meaning}");
                
                if (error == 126)
                {
                    Console.WriteLine();
                    ConsoleManager.LogError("+----------------------------------------+");
                    ConsoleManager.LogError("¦  MISSING DEPENDENCY DLL!               ¦");
                    ConsoleManager.LogError("+----------------------------------------+");
                    Console.WriteLine();
                    ConsoleManager.LogError("intruder.dll cannot load - it needs another DLL!");
                    Console.WriteLine();
                    ConsoleManager.LogWarning("DIAGNOSIS TOOL:");
                    ConsoleManager.LogWarning("  Download Dependency Walker:");
                    ConsoleManager.LogWarning("  https://www.dependencywalker.com/");
                    ConsoleManager.LogWarning("  Open intruder.dll and look for RED entries");
                    Console.WriteLine();
                }
                
                Console.WriteLine();
                return false;
            }
            else
            {
                ConsoleManager.LogSuccess("& intruder.dll loaded successfully!");
                ConsoleManager.LogSuccess("& All dependencies are present!");
                FreeLibrary(hModule);
                Console.WriteLine();
                return true;
            }
        }
        
        private static bool IsDllAvailable(string dllName)
        {
            IntPtr hModule = LoadLibraryW(dllName);
            if (hModule != IntPtr.Zero)
            {
                FreeLibrary(hModule);
                return true;
            }
            return false;
        }
    }
 
    // =========================================================================
    //  PROCESS INJECTOR
    // =========================================================================
    static class ProcessInjector
    {
        #region WinAPI
 
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CreateProcess(
            string? lpApplicationName,
            StringBuilder? lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string? lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);
 
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
 
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out IntPtr lpNumberOfBytesWritten);
 
        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
 
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);
 
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr hThread);
 
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);
 
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, IntPtr dwData);
 
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
 
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);
 
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool IsWow64Process(IntPtr hProcess, out bool wow64Process);
 
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct STARTUPINFO
        {
            public uint cb;
            public string? lpReserved;
            public string? lpDesktop;
            public string? lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }
 
        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }
 
        private const uint CREATE_SUSPENDED = 0x00000004;
        private const uint MEM_COMMIT = 0x00001000;
        private const uint MEM_RESERVE = 0x00002000;
        private const uint PAGE_READWRITE = 0x04;
        private const uint WAIT_TIMEOUT = 0x00000102;
        private const uint STILL_ACTIVE = 259;
 
        #endregion
 
        public static bool InjectAndRun(string exePath, string args, string workDir, string outputDir)
        {
            try
            {
                Console.WriteLine();
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("+----------------------------------------+");
                Console.WriteLine("¦      INJECTION SEQUENCE START          ¦");
                Console.WriteLine("+----------------------------------------+");
                Console.ResetColor();
                Console.WriteLine();
                
                ConsoleManager.LogInfo($"Target: {Path.GetFileName(exePath)}");
                ConsoleManager.LogInfo($"Args: {(string.IsNullOrEmpty(args) ? "(none)" : args)}");
                ConsoleManager.LogInfo($"WorkDir: {workDir}");
                ConsoleManager.LogInfo($"OutDir: {outputDir}");
                Console.WriteLine();
                
                CheckExecutableArchitecture(exePath);
                
                var baseDir = AppDomain.CurrentDomain.BaseDirectory;
                var intruderDll = Path.Combine(baseDir, "intruder.dll");
                
                ConsoleManager.Log("Searching for intruder.dll...");
                ConsoleManager.LogInfo($"Location: {baseDir}");
                
                if (!File.Exists(intruderDll))
                {
                    Console.WriteLine();
                    ConsoleManager.LogError("intruder.dll NOT FOUND!");
                    ConsoleManager.LogInfo($"Expected at: {intruderDll}");
                    Console.WriteLine();
                    return false;
                }
                
                var fileInfo = new FileInfo(intruderDll);
                Console.WriteLine();
                ConsoleManager.LogSuccess("DLL FOUND!");
                ConsoleManager.LogInfo($"Size: {fileInfo.Length:N0} bytes");
                ConsoleManager.LogInfo($"Modified: {fileInfo.LastWriteTime:yyyy-MM-dd HH:mm:ss}");
                
                CheckDllArchitecture(intruderDll);
                
                // RUN DEPENDENCY CHECKS!
                bool depsOk = DependencyChecker.CheckSystemDependencies();
                bool loadOk = DependencyChecker.CheckIntruderDependencies(intruderDll);
                
                if (!depsOk || !loadOk)
                {
                    Console.WriteLine();
                    ConsoleManager.LogWarning("+----------------------------------------+");
                    ConsoleManager.LogWarning("¦  DEPENDENCY ISSUES DETECTED!           ¦");
                    ConsoleManager.LogWarning("+----------------------------------------+");
                    ConsoleManager.LogWarning("Injection will likely FAIL!");
                    Console.WriteLine();
                    ConsoleManager.LogInfo("Press any key to continue anyway (or close this window to abort)...");
                    Console.ReadKey();
                    Console.WriteLine();
                }
 
                CreateOutputDirectoryStructure(outputDir);
 
                var commandLine = new StringBuilder();
                if (!string.IsNullOrEmpty(args))
                    commandLine.Append($"\"{exePath}\" {args}");
                else
                    commandLine.Append($"\"{exePath}\"");
 
                if (string.IsNullOrEmpty(workDir) || !Directory.Exists(workDir))
                    workDir = Path.GetDirectoryName(exePath) ?? "";
 
                var si = new STARTUPINFO { cb = (uint)Marshal.SizeOf(typeof(STARTUPINFO)) };
 
                Console.WriteLine();
                ConsoleManager.Log("Creating suspended process...");
                
                bool success = CreateProcess(
                    null, commandLine, IntPtr.Zero, IntPtr.Zero, false,
                    CREATE_SUSPENDED, IntPtr.Zero, workDir, ref si, out var pi);
 
                if (!success)
                {
                    var error = Marshal.GetLastWin32Error();
                    Console.WriteLine();
                    ConsoleManager.LogError("CreateProcess FAILED!");
                    ConsoleManager.LogError($"Error code: {error}");
                    ConsoleManager.LogError($"Error: {new System.ComponentModel.Win32Exception(error).Message}");
                    return false;
                }
                
                Console.WriteLine();
                ConsoleManager.LogSuccess("Process created!");
                ConsoleManager.LogInfo($"PID: {pi.dwProcessId}");
                ConsoleManager.LogInfo($"TID: {pi.dwThreadId}");
                
                CheckProcessArchitecture(pi.hProcess, pi.dwProcessId);
 
                try
                {
                    Console.WriteLine();
                    ConsoleManager.Log("Injecting DLL...");
                    InjectDllViaAPC(pi.hProcess, pi.hThread, intruderDll);
                    
                    Console.WriteLine();
                    ConsoleManager.LogSuccess("DLL injection queued!");
                    ConsoleManager.LogInfo("Method: LoadLibrary via APC");
                    
                    Console.WriteLine();
                    ConsoleManager.Log("Resuming main thread...");
                    ResumeThread(pi.hThread);
                    
                    Console.WriteLine();
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("+----------------------------------------+");
                    Console.WriteLine("¦     ? INJECTION SUCCESSFUL!            ¦");
                    Console.WriteLine("+----------------------------------------+");
                    Console.ResetColor();
                    Console.WriteLine();
                    
                    ConsoleManager.LogSuccess("DirectX hooks should now be active!");
                    ConsoleManager.LogInfo("Press F10 in-game to capture meshes");
                    ConsoleManager.LogInfo("Press F9 in-game to capture textures");
                    Console.WriteLine();
                    ConsoleManager.LogInfo("Output folder:");
                    ConsoleManager.LogInfo($"  {outputDir}\\_Ripper\\");
                    Console.WriteLine();
                    
                    // EXTENDED MONITORING (5 seconds instead of 500ms)
                    MonitorProcess(pi.hProcess, pi.dwProcessId);
                    
                    return true;
                }
                finally
                {
                    CloseHandle(pi.hThread);
                    CloseHandle(pi.hProcess);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine();
                ConsoleManager.LogError("EXCEPTION during injection!");
                ConsoleManager.LogError($"Type: {ex.GetType().Name}");
                ConsoleManager.LogError($"Message: {ex.Message}");
                ConsoleManager.Log(ex.StackTrace ?? "", ConsoleColor.DarkRed);
                return false;
            }
        }
 
        private static void CheckExecutableArchitecture(string exePath)
        {
            try
            {
                ConsoleManager.Log("Checking target executable architecture...");
                
                using var stream = new FileStream(exePath, FileMode.Open, FileAccess.Read);
                using var reader = new BinaryReader(stream);
                
                stream.Seek(0x3C, SeekOrigin.Begin);
                int peHeaderOffset = reader.ReadInt32();
                
                stream.Seek(peHeaderOffset, SeekOrigin.Begin);
                uint peSignature = reader.ReadUInt32();
                
                if (peSignature != 0x00004550)
                {
                    ConsoleManager.LogWarning("Invalid PE signature");
                    return;
                }
                
                ushort machine = reader.ReadUInt16();
                
                string arch = machine switch
                {
                    0x014c => "x86 (32-bit)",
                    0x8664 => "x64 (64-bit)",
                    _ => $"Unknown (0x{machine:X4})"
                };
                
                ConsoleManager.LogInfo($"Target architecture: {arch}");
                
                if (machine == 0x8664)
                {
                    ConsoleManager.LogWarning("$  TARGET IS 64-BIT!");
                    ConsoleManager.LogWarning("$  Original intruder.dll is 32-bit!");
                    ConsoleManager.LogWarning("$  DLL will NOT load - architecture mismatch!");
                    Console.WriteLine();
                }
            }
            catch (Exception ex)
            {
                ConsoleManager.LogWarning($"Failed to check architecture: {ex.Message}");
            }
        }
 
        private static void CheckDllArchitecture(string dllPath)
        {
            try
            {
                using var stream = new FileStream(dllPath, FileMode.Open, FileAccess.Read);
                using var reader = new BinaryReader(stream);
                
                stream.Seek(0x3C, SeekOrigin.Begin);
                int peHeaderOffset = reader.ReadInt32();
                
                stream.Seek(peHeaderOffset + 4, SeekOrigin.Begin);
                ushort machine = reader.ReadUInt16();
                
                string arch = machine switch
                {
                    0x014c => "x86 (32-bit)",
                    0x8664 => "x64 (64-bit)",
                    _ => $"Unknown (0x{machine:X4})"
                };
                
                ConsoleManager.LogInfo($"DLL architecture: {arch}");
                Console.WriteLine();
            }
            catch (Exception ex)
            {
                ConsoleManager.LogWarning($"Failed to check DLL architecture: {ex.Message}");
            }
        }
 
        private static void CheckProcessArchitecture(IntPtr hProcess, uint pid)
        {
            try
            {
                bool isWow64 = false;
                if (IsWow64Process(hProcess, out isWow64))
                {
                    string processArch = isWow64 ? "32-bit (WOW64)" : 
                        (Environment.Is64BitOperatingSystem ? "64-bit" : "32-bit");
                    ConsoleManager.LogInfo($"Process architecture: {processArch}");
                }
            }
            catch (Exception ex)
            {
                ConsoleManager.LogWarning($"Failed to check process architecture: {ex.Message}");
            }
        }
 
        private static void MonitorProcess(IntPtr hProcess, uint pid)
        {
            Console.WriteLine();
            ConsoleManager.Log("---------------------------------------", ConsoleColor.Cyan);
            ConsoleManager.LogInfo("MONITORING: Watching process for 5 seconds...");
            ConsoleManager.Log("---------------------------------------", ConsoleColor.Cyan);
            Console.WriteLine();
            
            bool windowFound = false;
            bool processExited = false;
            
            // Monitor for 5 seconds (50 checks at 100ms each)
            for (int i = 0; i < 50; i++)
            {
                Thread.Sleep(100);
                
                uint waitResult = WaitForSingleObject(hProcess, 0);
                
                if (waitResult != WAIT_TIMEOUT)
                {
                    processExited = true;
                    
                    Console.WriteLine();
                    ConsoleManager.LogError($"$ PROCESS EXITED at {(i + 1) * 100}ms!");
                    
                    if (GetExitCodeProcess(hProcess, out uint exitCode))
                    {
                        if (exitCode == STILL_ACTIVE)
                        {
                            ConsoleManager.LogWarning("Exit code reports STILL_ACTIVE");
                        }
                        else
                        {
                            ConsoleManager.LogError($"Exit code: 0x{exitCode:X8} ({exitCode})");
                            
                            string meaning = exitCode switch
                            {
                                0xC0000005 => "ACCESS_VIOLATION - Crash/Bad memory access",
                                0xC0000135 => "DLL_NOT_FOUND - Missing dependency DLL",
                                0xC000007B => "INVALID_IMAGE_FORMAT - 32/64-bit mismatch!",
                                0xC0000142 => "DLL_INIT_FAILED - DLL initialization failed",
                                0xC0000409 => "STACK_BUFFER_OVERRUN - Stack corruption",
                                0 => "SUCCESS - Normal exit",
                                1 => "ERROR - General error",
                                _ => "Unknown error code"
                            };
                            
                            ConsoleManager.LogError($"Meaning: {meaning}");
                            
                            Console.WriteLine();
                            ConsoleManager.LogError("+----------------------------------------+");
                            ConsoleManager.LogError("¦  PROCESS DIED AFTER INJECTION!         ¦");
                            ConsoleManager.LogError("+----------------------------------------+");
                            
                            if (exitCode == 0xC0000142)
                            {
                                Console.WriteLine();
                                ConsoleManager.LogError("DLL_INIT_FAILED - This means:");
                                ConsoleManager.LogError("  • intruder.dll loaded");
                                ConsoleManager.LogError("  • But DllMain CRASHED or returned FALSE");
                                Console.WriteLine();
                                ConsoleManager.LogWarning("SOLUTIONS:");
                                ConsoleManager.LogWarning("  1. Install VC++ 2010 Redistributable (x86)");
                                ConsoleManager.LogWarning("  2. Check Event Viewer for crash details");
                                ConsoleManager.LogWarning("  3. Use Dependency Walker on intruder.dll");
                            }
                            else if (exitCode == 0xC0000135)
                            {
                                Console.WriteLine();
                                ConsoleManager.LogError("DLL_NOT_FOUND - Missing dependency!");
                                ConsoleManager.LogWarning("Install VC++ 2010 Redistributable (x86)");
                            }
                        }
                    }
                    
                    break;
                }
                
                // Check for window every second
                if ((i + 1) % 10 == 0)
                {
                    try
                    {
                        var process = Process.GetProcessById((int)pid);
                        
                        if (process.MainWindowHandle != IntPtr.Zero && !windowFound)
                        {
                            windowFound = true;
                            Console.WriteLine();
                            ConsoleManager.LogSuccess($"& WINDOW APPEARED at {(i + 1) * 100}ms!");
                            ConsoleManager.LogInfo($"Window title: '{process.MainWindowTitle}'");
                            ConsoleManager.LogSuccess("Demo is running normally!");
                            Console.WriteLine();
                            break;
                        }
                        else if ((i + 1) % 10 == 0)
                        {
                            ConsoleManager.Log($"  {(i + 1) * 100}ms - Process alive, no window yet", ConsoleColor.Gray);
                        }
                    }
                    catch (ArgumentException)
                    {
                        processExited = true;
                        Console.WriteLine();
                        ConsoleManager.LogError($"$ Process vanished at {(i + 1) * 100}ms!");
                        break;
                    }
                }
                else if (i < 10)
                {
                    ConsoleManager.Log($"  {(i + 1) * 100}ms - Process alive", ConsoleColor.Green);
                }
            }
            
            Console.WriteLine();
            
            if (!processExited && !windowFound)
            {
                ConsoleManager.LogWarning("$  5 seconds elapsed - Process alive but NO WINDOW");
                ConsoleManager.LogInfo($"Check Task Manager for PID {pid}");
            }
            else if (windowFound)
            {
                ConsoleManager.LogSuccess("---------------------------------------");
                ConsoleManager.LogSuccess("  DEMO IS RUNNING SUCCESSFULLY!       ");
                ConsoleManager.LogSuccess("---------------------------------------");
            }
            else if (processExited)
            {
                ConsoleManager.LogError("---------------------------------------");
                ConsoleManager.LogError("  DEMO CRASHED/EXITED AFTER INJECTION  ");
                ConsoleManager.LogError("---------------------------------------");
            }
            
            Console.WriteLine();
        }
 
        private static void CreateOutputDirectoryStructure(string outputDir)
        {
            try
            {
                if (!Directory.Exists(outputDir))
                    Directory.CreateDirectory(outputDir);
                
                var ripperDir = Path.Combine(outputDir, "_Ripper");
                if (!Directory.Exists(ripperDir))
                    Directory.CreateDirectory(ripperDir);
            }
            catch { }
        }
 
        private static void InjectDllViaAPC(IntPtr hProcess, IntPtr hThread, string dllPath)
        {
            IntPtr kernel32 = GetModuleHandle("kernel32.dll");
            if (kernel32 == IntPtr.Zero)
                throw new Exception("Failed to get kernel32.dll handle");
                
            IntPtr loadLibrary = GetProcAddress(kernel32, "LoadLibraryA");
            if (loadLibrary == IntPtr.Zero)
                throw new Exception("Failed to get LoadLibraryA address");
 
            ConsoleManager.LogInfo($"kernel32.dll: 0x{kernel32.ToInt64():X}");
            ConsoleManager.LogInfo($"LoadLibraryA: 0x{loadLibrary.ToInt64():X}");
 
            byte[] dllBytes = Encoding.ASCII.GetBytes(dllPath + "\0");
            IntPtr allocMem = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)dllBytes.Length,
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
 
            if (allocMem == IntPtr.Zero)
                throw new Exception($"VirtualAllocEx failed! Error: {Marshal.GetLastWin32Error()}");
            
            ConsoleManager.LogInfo($"Allocated: 0x{allocMem.ToInt64():X} ({dllBytes.Length} bytes)");
 
            if (!WriteProcessMemory(hProcess, allocMem, dllBytes, (uint)dllBytes.Length, out _))
                throw new Exception($"WriteProcessMemory failed! Error: {Marshal.GetLastWin32Error()}");
            
            ConsoleManager.LogInfo("Wrote DLL path to process memory");
 
            QueueUserAPC(loadLibrary, hThread, allocMem);
            ConsoleManager.LogInfo("Queued APC call");
        }
    }
 
    // =========================================================================
    //  UI LAYOUT CONSTANTS - EXACT COORDINATES
    // =========================================================================
    static class UI
    {
        public const int FormWidth  = 456;
        public const int FormHeight = 289;
        public const int TargetGroupX      = 11;
        public const int TargetGroupY      = 11;
        public const int TargetGroupWidth  = 317;
        public const int TargetGroupHeight = 104;
        public const int ExeLabelX        = 19;
        public const int ExeLabelY        = 37;
        public const int ExeBoxX          = 50;
        public const int ExeBoxY          = 33;
        public const int ExeBoxWidth      = 238;
        public const int ExeBoxHeight     = 20;
        public const int ExeDotX          = 292;
        public const int ExeDotY          = 32;
        public const int ExeDotWidth      = 27;
        public const int ExeDotHeight     = 22;
        public const int ArgLabelX        = 19;
        public const int ArgLabelY        = 63;
        public const int ArgBoxX          = 50;
        public const int ArgBoxY          = 59;
        public const int ArgBoxWidth      = 268;
        public const int ArgBoxHeight     = 20;
        public const int DirLabelX        = 19;
        public const int DirLabelY        = 89;
        public const int DirBoxX          = 50;
        public const int DirBoxY          = 85;
        public const int DirBoxWidth      = 268;
        public const int DirBoxHeight     = 20;
        public const int RunGroupX        = 335;
        public const int RunGroupY        = 11;
        public const int RunGroupWidth    = 107;
        public const int RunGroupHeight   = 104;
        public const int RunButtonX       = 341;
        public const int RunButtonY       = 24;
        public const int RunButtonWidth   = 94;
        public const int RunButtonHeight  = 53;
        public const int ModeComboX       = 342;
        public const int ModeComboY       = 85;
        public const int ModeComboWidth   = 92;
        public const int ModeComboHeight  = 21;
        public const int OutputGroupX      = 11;
        public const int OutputGroupY      = 119;
        public const int OutputGroupWidth  = 431;
        public const int OutputGroupHeight = 79;
        public const int OutputDirLabelX   = 23;
        public const int OutputDirLabelY   = 143;
        public const int OutputDirBoxX     = 50;
        public const int OutputDirBoxY     = 142;
        public const int OutputDirBoxWidth = 238;
        public const int OutputDirBoxHeight= 20;
        public const int OutputDotX        = 292;
        public const int OutputDotY        = 141;
        public const int OutputDotWidth    = 27;
        public const int OutputDotHeight   = 22;
        public const int BrowseButtonX     = 341;
        public const int BrowseButtonY     = 141;
        public const int BrowseButtonWidth = 94;
        public const int BrowseButtonHeight= 42;
        public const int DontChangeX       = 50;
        public const int DontChangeY       = 168;
        public const int DontChangeWidth   = 160;
        public const int DontChangeHeight  = 17;
        public const int SettingsGroupX      = 11;
        public const int SettingsGroupY      = 202;
        public const int SettingsGroupWidth  = 317;
        public const int SettingsGroupHeight = 65;
        public const int RipLabelX          = 18;
        public const int RipLabelY          = 233;
        public const int RipComboX          = 44;
        public const int RipComboY          = 230;
        public const int RipComboWidth      = 49;
        public const int RipComboHeight     = 20;
        public const int ForcedGroupX       = 107;
        public const int ForcedGroupY       = 210;
        public const int ForcedGroupWidth   = 125;
        public const int ForcedGroupHeight  = 50;
        public const int TexturesLabelX     = 112;
        public const int TexturesLabelY     = 233;
        public const int TexturesComboX     = 168;
        public const int TexturesComboY     = 230;
        public const int TexturesComboWidth = 49;
        public const int TexturesComboHeight= 20;
        public const int AboutButtonX       = 341;
        public const int AboutButtonY       = 207;
        public const int AboutButtonWidth   = 94;
        public const int AboutButtonHeight  = 29;
        public const int ExitButtonX        = 341;
        public const int ExitButtonY        = 238;
        public const int ExitButtonWidth    = 94;
        public const int ExitButtonHeight   = 29;
    }
 
    // =========================================================================
    //  Config
    // =========================================================================
    static class Config
    {
        private const string RegKey = @"Software\black_ninja\NinjaRipper";
 
        public static (string Exe, string Dir) Load()
        {
            try
            {
                using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(RegKey);
                if (key == null) return (string.Empty, string.Empty);
                return (key.GetValue("Exe") as string ?? string.Empty, 
                        key.GetValue("Dir") as string ?? string.Empty);
            }
            catch { return (string.Empty, string.Empty); }
        }
 
        public static void Save(string exe, string dir)
        {
            try
            {
                using var key = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(RegKey, writable: true);
                key.SetValue("Exe", exe);
                key.SetValue("Dir", dir);
            }
            catch { }
        }
    }
 
    // =========================================================================
    //  Entry point
    // =========================================================================
    static class Program
    {
        [STAThread]
        static void Main()
        {
            ConsoleManager.ShowConsole();
            ConsoleManager.LogSuccess("NinjaRipper Started!");
            ConsoleManager.LogInfo($"Version: 1.1.2 (DirectX 9 Focused)");
            ConsoleManager.LogInfo($"Date: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            Console.WriteLine();
            
            var dllPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "intruder.dll");
            if (File.Exists(dllPath))
            {
                var fi = new FileInfo(dllPath);
                ConsoleManager.LogSuccess("intruder.dll detected!");
                ConsoleManager.LogInfo($"Size: {fi.Length:N0} bytes");
                ConsoleManager.LogInfo($"Modified: {fi.LastWriteTime:yyyy-MM-dd HH:mm:ss}");
            }
            else
            {
                ConsoleManager.LogWarning("WARNING: intruder.dll NOT FOUND!");
                ConsoleManager.LogInfo("Place intruder.dll in same folder as NinjaRipper.exe");
            }
            Console.WriteLine();
            ConsoleManager.LogSuccess("Ready! Select a target and click Run.");
            Console.WriteLine();
            
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm());
            
            Console.WriteLine();
            ConsoleManager.LogInfo("Application closed. Press any key to exit...");
            Console.ReadKey();
        }
    }
 
    // =========================================================================
    //  About Dialog
    // =========================================================================
    sealed class AboutForm : Form
    {
        public AboutForm()
        {
            Text = "About / Donate";
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            MinimizeBox = false;
            ShowInTaskbar = false;
            StartPosition = FormStartPosition.CenterParent;
            ClientSize = new Size(292, 210);
            Font = new Font("Microsoft Sans Serif", 8);
 
            Controls.Add(new Label
            {
                Text = "Ninja Ripper 1.1.2",
                Font = new Font("Microsoft Sans Serif", 9f, FontStyle.Bold),
                TextAlign = ContentAlignment.MiddleCenter,
                Bounds = new Rectangle(0, 10, 292, 18)
            });
 
            var authorLabel = new LinkLabel
            {
                Text = "Author:  black_ninja  (c) 2004-2012",
                TextAlign = ContentAlignment.MiddleCenter,
                Bounds = new Rectangle(0, 34, 292, 16)
            };
            authorLabel.Links.Clear();
            authorLabel.Links.Add(9, 11, "https://cgig.ru");
            authorLabel.LinkClicked += OnLinkClicked;
            Controls.Add(authorLabel);
 
            var homeLabel = new LinkLabel
            {
                Text = "Home:  cgig.ru/ninjaripper",
                TextAlign = ContentAlignment.MiddleCenter,
                Bounds = new Rectangle(0, 54, 292, 16)
            };
            homeLabel.Links.Clear();
            homeLabel.Links.Add(7, 19, "https://cgig.ru/ninjaripper/");
            homeLabel.LinkClicked += OnLinkClicked;
            Controls.Add(homeLabel);
 
            var okButton = new Button
            {
                Text = "OK",
                DialogResult = DialogResult.OK,
                Bounds = new Rectangle(106, 170, 80, 26)
            };
            Controls.Add(okButton);
            AcceptButton = okButton;
        }
 
        private static void OnLinkClicked(object? sender, LinkLabelLinkClickedEventArgs e)
        {
            if (e.Link?.LinkData is string url)
            {
                try { Process.Start(new ProcessStartInfo { FileName = url, UseShellExecute = true }); }
                catch { }
            }
        }
    }
 
    // =========================================================================
    //  MainForm
    // =========================================================================
    sealed class MainForm : Form
    {
        private readonly TextBox _exeBox, _argBox, _dirBox, _outputDirBox;
        private readonly ComboBox _ripCombo, _texturesCombo;
 
        public MainForm()
        {
            Text = "Ninja Ripper 1.1.2";
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            StartPosition = FormStartPosition.CenterScreen;
            ClientSize = new Size(UI.FormWidth, UI.FormHeight);
            Font = new Font("Microsoft Sans Serif", 8);
 
            var tip = new ToolTip();
 
            Controls.Add(MakeLabel("Exe", UI.ExeLabelX, UI.ExeLabelY));
            _exeBox = MakeTextBox(UI.ExeBoxX, UI.ExeBoxY, UI.ExeBoxWidth, UI.ExeBoxHeight);
            _exeBox.Enabled = false;
            Controls.Add(_exeBox);
 
            var exeDot = MakeDotButton(UI.ExeDotX, UI.ExeDotY, UI.ExeDotWidth, UI.ExeDotHeight);
            exeDot.Click += (_, _) => PickExecutable();
            Controls.Add(exeDot);
            tip.SetToolTip(exeDot, "Select target executable");
 
            Controls.Add(MakeLabel("Arg", UI.ArgLabelX, UI.ArgLabelY));
            _argBox = MakeTextBox(UI.ArgBoxX, UI.ArgBoxY, UI.ArgBoxWidth, UI.ArgBoxHeight);
            Controls.Add(_argBox);
 
            Controls.Add(MakeLabel("Dir", UI.DirLabelX, UI.DirLabelY));
            _dirBox = MakeTextBox(UI.DirBoxX, UI.DirBoxY, UI.DirBoxWidth, UI.DirBoxHeight);
            Controls.Add(_dirBox);
 
            var runButton = MakeButton("Run", UI.RunButtonX, UI.RunButtonY, UI.RunButtonWidth, UI.RunButtonHeight);
            runButton.Font = new Font("Microsoft Sans Serif", 13f, FontStyle.Bold);
            runButton.Click += RunButton_Click;
            Controls.Add(runButton);
 
            var modeCombo = new ComboBox
            {
                DropDownStyle = ComboBoxStyle.DropDownList,
                Bounds = new Rectangle(UI.ModeComboX, UI.ModeComboY, UI.ModeComboWidth, UI.ModeComboHeight)
            };
            modeCombo.Items.Add("Intruder (Rec.)");
            modeCombo.SelectedIndex = 0;
            Controls.Add(modeCombo);
 
            Controls.Add(MakeLabel("Dir", UI.OutputDirLabelX, UI.OutputDirLabelY));
            _outputDirBox = MakeTextBox(UI.OutputDirBoxX, UI.OutputDirBoxY,
                                        UI.OutputDirBoxWidth, UI.OutputDirBoxHeight);
            _outputDirBox.Enabled = false;
            _outputDirBox.Text = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "NinjaRipper");
            Controls.Add(_outputDirBox);
 
            var outputDot = MakeDotButton(UI.OutputDotX, UI.OutputDotY, UI.OutputDotWidth, UI.OutputDotHeight);
            outputDot.Click += (_, _) => PickOutputFolder();
            Controls.Add(outputDot);
 
            var browseButton = MakeButton("Browse", UI.BrowseButtonX, UI.BrowseButtonY,
                UI.BrowseButtonWidth, UI.BrowseButtonHeight);
            browseButton.Click += (_, _) => OpenExplorer(_outputDirBox.Text);
            Controls.Add(browseButton);
 
            Controls.Add(new CheckBox
            {
                Text = "Don't change the path",
                Checked = true,
                Bounds = new Rectangle(UI.DontChangeX, UI.DontChangeY, UI.DontChangeWidth, UI.DontChangeHeight)
            });
 
            Controls.Add(MakeLabel("RIP", UI.RipLabelX, UI.RipLabelY));
            _ripCombo = MakeFKeyCombo(UI.RipComboX, UI.RipComboY, UI.RipComboWidth, "F10");
            Controls.Add(_ripCombo);
 
            Controls.Add(MakeLabel("Textures", UI.TexturesLabelX, UI.TexturesLabelY));
            _texturesCombo = MakeFKeyCombo(UI.TexturesComboX, UI.TexturesComboY,
                                           UI.TexturesComboWidth, "F9");
            Controls.Add(_texturesCombo);
 
            var aboutButton = MakeButton("About / Donate", UI.AboutButtonX, UI.AboutButtonY,
                UI.AboutButtonWidth, UI.AboutButtonHeight);
            aboutButton.Click += (_, _) => { using var d = new AboutForm(); d.ShowDialog(this); };
            Controls.Add(aboutButton);
 
            var exitButton = MakeButton("Exit", UI.ExitButtonX, UI.ExitButtonY,
                UI.ExitButtonWidth, UI.ExitButtonHeight);
            exitButton.Click += (_, _) => Application.Exit();
            Controls.Add(exitButton);
 
            AddAllGroupBoxes();
 
            var (exe, dir) = Config.Load();
            if (!string.IsNullOrEmpty(exe))
            {
                _exeBox.Text = exe;
                _dirBox.Text = dir;
            }
        }
 
        private void AddAllGroupBoxes()
        {
            Controls.Add(new GroupBox { Text = "Target ( DX8, DX9, DX11 application )",
                Bounds = new Rectangle(UI.TargetGroupX, UI.TargetGroupY, UI.TargetGroupWidth, UI.TargetGroupHeight) });
            Controls.Add(new GroupBox { Text = string.Empty,
                Bounds = new Rectangle(UI.RunGroupX, UI.RunGroupY, UI.RunGroupWidth, UI.RunGroupHeight) });
            Controls.Add(new GroupBox { Text = "Output Directory",
                Bounds = new Rectangle(UI.OutputGroupX, UI.OutputGroupY, UI.OutputGroupWidth, UI.OutputGroupHeight) });
            Controls.Add(new GroupBox { Text = "Forced to save",
                Bounds = new Rectangle(UI.ForcedGroupX, UI.ForcedGroupY, UI.ForcedGroupWidth, UI.ForcedGroupHeight) });
            Controls.Add(new GroupBox { Text = "Settings",
                Bounds = new Rectangle(UI.SettingsGroupX, UI.SettingsGroupY, UI.SettingsGroupWidth, UI.SettingsGroupHeight) });
        }
 
        private static Label MakeLabel(string text, int x, int y) 
            => new Label { Text = text, Location = new Point(x, y), AutoSize = true };
 
        private static TextBox MakeTextBox(int x, int y, int width, int height)
            => new TextBox { Bounds = new Rectangle(x, y, width, height) };
 
        private static Button MakeButton(string text, int x, int y, int width, int height)
            => new Button { Text = text, Bounds = new Rectangle(x, y, width, height), FlatStyle = FlatStyle.System };
 
        private static Button MakeDotButton(int x, int y, int width, int height)
            => new Button { Text = "...", Bounds = new Rectangle(x, y, width, height), FlatStyle = FlatStyle.System };
 
        private static ComboBox MakeFKeyCombo(int x, int y, int width, string defaultKey)
        {
            var combo = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Bounds = new Rectangle(x, y, width, 21) };
            for (int i = 1; i <= 12; i++) combo.Items.Add($"F{i}");
            combo.SelectedItem = defaultKey;
            return combo;
        }
 
        private void PickExecutable()
        {
            using var d = new OpenFileDialog { Title = "Select target executable", Filter = "EXE Files (*.exe)|*.exe|All Files (*.*)|*.*" };
            if (d.ShowDialog(this) != DialogResult.OK) return;
            _exeBox.Text = d.FileName;
            _dirBox.Text = Path.GetDirectoryName(d.FileName) ?? string.Empty;
            Config.Save(_exeBox.Text, _dirBox.Text);
            
            ConsoleManager.LogSuccess($"Target selected: {Path.GetFileName(d.FileName)}");
            ConsoleManager.LogInfo($"Path: {d.FileName}");
            Console.WriteLine();
        }
 
        private void PickOutputFolder()
        {
            using var d = new FolderBrowserDialog { Description = "Select output directory", SelectedPath = _outputDirBox.Text, AutoUpgradeEnabled = false };
            if (d.ShowDialog(this) == DialogResult.OK)
            {
                _outputDirBox.Text = d.SelectedPath;
                ConsoleManager.LogSuccess($"Output directory set: {d.SelectedPath}");
                Console.WriteLine();
            }
        }
 
        private static void OpenExplorer(string path)
        {
            string target = Directory.Exists(path) ? path : Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            try
            {
                Process.Start(new ProcessStartInfo { FileName = "explorer.exe", Arguments = $"\"{target}\"", UseShellExecute = true });
                ConsoleManager.LogInfo("Opened output folder in Explorer");
            }
            catch { }
        }
 
        private void RunButton_Click(object? sender, EventArgs e)
        {
            if (string.IsNullOrWhiteSpace(_exeBox.Text))
            {
                ConsoleManager.LogWarning("No target selected!");
                MessageBox.Show("Please select a target executable.", Text, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            
            if (!File.Exists(_exeBox.Text))
            {
                ConsoleManager.LogError("Target file not found!");
                MessageBox.Show("The selected executable does not exist.", Text, MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            
            Config.Save(_exeBox.Text, _dirBox.Text);
            ProcessInjector.InjectAndRun(_exeBox.Text, _argBox.Text, _dirBox.Text, _outputDirBox.Text);
        }
    }
}
 
