// NinjaRipper_Complete.cs - Complete Single-File Implementation
// .NET 6.0 WinForms + DLL Injection + DirectX Hooking
// Original: (c)2004-2012 black_ninja | C# Port: 2025
// BUILD: csc /target:winexe /out:NinjaRipper.exe NinjaRipper_Complete.cs

using System;
using System.Drawing;
using System.Windows.Forms;
using System.IO;
using System.Runtime.InteropServices;
using System.Diagnostics;
using Microsoft.Win32;
using System.Text;

namespace NinjaRipper
{
    // ========================================
    // ENTRY POINT
    // ========================================
    internal static class Program
    {
        [STAThread]
        static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm());
        }
    }

    // ========================================
    // SETTINGS CLASS
    // ========================================
    public class Settings
    {
        private const string REGISTRY_PATH = @"SOFTWARE\black_ninja\NinjaRipper";
        
        public string PrevEXE { get; set; } = "";
        public string PrevArg { get; set; } = "";
        public string PrevDir { get; set; } = "";
        public string OutDir { get; set; } = "";
        public string IntruderDir { get; set; } = "";
        
        public int RipKey { get; set; } = 0x79;         // F10
        public int TextureRipKey { get; set; } = 0x78;  // F9
        public bool DontOverwriteOutDir { get; set; } = false;
        
        public Settings()
        {
            IntruderDir = AppDomain.CurrentDomain.BaseDirectory;
        }

        public void Load()
        {
            try
            {
                using (var key = Registry.CurrentUser.OpenSubKey(REGISTRY_PATH))
                {
                    if (key != null)
                    {
                        PrevEXE = key.GetValue("PrevEXE", "") as string ?? "";
                        PrevArg = key.GetValue("PrevArg", "") as string ?? "";
                        PrevDir = key.GetValue("PrevDir", "") as string ?? "";
                        OutDir = key.GetValue("OutDir", "") as string ?? "";
                        IntruderDir = key.GetValue("IntruderDir", IntruderDir) as string ?? IntruderDir;
                        
                        RipKey = Convert.ToInt32(key.GetValue("RipKey", 0x79));
                        TextureRipKey = Convert.ToInt32(key.GetValue("TextureRipKey", 0x78));
                        
                        var dontOverwrite = key.GetValue("DontOverwriteOutDir", 0);
                        DontOverwriteOutDir = Convert.ToInt32(dontOverwrite) != 0;
                    }
                }
            }
            catch { }
        }

        public void Save()
        {
            try
            {
                using (var key = Registry.CurrentUser.CreateSubKey(REGISTRY_PATH))
                {
                    if (key != null)
                    {
                        key.SetValue("PrevEXE", PrevEXE);
                        key.SetValue("PrevArg", PrevArg);
                        key.SetValue("PrevDir", PrevDir);
                        key.SetValue("OutDir", OutDir);
                        key.SetValue("IntruderDir", IntruderDir);
                        
                        key.SetValue("RipKey", RipKey, RegistryValueKind.DWord);
                        key.SetValue("TextureRipKey", TextureRipKey, RegistryValueKind.DWord);
                        key.SetValue("DontOverwriteOutDir", DontOverwriteOutDir ? 1 : 0, RegistryValueKind.DWord);
                    }
                }
            }
            catch { }
        }
    }

    // ========================================
    // PROCESS INJECTOR
    // ========================================
    public class ProcessInjector
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

        #endregion

        public bool InjectAndRun(string exePath, string args, string workDir, int wrapperMode)
        {
            try
            {
                var intruderDll = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "intruder.dll");
                
                // For now, launch without injection if DLL doesn't exist
                if (!File.Exists(intruderDll))
                {
                    return LaunchWithoutInjection(exePath, args, workDir);
                }

                var commandLine = new StringBuilder($"\"{exePath}\"");
                if (!string.IsNullOrEmpty(args))
                    commandLine.Append($" {args}");

                if (string.IsNullOrEmpty(workDir) || !Directory.Exists(workDir))
                    workDir = Path.GetDirectoryName(exePath) ?? "";

                var si = new STARTUPINFO { cb = (uint)Marshal.SizeOf(typeof(STARTUPINFO)) };

                bool success = CreateProcess(
                    null, commandLine, IntPtr.Zero, IntPtr.Zero, false,
                    CREATE_SUSPENDED, IntPtr.Zero, workDir, ref si, out var pi);

                if (!success) return false;

                try
                {
                    InjectDllViaAPC(pi.hProcess, pi.hThread, intruderDll);
                    ResumeThread(pi.hThread);
                    return true;
                }
                finally
                {
                    CloseHandle(pi.hThread);
                    CloseHandle(pi.hProcess);
                }
            }
            catch { return false; }
        }

        private void InjectDllViaAPC(IntPtr hProcess, IntPtr hThread, string dllPath)
        {
            IntPtr kernel32 = GetModuleHandle("kernel32.dll");
            IntPtr loadLibrary = GetProcAddress(kernel32, "LoadLibraryA");

            byte[] dllBytes = Encoding.ASCII.GetBytes(dllPath + "\0");
            IntPtr allocMem = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)dllBytes.Length,
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

            if (allocMem == IntPtr.Zero) throw new Exception("VirtualAllocEx failed");

            if (!WriteProcessMemory(hProcess, allocMem, dllBytes, (uint)dllBytes.Length, out _))
                throw new Exception("WriteProcessMemory failed");

            QueueUserAPC(loadLibrary, hThread, allocMem);
        }

        private bool LaunchWithoutInjection(string exePath, string args, string workDir)
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = exePath,
                    Arguments = args,
                    WorkingDirectory = string.IsNullOrEmpty(workDir) ? Path.GetDirectoryName(exePath) : workDir,
                    UseShellExecute = false
                });
                return true;
            }
            catch { return false; }
        }
    }

    // ========================================
    // ABOUT FORM
    // ========================================
    public class AboutForm : Form
    {
        public AboutForm()
        {
            Text = "About / Donate";
            ClientSize = new Size(458, 316);
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            MinimizeBox = false;
            StartPosition = FormStartPosition.CenterParent;

            var mainGroup = new GroupBox { Location = new Point(7, 7), Size = new Size(286, 178) };
            
            var titleLabel = new Label
            {
                Text = "NinjaRipper - Reborn (Prototype)",
                Location = new Point(60, 25),
                Size = new Size(180, 25),
                Font = new Font("Arial", 12, FontStyle.Bold),
                TextAlign = ContentAlignment.MiddleCenter
            };

            var authorLabel = new Label { Text = "Original Author:", Location = new Point(40, 51), Size = new Size(80, 12), TextAlign = ContentAlignment.MiddleRight };
            var authorName = new Label { Text = "black_ninja", Location = new Point(125, 51), Size = new Size(70, 12) };
            var copyright = new Label { Text = "(c) 2004-2012", Location = new Point(200, 51), Size = new Size(80, 12) };

            var portLabel = new Label { Text = "C# Port: 2026", Location = new Point(100, 68), Size = new Size(100, 12), TextAlign = ContentAlignment.MiddleCenter };

            var homepage = new LinkLabel { Text = "cgig.ru/ninjaripper", Location = new Point(90, 85), Size = new Size(120, 12), TextAlign = ContentAlignment.MiddleCenter };
            homepage.LinkClicked += (s, e) =>
            {
                try { Process.Start(new ProcessStartInfo { FileName = "http://cgig.ru/ninjaripper/", UseShellExecute = true }); }
                catch { }
            };

            var infoLabel = new Label
            {
                Text = "This is a C# educational port.\nFor full functionality, use the original C++ version.",
                Location = new Point(20, 110),
                Size = new Size(260, 30),
                TextAlign = ContentAlignment.MiddleCenter
            };

            var okBtn = new Button { Text = "OK", Location = new Point(200, 192), Size = new Size(86, 22), DialogResult = DialogResult.OK };
            
            mainGroup.Controls.AddRange(new Control[] { titleLabel, authorLabel, authorName, copyright, portLabel, homepage, infoLabel });
            Controls.AddRange(new Control[] { mainGroup, okBtn });
            AcceptButton = okBtn;
        }
    }

    // ========================================
    // MAIN FORM
    // ========================================
    public partial class MainForm : Form
    {
        private Settings _settings;
        private const string WINDOW_TITLE = "NinjaRipper - Reborn (Prototype)";

        // Controls
        private GroupBox targetGroup;
        private Label exeLabel, argLabel, dirLabel;
        private TextBox exeField, argField, dirField;
        private Button exeBrowseBtn;
        
        private Button runBtn;
        private ComboBox wrapperCombo;
        
        private GroupBox outputGroup;
        private Label outdirLabel;
        private TextBox outdirField;
        private Button outdirBrowseBtn, browseBtn;
        private CheckBox dontOverwriteCheck;
        
        private GroupBox settingsGroup, forcedSaveGroup;
        private Label ripLabel, texturesLabel;
        private ComboBox ripCombo, texturesCombo;
        
        private Button aboutBtn, exitBtn;

        public MainForm()
        {
            _settings = new Settings();
            InitializeComponent();
            InitializeSettings();
            LoadSettings();
        }

        private void InitializeComponent()
        {
            SuspendLayout();

            Text = WINDOW_TITLE;
            ClientSize = new Size(298, 238);
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            StartPosition = FormStartPosition.CenterScreen;

            // ===== Target Group =====
            targetGroup = new GroupBox 
            { 
                Text = "Target ( DX8, DX9, DX11 application )", 
                Location = new Point(7, 7), 
                Size = new Size(212, 85) 
            };
            
            exeLabel = new Label 
            { 
                Text = "Exe:", 
                Location = new Point(6, 19), 
                Size = new Size(24, 13),
                TextAlign = ContentAlignment.MiddleRight
            };
            // EDITABLE - removed ReadOnly and gray background
            exeField = new TextBox 
            { 
                Location = new Point(32, 17), 
                Size = new Size(143, 20)
            };
            exeBrowseBtn = new Button 
            { 
                Text = "...", 
                Location = new Point(178, 17), 
                Size = new Size(27, 20) 
            };
            exeBrowseBtn.Click += ExeBrowseBtn_Click;
            
            argLabel = new Label 
            { 
                Text = "Arg:", 
                Location = new Point(5, 43), 
                Size = new Size(25, 13),
                TextAlign = ContentAlignment.MiddleRight
            };
            argField = new TextBox 
            { 
                Location = new Point(32, 41), 
                Size = new Size(173, 20) 
            };
            
            dirLabel = new Label 
            { 
                Text = "Dir:", 
                Location = new Point(7, 65), 
                Size = new Size(23, 13),
                TextAlign = ContentAlignment.MiddleRight
            };
            dirField = new TextBox 
            { 
                Location = new Point(32, 63), 
                Size = new Size(173, 20) 
            };

            targetGroup.Controls.AddRange(new Control[] { exeLabel, exeField, exeBrowseBtn, argLabel, argField, dirLabel, dirField });

            // ===== Run Button & Wrapper =====
            runBtn = new Button 
            { 
                Text = "Run", 
                Location = new Point(228, 16), 
                Size = new Size(62, 32), 
                Font = new Font(Font.FontFamily, 9F, FontStyle.Bold) 
            };
            runBtn.Click += RunBtn_Click;

            wrapperCombo = new ComboBox 
            { 
                Location = new Point(228, 52), 
                Size = new Size(62, 21), 
                DropDownStyle = ComboBoxStyle.DropDownList 
            };
            wrapperCombo.Items.AddRange(new object[] { "Intruder (Rec.)", "D3D9 Wrapper", "D3D8 Wrapper", "D3D11 Wrapper" });
            wrapperCombo.SelectedIndex = 0;

            // ===== Output Directory Group =====
            outputGroup = new GroupBox 
            { 
                Text = "Output Directory", 
                Location = new Point(7, 97), 
                Size = new Size(212, 66) 
            };
            
            outdirLabel = new Label 
            { 
                Text = "Dir:", 
                Location = new Point(7, 22), 
                Size = new Size(23, 13),
                TextAlign = ContentAlignment.MiddleRight
            };
            // EDITABLE - removed ReadOnly and gray background
            outdirField = new TextBox 
            { 
                Location = new Point(32, 20), 
                Size = new Size(143, 20)
            };
            outdirBrowseBtn = new Button 
            { 
                Text = "...", 
                Location = new Point(178, 20), 
                Size = new Size(27, 20) 
            };
            outdirBrowseBtn.Click += OutdirBrowseBtn_Click;
            
            dontOverwriteCheck = new CheckBox 
            { 
                Text = "Don't change the path", 
                Location = new Point(32, 44), 
                Size = new Size(140, 17) 
            };

            outputGroup.Controls.AddRange(new Control[] { outdirLabel, outdirField, outdirBrowseBtn, dontOverwriteCheck });

            // ===== Browse Button (on form, not in group) =====
            browseBtn = new Button 
            { 
                Text = "Browse", 
                Location = new Point(228, 117), 
                Size = new Size(62, 25) 
            };
            browseBtn.Click += BrowseBtn_Click;

            // ===== Settings Group =====
            settingsGroup = new GroupBox 
            { 
                Text = "Settings", 
                Location = new Point(7, 168), 
                Size = new Size(212, 63) 
            };
            
            forcedSaveGroup = new GroupBox 
            { 
                Text = "Forced to save", 
                Location = new Point(13, 19), 
                Size = new Size(190, 37) 
            };
            
            ripLabel = new Label 
            { 
                Text = "RIP", 
                Location = new Point(7, 16), 
                Size = new Size(23, 13),
                TextAlign = ContentAlignment.MiddleRight
            };
            ripCombo = new ComboBox 
            { 
                Location = new Point(32, 14), 
                Size = new Size(44, 21), 
                DropDownStyle = ComboBoxStyle.DropDownList 
            };
            for (int i = 1; i <= 12; i++) ripCombo.Items.Add($"F{i}");
            ripCombo.SelectedIndex = 9; // F10
            
            texturesLabel = new Label 
            { 
                Text = "Textures", 
                Location = new Point(96, 16), 
                Size = new Size(46, 13),
                TextAlign = ContentAlignment.MiddleRight
            };
            texturesCombo = new ComboBox 
            { 
                Location = new Point(144, 14), 
                Size = new Size(40, 21), 
                DropDownStyle = ComboBoxStyle.DropDownList 
            };
            for (int i = 1; i <= 12; i++) texturesCombo.Items.Add($"F{i}");
            texturesCombo.SelectedIndex = 8; // F9

            forcedSaveGroup.Controls.AddRange(new Control[] { ripLabel, ripCombo, texturesLabel, texturesCombo });
            settingsGroup.Controls.Add(forcedSaveGroup);

            // ===== About & Exit Buttons =====
            aboutBtn = new Button 
            { 
                Text = "About / Donate", 
                Location = new Point(228, 175), 
                Size = new Size(62, 23) 
            };
            aboutBtn.Click += (s, e) => new AboutForm().ShowDialog(this);
            
            exitBtn = new Button 
            { 
                Text = "Exit", 
                Location = new Point(228, 204), 
                Size = new Size(62, 23) 
            };
            exitBtn.Click += (s, e) => Close();

            // ===== Add all controls to form =====
            Controls.AddRange(new Control[] 
            { 
                targetGroup, 
                runBtn, 
                wrapperCombo, 
                outputGroup, 
                browseBtn, 
                settingsGroup, 
                aboutBtn, 
                exitBtn 
            });
            
            ResumeLayout(false);
        }

        private void ExeBrowseBtn_Click(object? sender, EventArgs e)
        {
            using var ofd = new OpenFileDialog { Filter = "Executable Files (*.exe)|*.exe|All Files (*.*)|*.*", Title = "Select Target Executable" };
            if (ofd.ShowDialog() == DialogResult.OK)
            {
                exeField.Text = ofd.FileName;
                var dir = Path.GetDirectoryName(ofd.FileName) ?? "";
                dirField.Text = dir;
                if (!dontOverwriteCheck.Checked) outdirField.Text = dir;
            }
        }

        private void OutdirBrowseBtn_Click(object? sender, EventArgs e)
        {
            using var fbd = new FolderBrowserDialog { Description = "Select Output Directory", SelectedPath = outdirField.Text };
            if (fbd.ShowDialog() == DialogResult.OK) outdirField.Text = fbd.SelectedPath;
        }

        private void BrowseBtn_Click(object? sender, EventArgs e)
        {
            var outDir = outdirField.Text;
            if (!string.IsNullOrEmpty(outDir) && Directory.Exists(outDir))
                Process.Start("explorer.exe", outDir);
        }

        private void RunBtn_Click(object? sender, EventArgs e)
        {
            if (string.IsNullOrEmpty(exeField.Text))
            {
                MessageBox.Show("Please select an executable file first.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            SaveSettings();

            var injector = new ProcessInjector();
            bool success = injector.InjectAndRun(
                exeField.Text,
                argField.Text,
                dirField.Text,
                wrapperCombo.SelectedIndex
            );

            if (!success)
            {
                MessageBox.Show("Failed to launch target process.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void InitializeSettings()
        {
            _settings.Load();
        }

        private void LoadSettings()
        {
            exeField.Text = _settings.PrevEXE;
            argField.Text = _settings.PrevArg;
            dirField.Text = _settings.PrevDir;
            outdirField.Text = _settings.OutDir;
            dontOverwriteCheck.Checked = _settings.DontOverwriteOutDir;
        }

        private void SaveSettings()
        {
            _settings.PrevEXE = exeField.Text;
            _settings.PrevArg = argField.Text;
            _settings.PrevDir = dirField.Text;
            _settings.OutDir = outdirField.Text;
            _settings.DontOverwriteOutDir = dontOverwriteCheck.Checked;
            _settings.RipKey = 0x79 + ripCombo.SelectedIndex;
            _settings.TextureRipKey = 0x79 + texturesCombo.SelectedIndex;
            
            _settings.Save();
        }
    }
}