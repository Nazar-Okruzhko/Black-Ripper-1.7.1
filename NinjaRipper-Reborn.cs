using System;
using System.IO;
using System.Drawing;
using System.Windows.Forms;
using System.Diagnostics;
 
namespace NinjaRipper
{
    // =========================================================================
    //  UI LAYOUT CONSTANTS
    //  ALL coordinates are CLIENT-SPACE (origin = top-left of client area).
    //  Edit only this class to fix any pixel mismatches.
    // =========================================================================
    static class UI
    {
        // -- Form --------------------------------------------------------------
        public const int FormWidth  = 456;
        public const int FormHeight = 289;
 
        // -- Target GroupBox ---------------------------------------------------
        public const int TargetGroupX      = 11;
        public const int TargetGroupY      = 11;
        public const int TargetGroupWidth  = 317;   // = RunGroupX - TargetGroupX - 8
        public const int TargetGroupHeight = 104;
 
        // Exe row
        public const int ExeLabelX        = 19;
        public const int ExeLabelY        = 37;
        public const int ExeBoxX          = 50;
        public const int ExeBoxY          = 33;
        public const int ExeBoxWidth      = 238;
        public const int ExeBoxHeight     = 20;

        // Exe "..." button
        public const int ExeDotX          = 292;
        public const int ExeDotY          = 32;
        public const int ExeDotWidth      = 27;
        public const int ExeDotHeight     = 22;
 
        // Arg row
        public const int ArgLabelX        = 19;
        public const int ArgLabelY        = 63;
        public const int ArgBoxX          = 50;
        public const int ArgBoxY          = 59;
        public const int ArgBoxWidth      = 268;
        public const int ArgBoxHeight     = 20;
 
        // Dir row ? editable, NOT ReadOnly, NO dot button; auto-filled from Exe
        public const int DirLabelX        = 19;
        public const int DirLabelY        = 89;
        public const int DirBoxX          = 50;
        public const int DirBoxY          = 85;
        public const int DirBoxWidth      = 268;
        public const int DirBoxHeight     = 20;
 
        // -- Run GroupBox (unlabelled border panel) ----------------------------
        public const int RunGroupX        = 335;
        public const int RunGroupY        = 11;
        public const int RunGroupWidth    = 107;
        public const int RunGroupHeight   = 104;
 
        // Run button (tall, top half of RunGroup)
        public const int RunButtonX       = 341;
        public const int RunButtonY       = 24;
        public const int RunButtonWidth   = 94;
        public const int RunButtonHeight  = 53;
 
        // Mode selector combo (bottom half of RunGroup, below Run button)
        public const int ModeComboX       = 342;
        public const int ModeComboY       = 85;
        public const int ModeComboWidth   = 92;
        public const int ModeComboHeight  = 21;
 
        // -- Output Directory GroupBox -----------------------------------------
        public const int OutputGroupX      = 11;
        public const int OutputGroupY      = 119;
        public const int OutputGroupWidth  = 431;
        public const int OutputGroupHeight = 79;
 
        // Output Dir row
        public const int OutputDirLabelX   = 23;
        public const int OutputDirLabelY   = 143;
        public const int OutputDirBoxX     = 50;
        public const int OutputDirBoxY     = 142;
        public const int OutputDirBoxWidth = 238;
        public const int OutputDirBoxHeight= 20;
 
        // Dir's "..." Button
        public const int OutputDotX        = 292;
        public const int OutputDotY        = 141;
        public const int OutputDotWidth    = 27;
        public const int OutputDotHeight   = 22;
 
        // Browse button (tall; right side of Output Directory group)
        public const int BrowseButtonX     = 341;
        public const int BrowseButtonY     = 141;
        public const int BrowseButtonWidth = 94;
        public const int BrowseButtonHeight= 42;
 
        // "Don't change the path" checkbox
        public const int DontChangeX       = 50;
        public const int DontChangeY       = 168;
        public const int DontChangeWidth   = 160;
        public const int DontChangeHeight  = 17;
 
        // -- Settings GroupBox -------------------------------------------------
        public const int SettingsGroupX      = 11;
        public const int SettingsGroupY      = 202;
        public const int SettingsGroupWidth  = 317;
        public const int SettingsGroupHeight = 65;
 
        // RIP row (inside Settings group visually)
        public const int RipLabelX          = 18;
        public const int RipLabelY          = 233;
        public const int RipComboX          = 44;
        public const int RipComboY          = 230;
        public const int RipComboWidth      = 49;
        public const int RipComboHeight     = 20;
 
        // -- Forced to Save GroupBox (visually nested inside Settings) ---------
        public const int ForcedGroupX       = 107;
        public const int ForcedGroupY       = 210;
        public const int ForcedGroupWidth   = 125;
        public const int ForcedGroupHeight  = 50;
 
        // Textures row (inside Forced to Save group visually)
        public const int TexturesLabelX     = 112;
        public const int TexturesLabelY     = 233;
        public const int TexturesComboX     = 168;
        public const int TexturesComboY     = 230;
        public const int TexturesComboWidth = 49;
        public const int TexturesComboHeight= 20;
 
        // -- About / Donate button ---------------------------------------------
        public const int AboutButtonX       = 341;
        public const int AboutButtonY       = 207;
        public const int AboutButtonWidth   = 94;
        public const int AboutButtonHeight  = 29;
 
        // -- Exit button -------------------------------------------------------
        public const int ExitButtonX        = 341;
        public const int ExitButtonY        = 238;
        public const int ExitButtonWidth    = 94;
        public const int ExitButtonHeight   = 29;
    }
 
    // =========================================================================
    //  Config -- persists Exe and Dir across restarts using a plain text file
    //  stored next to the executable: NinjaRipper.cfg
    //  Format: two lines -- Exe path then Dir path.  Missing/corrupt = ignored.
    // =========================================================================
    static class Config
    {
        private static readonly string FilePath = Path.Combine(
            Path.GetDirectoryName(Application.ExecutablePath) ?? string.Empty,
            "NinjaRipper.cfg");

        public static (string Exe, string Dir) Load()
        {
            try
            {
                if (!File.Exists(FilePath)) return (string.Empty, string.Empty);
                string[] lines = File.ReadAllLines(FilePath);
                string exe = lines.Length > 0 ? lines[0] : string.Empty;
                string dir = lines.Length > 1 ? lines[1] : string.Empty;
                return (exe, dir);
            }
            catch { return (string.Empty, string.Empty); }
        }

        public static void Save(string exe, string dir)
        {
            try { File.WriteAllLines(FilePath, new[] { exe, dir }); }
            catch { /* best-effort */ }
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
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm());
        }
    }
 
    // =========================================================================
    //  About / Donate dialog  ?  ClientSize = 292 ? 210
    // =========================================================================
    sealed class AboutForm : Form
    {
        public AboutForm()
        {
            Text            = "About / Donate";
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox     = false;
            MinimizeBox     = false;
            ShowInTaskbar   = false;
            StartPosition   = FormStartPosition.CenterParent;
            ClientSize      = new Size(292, 210);
            Font            = new Font("Microsoft Sans Serif", 8);
 
            Controls.Add(new Label
            {
                Text      = "Ninja Ripper 1.1.2",
                Font      = new Font("Microsoft Sans Serif", 9f, FontStyle.Bold),
                TextAlign = ContentAlignment.MiddleCenter,
                Bounds    = new Rectangle(0, 10, 292, 18)
            });
 
            // "black_ninja" is the only hyperlink
            var authorLabel = new LinkLabel
            {
                Text      = "Author:  black_ninja  (c) 2004-2012",
                TextAlign = ContentAlignment.MiddleCenter,
                Bounds    = new Rectangle(0, 34, 292, 16)
            };
            authorLabel.Links.Clear();
            authorLabel.Links.Add(9, 11, "https://cgig.ru");
            authorLabel.LinkClicked += OnLinkClicked;
            Controls.Add(authorLabel);
 
            // "cgig.ru/ninjaripper" is the only hyperlink
            var homeLabel = new LinkLabel
            {
                Text      = "Home:  cgig.ru/ninjaripper",
                TextAlign = ContentAlignment.MiddleCenter,
                Bounds    = new Rectangle(0, 54, 292, 16)
            };
            homeLabel.Links.Clear();
            homeLabel.Links.Add(7, 19, "https://cgig.ru/ninjaripper/");
            homeLabel.LinkClicked += OnLinkClicked;
            Controls.Add(homeLabel);
 
            // Donation group ? interactive controls added BEFORE GroupBox
            var paypalButton = new Button
            {
                Text      = "PayPal",
                Font      = new Font("Arial", 11f, FontStyle.Bold | FontStyle.Italic),
                ForeColor = Color.FromArgb(0, 59, 122),
                BackColor = Color.FromArgb(255, 196, 57),
                FlatStyle = FlatStyle.Flat,
                Bounds    = new Rectangle(86, 90, 120, 30),
                Cursor    = Cursors.Hand,
                UseVisualStyleBackColor = false
            };
            paypalButton.FlatAppearance.BorderColor = Color.FromArgb(0, 59, 122);
            paypalButton.Click += (_, _) => OpenUrl(
                "https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=RPNFSGKSUKLM2");
            Controls.Add(paypalButton);
 
            Controls.Add(new Label  { Text = "WMR:", AutoSize = true, Location = new Point(14, 130) });
            var wmrBox = new TextBox { Text = "R175496431227", ReadOnly = true, Bounds = new Rectangle(52, 127, 164, 20) };
            Controls.Add(wmrBox);
            Controls.Add(new Label  { Text = "WMZ:", AutoSize = true, Location = new Point(14, 150) });
            var wmzBox = new TextBox { Text = "Z983369561118", ReadOnly = true, Bounds = new Rectangle(52, 147, 164, 20) };
            Controls.Add(wmzBox);
 
            // OK button
            var okButton = new Button
            {
                Text         = "OK",
                DialogResult = DialogResult.OK,
                FlatStyle    = FlatStyle.System,
                Bounds       = new Rectangle(210, 182, 74, 23)
            };
            AcceptButton = okButton;
            Controls.Add(okButton);
 
            // GroupBox added LAST so it paints BEHIND all controls above
            // CRITICAL: never set BackColor on GroupBox ? kills the border
            Controls.Add(new GroupBox
            {
                Text   = "Make a donation - support the development",
                Bounds = new Rectangle(8, 76, 276, 96)
            });
        }
 
        private static void OnLinkClicked(object? s, LinkLabelLinkClickedEventArgs e)
        {
            if (e.Link?.LinkData is string url) OpenUrl(url);
        }
 
        internal static void OpenUrl(string url)
        {
            try { Process.Start(new ProcessStartInfo { FileName = url, UseShellExecute = true }); }
            catch { }
        }
    }
 
    // =========================================================================
    //  Main form  ?  ClientSize = 456 ? 289
    //
    //  Z-ORDER RULE (critical for GroupBox borders to be visible AND for
    //  controls to appear on top of GroupBox backgrounds):
    //
    //    In WinForms, Controls.Add() inserts at the FRONT of the paint stack.
    //    The first control added is painted LAST ? appears on TOP.
    //    The last control added is painted FIRST ? appears BEHIND.
    //
    //    Therefore: add ALL buttons/textboxes/labels/combos FIRST,
    //               add ALL GroupBoxes LAST.
    //
    //    GroupBoxes will then be painted first (behind everything), while
    //    all interactive controls float visibly on top of them.
    // =========================================================================
    sealed class MainForm : Form
    {
        private TextBox  _exeBox        = null!;
        private TextBox  _argBox        = null!;
        private TextBox  _dirBox        = null!;
        private TextBox  _outputDirBox  = null!;
        private ComboBox _modeCombo     = null!;
        private ComboBox _ripCombo      = null!;
        private ComboBox _texturesCombo = null!;
 
        public MainForm()
        {
            Text            = "Ninja Ripper 1.1.2";
            FormBorderStyle = FormBorderStyle.FixedSingle;
            MaximizeBox     = false;
            StartPosition   = FormStartPosition.CenterScreen;
            ClientSize      = new Size(UI.FormWidth, UI.FormHeight);
            Font            = new Font("Microsoft Sans Serif", 8);
 
            // -- STEP 1: Add all interactive controls first (they paint on top) -
            AddAllControls();
 
            // -- STEP 2: Add all GroupBoxes last (they paint behind everything) -
            AddAllGroupBoxes();
        }
 
        // -- All labels, textboxes, combos and buttons -------------------------
        private void AddAllControls()
        {
            // --- Target section ---
 
            Controls.Add(MakeLabel("Exe:", UI.ExeLabelX, UI.ExeLabelY));
            _exeBox          = MakeTextBox(UI.ExeBoxX, UI.ExeBoxY, UI.ExeBoxWidth, UI.ExeBoxHeight);
            _exeBox.Enabled = false;    // grey ? pick via "..."
            Controls.Add(_exeBox);

            // Restore previously selected paths
            var (savedExe, savedDir) = Config.Load();
            if (!string.IsNullOrEmpty(savedExe)) _exeBox.Text = savedExe;

            var exeDot = MakeDotButton(UI.ExeDotX, UI.ExeDotY, UI.ExeDotWidth, UI.ExeDotHeight);
            exeDot.Click += (_, _) => PickExecutable();
            Controls.Add(exeDot);
 
            Controls.Add(MakeLabel("Arg:", UI.ArgLabelX, UI.ArgLabelY));
            _argBox = MakeTextBox(UI.ArgBoxX, UI.ArgBoxY, UI.ArgBoxWidth, UI.ArgBoxHeight);
            Controls.Add(_argBox);
 
            Controls.Add(MakeLabel("Dir:", UI.DirLabelX, UI.DirLabelY));
            _dirBox = MakeTextBox(UI.DirBoxX, UI.DirBoxY, UI.DirBoxWidth, UI.DirBoxHeight);
            Controls.Add(_dirBox);
            if (!string.IsNullOrEmpty(savedDir)) _dirBox.Text = savedDir;
 
            // --- Run / mode section ---
 
            var runButton = MakeButton("Run",
                UI.RunButtonX, UI.RunButtonY, UI.RunButtonWidth, UI.RunButtonHeight);
            runButton.Click += RunButton_Click;
            Controls.Add(runButton);
 
            _modeCombo = new ComboBox
            {
                DropDownStyle = ComboBoxStyle.DropDownList,
                Bounds        = new Rectangle(UI.ModeComboX, UI.ModeComboY,
                                              UI.ModeComboWidth, UI.ModeComboHeight)
            };
            _modeCombo.Items.AddRange(new object[]
            {
                "Intruder (Recommended)",
                "D3D9 Wrapper",
                "D3D8 Wrapper",
                "D3D11 Wrapper"
            });
            _modeCombo.SelectedIndex = 0;
            Controls.Add(_modeCombo);
 
            // --- Output Directory section ---
 
            Controls.Add(MakeLabel("Dir:", UI.OutputDirLabelX, UI.OutputDirLabelY));
 
            _outputDirBox      = MakeTextBox(UI.OutputDirBoxX, UI.OutputDirBoxY,
                                             UI.OutputDirBoxWidth, UI.OutputDirBoxHeight);
            _outputDirBox.Enabled = false;
            _outputDirBox.Text = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                "NinjaRipper");
            Controls.Add(_outputDirBox);
 
            var outputDot = MakeDotButton(UI.OutputDotX, UI.OutputDotY,
                                          UI.OutputDotWidth, UI.OutputDotHeight);
            outputDot.Click += (_, _) => PickOutputFolder();
            Controls.Add(outputDot);
 
            var browseButton = MakeButton("Browse",
                UI.BrowseButtonX, UI.BrowseButtonY,
                UI.BrowseButtonWidth, UI.BrowseButtonHeight);
            browseButton.Click += (_, _) => OpenExplorer(_outputDirBox.Text);
            Controls.Add(browseButton);
 
            Controls.Add(new CheckBox
            {
                Text    = "Don't change the path",
                Checked = true,
                Bounds  = new Rectangle(UI.DontChangeX, UI.DontChangeY,
                                        UI.DontChangeWidth, UI.DontChangeHeight)
            });
 
            // --- Settings / Forced to save section ---
 
            Controls.Add(MakeLabel("RIP", UI.RipLabelX, UI.RipLabelY));
            _ripCombo = MakeFKeyCombo(UI.RipComboX, UI.RipComboY, UI.RipComboWidth, "F12");
            Controls.Add(_ripCombo);
 
            Controls.Add(MakeLabel("Textures", UI.TexturesLabelX, UI.TexturesLabelY));
            _texturesCombo = MakeFKeyCombo(UI.TexturesComboX, UI.TexturesComboY,
                                           UI.TexturesComboWidth, "F12");
            Controls.Add(_texturesCombo);
 
            // --- Action buttons ---
 
            var aboutButton = MakeButton("About / Donate",
                UI.AboutButtonX, UI.AboutButtonY,
                UI.AboutButtonWidth, UI.AboutButtonHeight);
            aboutButton.Click += (_, _) => { using var d = new AboutForm(); d.ShowDialog(this); };
            Controls.Add(aboutButton);
 
            var exitButton = MakeButton("Exit",
                UI.ExitButtonX, UI.ExitButtonY,
                UI.ExitButtonWidth, UI.ExitButtonHeight);
            exitButton.Click += (_, _) => Application.Exit();
            Controls.Add(exitButton);
        }
 
        // -- All GroupBoxes ? added LAST so they render BEHIND everything above -
        private void AddAllGroupBoxes()
        {
            // Target GroupBox
            Controls.Add(new GroupBox
            {
                Text   = "Target ( DX8, DX9, DX11 application )",
                Bounds = new Rectangle(UI.TargetGroupX, UI.TargetGroupY,
                                       UI.TargetGroupWidth, UI.TargetGroupHeight)
            });
 
            // Run GroupBox ? no title text, just a border box
            Controls.Add(new GroupBox
            {
                Text   = string.Empty,
                Bounds = new Rectangle(UI.RunGroupX, UI.RunGroupY,
                                       UI.RunGroupWidth, UI.RunGroupHeight)
            });
 
            // Output Directory GroupBox
            Controls.Add(new GroupBox
            {
                Text   = "Output Directory",
                Bounds = new Rectangle(UI.OutputGroupX, UI.OutputGroupY,
                                       UI.OutputGroupWidth, UI.OutputGroupHeight)
            });
 
            // Forced to Save GroupBox ? added before Settings so Settings
            // border overlaps it correctly (Settings is the outer box)
            Controls.Add(new GroupBox
            {
                Text   = "Forced to save",
                Bounds = new Rectangle(UI.ForcedGroupX, UI.ForcedGroupY,
                                       UI.ForcedGroupWidth, UI.ForcedGroupHeight)
            });
 
            // Settings GroupBox ? outermost, added last of the GroupBoxes
            // so it paints furthest back; its border frames the whole bottom row
            Controls.Add(new GroupBox
            {
                Text   = "Settings",
                Bounds = new Rectangle(UI.SettingsGroupX, UI.SettingsGroupY,
                                       UI.SettingsGroupWidth, UI.SettingsGroupHeight)
            });
        }
 
        // -- Control factory helpers -------------------------------------------
 
        private static Label MakeLabel(string text, int x, int y)
            => new Label { Text = text, Location = new Point(x, y), AutoSize = true };
 
        private static TextBox MakeTextBox(int x, int y, int width, int height)
            => new TextBox { Bounds = new Rectangle(x, y, width, height) };
 
        private static Button MakeButton(string text, int x, int y, int width, int height)
            => new Button
            {
                Text      = text,
                Bounds    = new Rectangle(x, y, width, height),
                FlatStyle = FlatStyle.System   // native Win32 raised button look
            };
 
        private static Button MakeDotButton(int x, int y, int width, int height)
            => new Button
            {
                Text      = "...",
                Bounds    = new Rectangle(x, y, width, height),
                FlatStyle = FlatStyle.System
            };
 
        private static ComboBox MakeFKeyCombo(int x, int y, int width, string defaultKey)
        {
            var combo = new ComboBox
            {
                DropDownStyle = ComboBoxStyle.DropDownList,
                Bounds        = new Rectangle(x, y, width, 21)
            };
            for (int i = 1; i <= 12; i++) combo.Items.Add($"F{i}");
            combo.SelectedItem = defaultKey;
            return combo;
        }
 
        // -- Actions -----------------------------------------------------------
 
        private void PickExecutable()
        {
            using var d = new OpenFileDialog
            {
                Title  = "Select target executable",
                Filter = "EXE Files (*.exe)|*.exe|All Files (*.*)|*.*"
            };
            if (d.ShowDialog(this) != DialogResult.OK) return;
            _exeBox.Text = d.FileName;
            _dirBox.Text = Path.GetDirectoryName(d.FileName) ?? string.Empty;
            Config.Save(_exeBox.Text, _dirBox.Text);
        }
 
        private void PickOutputFolder()
        {
            using var d = new FolderBrowserDialog
            {
                Description        = "Select output directory",
                SelectedPath       = _outputDirBox.Text,
                AutoUpgradeEnabled = false   // classic dialog with "Make New Folder"
            };
            if (d.ShowDialog(this) == DialogResult.OK)
                _outputDirBox.Text = d.SelectedPath;
        }
 
        private static void OpenExplorer(string path)
        {
            string target = Directory.Exists(path) ? path
                : Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName        = "explorer.exe",
                    Arguments       = $"\"{target}\"",
                    UseShellExecute = true
                });
            }
            catch { }
        }
 
        private void RunButton_Click(object? sender, EventArgs e)
        {
            if (string.IsNullOrWhiteSpace(_exeBox.Text))
            {
                MessageBox.Show("Please select a target executable.", Text,
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName         = _exeBox.Text,
                    Arguments        = _argBox.Text,
                    WorkingDirectory = _dirBox.Text,
                    UseShellExecute  = true
                });
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to launch:\n{ex.Message}", Text,
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
    }
}
 
