using System;
using System.Drawing;
using System.Runtime.Versioning;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using mRemoteNG.App;
using mRemoteNG.Messages;
using mRemoteNG.Tools.SecurityScanner;

namespace mRemoteNG.UI.Forms
{
    /// <summary>
    /// Form for running AI-powered security scans of the local system.
    /// Supports OpenAI, Claude, Gemini, and Grok LLM providers.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public class FrmSecurityScan : Form
    {
        private ComboBox _cboProvider;
        private TextBox _txtApiKey;
        private TextBox _txtModel;
        private Button _btnScan;
        private Button _btnCancel;
        private Button _btnExport;
        private RichTextBox _txtResults;
        private ProgressBar _progressBar;
        private Label _lblStatus;
        private Label _lblProvider;
        private Label _lblApiKey;
        private Label _lblModel;
        private GroupBox _grpConfig;
        private GroupBox _grpResults;
        private CancellationTokenSource _cts;

        public FrmSecurityScan()
        {
            InitializeComponent();
        }

        private void InitializeComponent()
        {
            SuspendLayout();

            // Form settings
            Text = "AI Security Scanner";
            Size = new Size(950, 750);
            MinimumSize = new Size(750, 550);
            StartPosition = FormStartPosition.CenterParent;
            Icon = Properties.Resources.mRemoteNG_Icon;
            Font = new Font("Segoe UI", 9F);

            // Configuration group
            _grpConfig = new GroupBox
            {
                Text = "LLM Configuration",
                Location = new Point(12, 12),
                Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right,
                Size = new Size(910, 120)
            };

            _lblProvider = new Label { Text = "Provider:", Location = new Point(15, 28), Size = new Size(70, 23), TextAlign = ContentAlignment.MiddleRight };
            _cboProvider = new ComboBox
            {
                Location = new Point(90, 28),
                Size = new Size(160, 23),
                DropDownStyle = ComboBoxStyle.DropDownList
            };
            _cboProvider.Items.AddRange(new object[] { "OpenAI", "Claude (Anthropic)", "Gemini (Google)", "Grok (xAI)" });
            _cboProvider.SelectedIndex = 0;
            _cboProvider.SelectedIndexChanged += CboProvider_SelectedIndexChanged;

            _lblApiKey = new Label { Text = "API Key:", Location = new Point(270, 28), Size = new Size(60, 23), TextAlign = ContentAlignment.MiddleRight };
            _txtApiKey = new TextBox
            {
                Location = new Point(335, 28),
                Size = new Size(400, 23),
                UseSystemPasswordChar = true,
                Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right
            };

            _lblModel = new Label { Text = "Model:", Location = new Point(15, 60), Size = new Size(70, 23), TextAlign = ContentAlignment.MiddleRight };
            _txtModel = new TextBox
            {
                Location = new Point(90, 60),
                Size = new Size(160, 23),
                Text = LlmConfig.GetDefaultModel(LlmProvider.OpenAI),
                PlaceholderText = "Leave blank for default"
            };

            _btnScan = new Button
            {
                Text = "Run Security Scan",
                Location = new Point(335, 58),
                Size = new Size(150, 30),
                BackColor = Color.FromArgb(0, 122, 204),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Cursor = Cursors.Hand
            };
            _btnScan.FlatAppearance.BorderSize = 0;
            _btnScan.Click += BtnScan_Click;

            _btnCancel = new Button
            {
                Text = "Cancel",
                Location = new Point(495, 58),
                Size = new Size(80, 30),
                Enabled = false,
                FlatStyle = FlatStyle.Flat,
                Cursor = Cursors.Hand
            };
            _btnCancel.Click += BtnCancel_Click;

            _btnExport = new Button
            {
                Text = "Export Report",
                Location = new Point(585, 58),
                Size = new Size(100, 30),
                Enabled = false,
                FlatStyle = FlatStyle.Flat,
                Cursor = Cursors.Hand
            };
            _btnExport.Click += BtnExport_Click;

            _grpConfig.Controls.AddRange(new Control[]
            {
                _lblProvider, _cboProvider,
                _lblApiKey, _txtApiKey,
                _lblModel, _txtModel,
                _btnScan, _btnCancel, _btnExport
            });

            // Progress
            _progressBar = new ProgressBar
            {
                Location = new Point(12, 140),
                Size = new Size(910, 8),
                Style = ProgressBarStyle.Marquee,
                MarqueeAnimationSpeed = 30,
                Visible = false,
                Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right
            };

            _lblStatus = new Label
            {
                Text = "Ready. Configure your LLM provider and click 'Run Security Scan' to begin.",
                Location = new Point(12, 152),
                Size = new Size(910, 20),
                Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right,
                ForeColor = Color.Gray
            };

            // Results group
            _grpResults = new GroupBox
            {
                Text = "Security Analysis Results",
                Location = new Point(12, 175),
                Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right,
                Size = new Size(910, 520)
            };

            _txtResults = new RichTextBox
            {
                Location = new Point(10, 22),
                Size = new Size(890, 488),
                Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right,
                ReadOnly = true,
                Font = new Font("Cascadia Code", 9.5F, FontStyle.Regular, GraphicsUnit.Point, 0),
                BackColor = Color.FromArgb(30, 30, 30),
                ForeColor = Color.FromArgb(220, 220, 220),
                BorderStyle = BorderStyle.None,
                WordWrap = true,
                Text = "Security scan results will appear here.\n\nSupported providers:\n" +
                       "  - OpenAI (GPT-4o, GPT-4, etc.)\n" +
                       "  - Claude (Anthropic - Claude Sonnet, Opus, etc.)\n" +
                       "  - Gemini (Google - Gemini 2.0 Flash, Pro, etc.)\n" +
                       "  - Grok (xAI - Grok-3, etc.)\n\n" +
                       "The scanner will collect:\n" +
                       "  - OS version and configuration\n" +
                       "  - Running processes and their paths\n" +
                       "  - Active network connections and open ports\n" +
                       "  - Installed software and versions\n" +
                       "  - Firewall status\n" +
                       "  - User accounts and security settings\n" +
                       "  - Windows Update history\n" +
                       "  - Network shares\n" +
                       "  - Startup programs\n" +
                       "  - Antivirus status\n\n" +
                       "This data is sent to the selected LLM for expert security analysis."
            };

            _grpResults.Controls.Add(_txtResults);

            // Add all to form
            Controls.AddRange(new Control[]
            {
                _grpConfig,
                _progressBar,
                _lblStatus,
                _grpResults
            });

            ResumeLayout(false);
        }

        private void CboProvider_SelectedIndexChanged(object sender, EventArgs e)
        {
            LlmProvider provider = GetSelectedProvider();
            _txtModel.Text = LlmConfig.GetDefaultModel(provider);
        }

        private LlmProvider GetSelectedProvider()
        {
            return _cboProvider.SelectedIndex switch
            {
                0 => LlmProvider.OpenAI,
                1 => LlmProvider.Claude,
                2 => LlmProvider.Gemini,
                3 => LlmProvider.Grok,
                _ => LlmProvider.OpenAI
            };
        }

        private async void BtnScan_Click(object sender, EventArgs e)
        {
            if (string.IsNullOrWhiteSpace(_txtApiKey.Text))
            {
                MessageBox.Show("Please enter an API key for the selected LLM provider.",
                    "API Key Required", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                _txtApiKey.Focus();
                return;
            }

            _btnScan.Enabled = false;
            _btnCancel.Enabled = true;
            _btnExport.Enabled = false;
            _progressBar.Visible = true;
            _txtResults.Clear();

            _cts = new CancellationTokenSource();

            try
            {
                // Step 1: Collect system information
                _lblStatus.Text = "Collecting system information...";
                _lblStatus.ForeColor = Color.DarkCyan;
                _txtResults.AppendText("Collecting system security data...\n\n");
                Application.DoEvents();

                string systemData = await Task.Run(() => SystemInfoCollector.CollectAll(), _cts.Token);

                _txtResults.AppendText(systemData);
                _txtResults.AppendText("\n\n========================================\n");
                _txtResults.AppendText("Sending data to LLM for analysis...\n");
                _txtResults.AppendText("========================================\n\n");

                // Step 2: Send to LLM for analysis
                _lblStatus.Text = $"Analyzing with {_cboProvider.SelectedItem}... (this may take 30-60 seconds)";
                _lblStatus.ForeColor = Color.DarkOrange;
                Application.DoEvents();

                LlmConfig config = new()
                {
                    Provider = GetSelectedProvider(),
                    ApiKey = _txtApiKey.Text.Trim(),
                    Model = _txtModel.Text.Trim()
                };

                LlmSecurityAnalyzer analyzer = new();
                string analysis = await analyzer.AnalyzeAsync(systemData, config, _cts.Token);

                // Step 3: Display results
                _txtResults.AppendText(analysis);
                _lblStatus.Text = "Security scan complete.";
                _lblStatus.ForeColor = Color.DarkGreen;
                _btnExport.Enabled = true;

                // Scroll to the analysis section
                int analysisStart = _txtResults.Text.IndexOf("========================================\n\n", StringComparison.Ordinal);
                if (analysisStart > 0)
                {
                    _txtResults.SelectionStart = analysisStart;
                    _txtResults.ScrollToCaret();
                }
            }
            catch (OperationCanceledException)
            {
                _txtResults.AppendText("\n\n[Scan cancelled by user]\n");
                _lblStatus.Text = "Scan cancelled.";
                _lblStatus.ForeColor = Color.Gray;
            }
            catch (Exception ex)
            {
                _txtResults.AppendText($"\n\n[ERROR: {ex.Message}]\n");
                if (ex.InnerException != null)
                    _txtResults.AppendText($"[Inner: {ex.InnerException.Message}]\n");

                _lblStatus.Text = $"Error: {ex.Message}";
                _lblStatus.ForeColor = Color.Red;

                Runtime.MessageCollector?.AddExceptionMessage("Security scan failed", ex, MessageClass.ErrorMsg);
            }
            finally
            {
                _btnScan.Enabled = true;
                _btnCancel.Enabled = false;
                _progressBar.Visible = false;
                _cts?.Dispose();
                _cts = null;
            }
        }

        private void BtnCancel_Click(object sender, EventArgs e)
        {
            _cts?.Cancel();
        }

        private void BtnExport_Click(object sender, EventArgs e)
        {
            using SaveFileDialog saveDialog = new()
            {
                Filter = "Text Files (*.txt)|*.txt|HTML Files (*.html)|*.html|All Files (*.*)|*.*",
                DefaultExt = "txt",
                FileName = $"SecurityScan_{DateTime.Now:yyyyMMdd_HHmmss}.txt",
                Title = "Export Security Scan Report"
            };

            if (saveDialog.ShowDialog() == DialogResult.OK)
            {
                try
                {
                    System.IO.File.WriteAllText(saveDialog.FileName, _txtResults.Text);
                    _lblStatus.Text = $"Report exported to: {saveDialog.FileName}";
                    _lblStatus.ForeColor = Color.DarkGreen;
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Failed to export report: {ex.Message}", "Export Error",
                        MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _cts?.Cancel();
                _cts?.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}
