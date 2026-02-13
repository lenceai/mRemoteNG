using System;
using System.Runtime.Versioning;
using System.Windows.Forms;
using mRemoteNG.App;
using mRemoteNG.Connection;
using mRemoteNG.Connection.Protocol;
using mRemoteNG.Credential;
using mRemoteNG.Resources.Language;
using mRemoteNG.UI.Forms;

namespace mRemoteNG.UI.Menu
{
    [SupportedOSPlatform("windows")]
    public class ToolsMenu : ToolStripMenuItem
    {
        private ToolStripMenuItem _mMenToolsSshTransfer;
        private ToolStripMenuItem _mMenToolsExternalApps;
        private ToolStripMenuItem _mMenToolsPortScan;
        private ToolStripMenuItem _mMenToolsUvncsc;
        private ToolStripSeparator _mMenToolsSep1;
        private ToolStripMenuItem _mMenToolsSpanAllScreens;
        private ToolStripSeparator _mMenToolsSep2;
        private ToolStripMenuItem _mMenToolsSecurityScan;

        public Form MainForm { get; set; }
        public ICredentialRepositoryList CredentialProviderCatalog { get; set; }

        public ToolsMenu()
        {
            Initialize();
        }

        private void Initialize()
        {
            _mMenToolsSshTransfer = new ToolStripMenuItem();
            _mMenToolsUvncsc = new ToolStripMenuItem();
            _mMenToolsExternalApps = new ToolStripMenuItem();
            _mMenToolsPortScan = new ToolStripMenuItem();
            _mMenToolsSep1 = new ToolStripSeparator();
            _mMenToolsSpanAllScreens = new ToolStripMenuItem();
            _mMenToolsSep2 = new ToolStripSeparator();
            _mMenToolsSecurityScan = new ToolStripMenuItem();
            // 
            // mMenTools
            // 
            DropDownItems.AddRange(new ToolStripItem[]
            {
                _mMenToolsSshTransfer,
                _mMenToolsUvncsc,
                _mMenToolsExternalApps,
                _mMenToolsPortScan,
                _mMenToolsSep1,
                _mMenToolsSpanAllScreens,
                _mMenToolsSep2,
                _mMenToolsSecurityScan
            });
            Name = "mMenTools";
            Size = new System.Drawing.Size(48, 20);
            Text = Language._Tools;
            // 
            // mMenToolsSSHTransfer
            // 
            _mMenToolsSshTransfer.Image = Properties.Resources.SyncArrow_16x;
            _mMenToolsSshTransfer.Name = "mMenToolsSSHTransfer";
            _mMenToolsSshTransfer.Size = new System.Drawing.Size(184, 22);
            _mMenToolsSshTransfer.Text = Language.SshFileTransfer;
            _mMenToolsSshTransfer.Click += mMenToolsSSHTransfer_Click;
            // 
            // mMenToolsUVNCSC
            // 
            _mMenToolsUvncsc.Name = "mMenToolsUVNCSC";
            _mMenToolsUvncsc.Size = new System.Drawing.Size(184, 22);
            _mMenToolsUvncsc.Text = Language.UltraVNCSingleClick;
            _mMenToolsUvncsc.Visible = false;
            _mMenToolsUvncsc.Click += mMenToolsUVNCSC_Click;
            // 
            // mMenToolsExternalApps
            // 
            _mMenToolsExternalApps.Image = Properties.Resources.Console_16x;
            _mMenToolsExternalApps.Name = "mMenToolsExternalApps";
            _mMenToolsExternalApps.Size = new System.Drawing.Size(184, 22);
            _mMenToolsExternalApps.Text = Language.ExternalTool;
            _mMenToolsExternalApps.Click += mMenToolsExternalApps_Click;
            // 
            // mMenToolsPortScan
            // 
            _mMenToolsPortScan.Image = Properties.Resources.SearchAndApps_16x;
            _mMenToolsPortScan.Name = "mMenToolsPortScan";
            _mMenToolsPortScan.Size = new System.Drawing.Size(184, 22);
            _mMenToolsPortScan.Text = Language.PortScan;
            _mMenToolsPortScan.Click += mMenToolsPortScan_Click;
            //
            // separator
            //
            _mMenToolsSep1.Name = "mMenToolsSep1";
            _mMenToolsSep1.Size = new System.Drawing.Size(181, 6);
            //
            // mMenToolsSpanAllScreens
            //
            _mMenToolsSpanAllScreens.Image = Properties.Resources.Monitor_16x;
            _mMenToolsSpanAllScreens.Name = "mMenToolsSpanAllScreens";
            _mMenToolsSpanAllScreens.Size = new System.Drawing.Size(184, 22);
            _mMenToolsSpanAllScreens.Text = "RDP Span All Screens";
            _mMenToolsSpanAllScreens.Click += mMenToolsSpanAllScreens_Click;
            //
            // separator
            //
            _mMenToolsSep2.Name = "mMenToolsSep2";
            _mMenToolsSep2.Size = new System.Drawing.Size(181, 6);
            //
            // mMenToolsSecurityScan
            //
            _mMenToolsSecurityScan.Image = Properties.Resources.UniqueKeyError_16x;
            _mMenToolsSecurityScan.Name = "mMenToolsSecurityScan";
            _mMenToolsSecurityScan.Size = new System.Drawing.Size(184, 22);
            _mMenToolsSecurityScan.Text = "AI Security Scan";
            _mMenToolsSecurityScan.Click += mMenToolsSecurityScan_Click;
        }

        public void ApplyLanguage()
        {
            Text = Language._Tools;
            _mMenToolsSshTransfer.Text = Language.SshFileTransfer;
            _mMenToolsExternalApps.Text = Language.ExternalTool;
            _mMenToolsPortScan.Text = Language.PortScan;
            _mMenToolsSpanAllScreens.Text = "RDP Span All Screens";
            _mMenToolsSecurityScan.Text = "AI Security Scan";
        }

        #region Tools

        private void mMenToolsSSHTransfer_Click(object sender, EventArgs e)
        {
            AppWindows.Show(WindowType.SSHTransfer);
        }

        private void mMenToolsUVNCSC_Click(object sender, EventArgs e)
        {
            AppWindows.Show(WindowType.UltraVNCSC);
        }

        private void mMenToolsExternalApps_Click(object sender, EventArgs e)
        {
            AppWindows.Show(WindowType.ExternalApps);
        }

        private void mMenToolsPortScan_Click(object sender, EventArgs e)
        {
            AppWindows.Show(WindowType.PortScan);
        }

        private void mMenToolsOptions_Click(object sender, EventArgs e)
        {
            AppWindows.Show(WindowType.Options);
        }

        private void mMenToolsSpanAllScreens_Click(object sender, EventArgs e)
        {
            try
            {
                ConnectionInfo selectedConnection = FrmMain.Default.SelectedConnection;
                if (selectedConnection == null)
                {
                    MessageBox.Show("Please select an RDP connection first.", "Span All Screens",
                        MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                }

                if (selectedConnection.Protocol != ProtocolType.RDP)
                {
                    MessageBox.Show("Spanning all screens is only supported for RDP connections.", "Span All Screens",
                        MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                }

                Runtime.ConnectionInitiator.OpenConnection(selectedConnection,
                    ConnectionInfo.Force.SpanAllScreens | ConnectionInfo.Force.DoNotJump);
            }
            catch (Exception ex)
            {
                Runtime.MessageCollector.AddExceptionStackTrace("Span All Screens failed", ex);
            }
        }

        private void mMenToolsSecurityScan_Click(object sender, EventArgs e)
        {
            try
            {
                FrmSecurityScan securityScanForm = new();
                securityScanForm.Show(MainForm);
            }
            catch (Exception ex)
            {
                Runtime.MessageCollector.AddExceptionStackTrace("Security Scan launch failed", ex);
            }
        }

        #endregion
    }
}