using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Text;

namespace mRemoteNG.Tools.SecurityScanner
{
    /// <summary>
    /// Collects system information for security analysis including OS details,
    /// running processes, network connections, installed software, and security configuration.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public static class SystemInfoCollector
    {
        /// <summary>
        /// Collects comprehensive system information and returns it as a formatted string
        /// suitable for LLM analysis.
        /// </summary>
        public static string CollectAll()
        {
            StringBuilder sb = new();

            sb.AppendLine("=== SYSTEM SECURITY SCAN DATA ===");
            sb.AppendLine($"Scan Time: {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC");
            sb.AppendLine();

            try { AppendOsInfo(sb); } catch (Exception ex) { sb.AppendLine($"[ERROR collecting OS info: {ex.Message}]"); }
            try { AppendRunningProcesses(sb); } catch (Exception ex) { sb.AppendLine($"[ERROR collecting processes: {ex.Message}]"); }
            try { AppendNetworkConnections(sb); } catch (Exception ex) { sb.AppendLine($"[ERROR collecting network info: {ex.Message}]"); }
            try { AppendInstalledSoftware(sb); } catch (Exception ex) { sb.AppendLine($"[ERROR collecting software info: {ex.Message}]"); }
            try { AppendFirewallStatus(sb); } catch (Exception ex) { sb.AppendLine($"[ERROR collecting firewall info: {ex.Message}]"); }
            try { AppendUserAccounts(sb); } catch (Exception ex) { sb.AppendLine($"[ERROR collecting user info: {ex.Message}]"); }
            try { AppendWindowsUpdateInfo(sb); } catch (Exception ex) { sb.AppendLine($"[ERROR collecting update info: {ex.Message}]"); }
            try { AppendSharedFolders(sb); } catch (Exception ex) { sb.AppendLine($"[ERROR collecting share info: {ex.Message}]"); }
            try { AppendStartupPrograms(sb); } catch (Exception ex) { sb.AppendLine($"[ERROR collecting startup info: {ex.Message}]"); }
            try { AppendAntivirusStatus(sb); } catch (Exception ex) { sb.AppendLine($"[ERROR collecting antivirus info: {ex.Message}]"); }

            return sb.ToString();
        }

        private static void AppendOsInfo(StringBuilder sb)
        {
            sb.AppendLine("--- OPERATING SYSTEM ---");
            sb.AppendLine($"OS: {Environment.OSVersion}");
            sb.AppendLine($"Machine Name: {Environment.MachineName}");
            sb.AppendLine($"64-bit OS: {Environment.Is64BitOperatingSystem}");
            sb.AppendLine($"64-bit Process: {Environment.Is64BitProcess}");
            sb.AppendLine($".NET Version: {Environment.Version}");
            sb.AppendLine($"User: {Environment.UserName}");
            sb.AppendLine($"Domain: {Environment.UserDomainName}");
            sb.AppendLine($"Processor Count: {Environment.ProcessorCount}");

            try
            {
                using ManagementObjectSearcher searcher = new("SELECT * FROM Win32_OperatingSystem");
                foreach (ManagementObject obj in searcher.Get().Cast<ManagementObject>())
                {
                    sb.AppendLine($"OS Name: {obj["Caption"]}");
                    sb.AppendLine($"OS Version: {obj["Version"]}");
                    sb.AppendLine($"Build Number: {obj["BuildNumber"]}");
                    sb.AppendLine($"OS Architecture: {obj["OSArchitecture"]}");
                    sb.AppendLine($"Last Boot: {ManagementDateTimeConverter.ToDateTime(obj["LastBootUpTime"]?.ToString() ?? "")}");
                }
            }
            catch { /* WMI may not be available */ }

            sb.AppendLine();
        }

        private static void AppendRunningProcesses(StringBuilder sb)
        {
            sb.AppendLine("--- RUNNING PROCESSES (top 50 by memory) ---");
            Process[] processes = Process.GetProcesses();
            var sorted = processes
                .Select(p =>
                {
                    try { return new { p.ProcessName, p.Id, Memory = p.WorkingSet64, Path = GetProcessPath(p) }; }
                    catch { return new { ProcessName = p.ProcessName, Id = p.Id, Memory = 0L, Path = "N/A" }; }
                })
                .OrderByDescending(p => p.Memory)
                .Take(50);

            foreach (var p in sorted)
            {
                sb.AppendLine($"  PID {p.Id,-6} | {p.ProcessName,-30} | {p.Memory / 1024 / 1024,6} MB | {p.Path}");
            }
            sb.AppendLine($"Total processes: {processes.Length}");
            sb.AppendLine();
        }

        private static string GetProcessPath(Process process)
        {
            try { return process.MainModule?.FileName ?? "N/A"; }
            catch { return "Access Denied"; }
        }

        private static void AppendNetworkConnections(StringBuilder sb)
        {
            sb.AppendLine("--- ACTIVE NETWORK CONNECTIONS ---");

            IPGlobalProperties ipProperties = IPGlobalProperties.GetIPGlobalProperties();

            // TCP Listeners (open ports)
            sb.AppendLine("  Listening TCP Ports:");
            foreach (IPEndPoint ep in ipProperties.GetActiveTcpListeners())
            {
                sb.AppendLine($"    {ep.Address}:{ep.Port}");
            }

            // Active TCP connections
            sb.AppendLine("  Active TCP Connections:");
            TcpConnectionInformation[] tcpConnections = ipProperties.GetActiveTcpConnections();
            foreach (TcpConnectionInformation conn in tcpConnections.Take(50))
            {
                sb.AppendLine($"    {conn.LocalEndPoint} -> {conn.RemoteEndPoint} [{conn.State}]");
            }
            if (tcpConnections.Length > 50)
                sb.AppendLine($"    ... and {tcpConnections.Length - 50} more connections");

            // UDP Listeners
            sb.AppendLine("  Listening UDP Ports:");
            foreach (IPEndPoint ep in ipProperties.GetActiveUdpListeners().Take(30))
            {
                sb.AppendLine($"    {ep.Address}:{ep.Port}");
            }

            sb.AppendLine();
        }

        private static void AppendInstalledSoftware(StringBuilder sb)
        {
            sb.AppendLine("--- INSTALLED SOFTWARE (from registry) ---");
            string[] registryPaths =
            {
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
            };

            HashSet<string> seen = new(StringComparer.OrdinalIgnoreCase);

            foreach (string path in registryPaths)
            {
                try
                {
                    using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(path);
                    if (key == null) continue;

                    foreach (string subKeyName in key.GetSubKeyNames())
                    {
                        try
                        {
                            using var subKey = key.OpenSubKey(subKeyName);
                            string name = subKey?.GetValue("DisplayName")?.ToString();
                            if (string.IsNullOrWhiteSpace(name) || !seen.Add(name)) continue;

                            string version = subKey?.GetValue("DisplayVersion")?.ToString() ?? "";
                            string publisher = subKey?.GetValue("Publisher")?.ToString() ?? "";
                            sb.AppendLine($"  {name} | v{version} | {publisher}");
                        }
                        catch { /* skip inaccessible entries */ }
                    }
                }
                catch { /* skip inaccessible registry paths */ }
            }
            sb.AppendLine();
        }

        private static void AppendFirewallStatus(StringBuilder sb)
        {
            sb.AppendLine("--- FIREWALL STATUS ---");
            try
            {
                using ManagementObjectSearcher searcher = new(
                    @"root\StandardCimv2",
                    "SELECT * FROM MSFT_NetFirewallProfile");

                foreach (ManagementObject obj in searcher.Get().Cast<ManagementObject>())
                {
                    string name = obj["Name"]?.ToString() ?? "Unknown";
                    string enabled = obj["Enabled"]?.ToString() ?? "Unknown";
                    sb.AppendLine($"  Profile: {name} | Enabled: {enabled}");
                }
            }
            catch
            {
                // Fallback: use netsh
                try
                {
                    ProcessStartInfo psi = new("netsh", "advfirewall show allprofiles state")
                    {
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    };
                    using Process proc = Process.Start(psi);
                    string output = proc?.StandardOutput.ReadToEnd() ?? "";
                    proc?.WaitForExit(5000);
                    sb.AppendLine(output);
                }
                catch (Exception ex)
                {
                    sb.AppendLine($"  Could not determine firewall status: {ex.Message}");
                }
            }
            sb.AppendLine();
        }

        private static void AppendUserAccounts(StringBuilder sb)
        {
            sb.AppendLine("--- LOCAL USER ACCOUNTS ---");
            try
            {
                using ManagementObjectSearcher searcher = new("SELECT * FROM Win32_UserAccount WHERE LocalAccount=True");
                foreach (ManagementObject obj in searcher.Get().Cast<ManagementObject>())
                {
                    string name = obj["Name"]?.ToString() ?? "";
                    bool disabled = (bool)(obj["Disabled"] ?? false);
                    bool lockout = (bool)(obj["Lockout"] ?? false);
                    bool passRequired = (bool)(obj["PasswordRequired"] ?? true);
                    sb.AppendLine($"  {name} | Disabled: {disabled} | Locked: {lockout} | PasswordRequired: {passRequired}");
                }
            }
            catch (Exception ex)
            {
                sb.AppendLine($"  Could not enumerate users: {ex.Message}");
            }
            sb.AppendLine();
        }

        private static void AppendWindowsUpdateInfo(StringBuilder sb)
        {
            sb.AppendLine("--- RECENT WINDOWS UPDATES (last 10) ---");
            try
            {
                using ManagementObjectSearcher searcher = new("SELECT * FROM Win32_QuickFixEngineering");
                var updates = searcher.Get().Cast<ManagementObject>()
                    .Select(obj => new
                    {
                        HotFixID = obj["HotFixID"]?.ToString() ?? "",
                        Description = obj["Description"]?.ToString() ?? "",
                        InstalledOn = obj["InstalledOn"]?.ToString() ?? ""
                    })
                    .OrderByDescending(u => u.InstalledOn)
                    .Take(10);

                foreach (var u in updates)
                {
                    sb.AppendLine($"  {u.HotFixID} | {u.Description} | {u.InstalledOn}");
                }
            }
            catch (Exception ex)
            {
                sb.AppendLine($"  Could not enumerate updates: {ex.Message}");
            }
            sb.AppendLine();
        }

        private static void AppendSharedFolders(StringBuilder sb)
        {
            sb.AppendLine("--- NETWORK SHARES ---");
            try
            {
                using ManagementObjectSearcher searcher = new("SELECT * FROM Win32_Share");
                foreach (ManagementObject obj in searcher.Get().Cast<ManagementObject>())
                {
                    string name = obj["Name"]?.ToString() ?? "";
                    string path = obj["Path"]?.ToString() ?? "";
                    string description = obj["Description"]?.ToString() ?? "";
                    sb.AppendLine($"  {name} -> {path} ({description})");
                }
            }
            catch (Exception ex)
            {
                sb.AppendLine($"  Could not enumerate shares: {ex.Message}");
            }
            sb.AppendLine();
        }

        private static void AppendStartupPrograms(StringBuilder sb)
        {
            sb.AppendLine("--- STARTUP PROGRAMS ---");
            try
            {
                using ManagementObjectSearcher searcher = new("SELECT * FROM Win32_StartupCommand");
                foreach (ManagementObject obj in searcher.Get().Cast<ManagementObject>())
                {
                    string name = obj["Name"]?.ToString() ?? "";
                    string command = obj["Command"]?.ToString() ?? "";
                    string location = obj["Location"]?.ToString() ?? "";
                    string user = obj["User"]?.ToString() ?? "";
                    sb.AppendLine($"  {name} | {command} | Location: {location} | User: {user}");
                }
            }
            catch (Exception ex)
            {
                sb.AppendLine($"  Could not enumerate startup programs: {ex.Message}");
            }
            sb.AppendLine();
        }

        private static void AppendAntivirusStatus(StringBuilder sb)
        {
            sb.AppendLine("--- ANTIVIRUS / SECURITY PRODUCTS ---");
            try
            {
                using ManagementObjectSearcher searcher = new(
                    @"root\SecurityCenter2",
                    "SELECT * FROM AntiVirusProduct");

                foreach (ManagementObject obj in searcher.Get().Cast<ManagementObject>())
                {
                    string displayName = obj["displayName"]?.ToString() ?? "";
                    string productState = obj["productState"]?.ToString() ?? "";
                    sb.AppendLine($"  {displayName} | State: {productState}");
                }
            }
            catch
            {
                sb.AppendLine("  Could not query SecurityCenter2 (may require elevated privileges or server OS)");
            }

            // Also check Windows Defender status
            try
            {
                ProcessStartInfo psi = new("powershell", "-NoProfile -Command \"Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureLastUpdated | Format-List\"")
                {
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                using Process proc = Process.Start(psi);
                string output = proc?.StandardOutput.ReadToEnd() ?? "";
                proc?.WaitForExit(10000);
                if (!string.IsNullOrWhiteSpace(output))
                {
                    sb.AppendLine("  Windows Defender:");
                    sb.AppendLine(output);
                }
            }
            catch { /* Defender query failed */ }

            sb.AppendLine();
        }
    }
}
