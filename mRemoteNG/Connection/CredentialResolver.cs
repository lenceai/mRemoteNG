using System;
using System.Runtime.Versioning;
using mRemoteNG.App;
using mRemoteNG.Messages;
using mRemoteNG.Resources.Language;
using mRemoteNG.Security.SymmetricEncryption;
using mRemoteNG.Tree.Root;

namespace mRemoteNG.Connection
{
    /// <summary>
    /// Holds the resolved credentials from an external credential provider or direct connection info.
    /// </summary>
    public class ResolvedCredentials
    {
        public string Username { get; set; } = "";
        public string Password { get; set; } = "";
        public string Domain { get; set; } = "";
        public string PrivateKey { get; set; } = "";
    }

    /// <summary>
    /// Centralizes credential resolution from external credential providers (DelineaSecretServer,
    /// ClickstudiosPasswordState, OnePassword, VaultOpenbao) eliminating duplication across
    /// RdpProtocol, PuttyBase, and other protocol implementations.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public static class CredentialResolver
    {
        /// <summary>
        /// Resolves credentials for a connection, checking external credential providers first,
        /// then falling back to direct connection info fields, then to default credentials.
        /// </summary>
        public static ResolvedCredentials Resolve(ConnectionInfo connectionInfo, Action<string, int?> errorCallback = null)
        {
            if (connectionInfo == null)
                return new ResolvedCredentials();

            ResolvedCredentials creds = new()
            {
                Username = connectionInfo.Username ?? "",
                Password = connectionInfo.Password ?? "",
                Domain = connectionInfo.Domain ?? ""
            };

            string userViaApi = connectionInfo.UserViaAPI ?? "";

            // Resolve from external credential provider if configured
            if (connectionInfo.ExternalCredentialProvider != ExternalCredentialProvider.None)
            {
                ResolveFromExternalProvider(connectionInfo.ExternalCredentialProvider, userViaApi, connectionInfo, creds, errorCallback);
            }

            // Apply fallback defaults if username is still empty
            if (string.IsNullOrEmpty(creds.Username))
            {
                ApplyDefaultCredentials(creds, connectionInfo, errorCallback);
            }

            // Apply fallback for empty password
            if (string.IsNullOrEmpty(creds.Password) && string.IsNullOrEmpty(creds.PrivateKey))
            {
                ApplyDefaultPassword(creds);
            }

            return creds;
        }

        /// <summary>
        /// Resolves RD Gateway credentials from a connection, using the gateway-specific external provider settings.
        /// </summary>
        public static ResolvedCredentials ResolveGateway(ConnectionInfo connectionInfo, Action<string, int?> errorCallback = null)
        {
            if (connectionInfo == null)
                return new ResolvedCredentials();

            ResolvedCredentials creds = new()
            {
                Username = connectionInfo.RDGatewayUsername ?? "",
                Password = connectionInfo.RDGatewayPassword ?? "",
                Domain = connectionInfo.RDGatewayDomain ?? ""
            };

            string userViaApi = connectionInfo.RDGatewayUserViaAPI ?? "";

            if (connectionInfo.RDGatewayExternalCredentialProvider != ExternalCredentialProvider.None)
            {
                ResolveFromExternalProvider(connectionInfo.RDGatewayExternalCredentialProvider, userViaApi, connectionInfo, creds, errorCallback);
            }

            return creds;
        }

        private static void ResolveFromExternalProvider(
            ExternalCredentialProvider provider,
            string userViaApi,
            ConnectionInfo connectionInfo,
            ResolvedCredentials creds,
            Action<string, int?> errorCallback)
        {
            try
            {
                switch (provider)
                {
                    case ExternalCredentialProvider.DelineaSecretServer:
                        ExternalConnectors.DSS.SecretServerInterface.FetchSecretFromServer(
                            $"{userViaApi}", out string dssUser, out string dssPass, out string dssDomain, out string dssPkey);
                        creds.Username = dssUser;
                        creds.Password = dssPass;
                        creds.Domain = dssDomain;
                        creds.PrivateKey = dssPkey;
                        break;

                    case ExternalCredentialProvider.ClickstudiosPasswordState:
                        ExternalConnectors.CPS.PasswordstateInterface.FetchSecretFromServer(
                            $"{userViaApi}", out string cpsUser, out string cpsPass, out string cpsDomain, out string cpsPkey);
                        creds.Username = cpsUser;
                        creds.Password = cpsPass;
                        creds.Domain = cpsDomain;
                        creds.PrivateKey = cpsPkey;
                        break;

                    case ExternalCredentialProvider.OnePassword:
                        try
                        {
                            ExternalConnectors.OP.OnePasswordCli.ReadPassword(
                                $"{userViaApi}", out string opUser, out string opPass, out string opDomain, out string opPkey);
                            creds.Username = opUser;
                            creds.Password = opPass;
                            creds.Domain = opDomain;
                            creds.PrivateKey = opPkey;
                        }
                        catch (ExternalConnectors.OP.OnePasswordCliException ex)
                        {
                            Runtime.MessageCollector.AddMessage(MessageClass.InformationMsg,
                                Language.ECPOnePasswordCommandLine + ": " + ex.Arguments);
                            Runtime.MessageCollector.AddMessage(MessageClass.ErrorMsg,
                                Language.ECPOnePasswordReadFailed + Environment.NewLine + ex.Message);
                        }
                        break;

                    case ExternalCredentialProvider.VaultOpenbao:
                        ResolveFromVaultOpenbao(connectionInfo, creds, errorCallback);
                        break;
                }
            }
            catch (Exception ex) when (provider != ExternalCredentialProvider.OnePassword)
            {
                string providerName = provider.ToString();
                errorCallback?.Invoke($"{providerName} Interface Error: " + ex.Message, 0);
            }
        }

        private static void ResolveFromVaultOpenbao(ConnectionInfo connectionInfo, ResolvedCredentials creds, Action<string, int?> errorCallback)
        {
            try
            {
                if (connectionInfo.VaultOpenbaoSecretEngine == VaultOpenbaoSecretEngine.Kv)
                    creds.Username = connectionInfo.Username ?? "";

                ExternalConnectors.VO.VaultOpenbao.ReadPasswordRDP(
                    (int)connectionInfo.VaultOpenbaoSecretEngine,
                    connectionInfo.VaultOpenbaoMount ?? "",
                    connectionInfo.VaultOpenbaoRole ?? "",
                    ref creds.Username,
                    out string vaultPass);
                creds.Password = vaultPass;
            }
            catch (ExternalConnectors.VO.VaultOpenbaoException ex)
            {
                errorCallback?.Invoke("Vault/OpenBao Interface Error: " + ex.Message, 0);
            }
        }

        private static void ApplyDefaultCredentials(ResolvedCredentials creds, ConnectionInfo connectionInfo, Action<string, int?> errorCallback)
        {
            switch (Properties.OptionsCredentialsPage.Default.EmptyCredentials)
            {
                case "windows":
                    creds.Username = Environment.UserName;
                    creds.Domain = Environment.UserDomainName;
                    break;
                case "custom":
                    if (!string.IsNullOrEmpty(Properties.OptionsCredentialsPage.Default.DefaultUsername))
                    {
                        creds.Username = Properties.OptionsCredentialsPage.Default.DefaultUsername;
                        creds.Domain = Properties.OptionsCredentialsPage.Default.DefaultDomain;
                    }
                    else
                    {
                        // Try fetching from the default external credential provider
                        try
                        {
                            if (Properties.OptionsCredentialsPage.Default.ExternalCredentialProviderDefault == ExternalCredentialProvider.DelineaSecretServer)
                            {
                                ExternalConnectors.DSS.SecretServerInterface.FetchSecretFromServer(
                                    Properties.OptionsCredentialsPage.Default.UserViaAPIDefault,
                                    out string defUser, out string defPass, out string defDomain, out string defPkey);
                                creds.Username = defUser;
                                creds.Password = defPass;
                                creds.Domain = defDomain;
                                creds.PrivateKey = defPkey;
                            }
                        }
                        catch (Exception ex)
                        {
                            errorCallback?.Invoke("Secret Server Interface Error: " + ex.Message, 0);
                        }
                    }
                    break;
            }
        }

        private static void ApplyDefaultPassword(ResolvedCredentials creds)
        {
            if (Properties.OptionsCredentialsPage.Default.EmptyCredentials == "custom"
                && !string.IsNullOrEmpty(Properties.OptionsCredentialsPage.Default.DefaultPassword))
            {
                LegacyRijndaelCryptographyProvider cryptographyProvider = new();
                creds.Password = cryptographyProvider.Decrypt(
                    Properties.OptionsCredentialsPage.Default.DefaultPassword,
                    Runtime.EncryptionKey);
            }
        }
    }
}
