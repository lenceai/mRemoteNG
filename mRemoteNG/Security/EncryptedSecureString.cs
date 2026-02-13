using System;
using System.Security;
using mRemoteNG.Security.SymmetricEncryption;
using Org.BouncyCastle.Security;

// ReSharper disable ArrangeAccessorOwnerBody

namespace mRemoteNG.Security
{
    public class EncryptedSecureString : IDisposable
    {
        private static SecureString _machineKey;
        private SecureString _secureString;
        private readonly ICryptographyProvider _cryptographyProvider;

        private static SecureString MachineKey
        {
            get { return _machineKey ?? (_machineKey = GenerateNewMachineKey(32)); }
        }

        public EncryptedSecureString()
        {
            _secureString = new SecureString();
            _cryptographyProvider = new AeadCryptographyProvider();
        }

        public EncryptedSecureString(ICryptographyProvider cryptographyProvider)
        {
            _secureString = new SecureString();
            _cryptographyProvider = cryptographyProvider;
        }

        public string GetClearTextValue()
        {
            string encryptedText = _secureString.ConvertToUnsecureString();
            string clearText = _cryptographyProvider.Decrypt(encryptedText, MachineKey);
            return clearText;
        }

        public void SetValue(string value)
        {
            string cipherText = _cryptographyProvider.Encrypt(value, MachineKey);
            _secureString = cipherText.ConvertToSecureString();
        }

        private static SecureString GenerateNewMachineKey(int keySize)
        {
            SecureRandom random = new();
            random.SetSeed(random.GenerateSeed(128));

            char[] machineKeyChars = new char[keySize];
            for (int x = 0; x < keySize; x++)
            {
                machineKeyChars[x] = (char)random.Next(33, 126);
            }

            SecureString result = new string(machineKeyChars).ConvertToSecureString();
            Array.Clear(machineKeyChars, 0, machineKeyChars.Length);
            return result;
        }

        private void Dispose(bool disposing)
        {
            if (!disposing) return;

            // Do NOT dispose _machineKey here - it is a static field shared by all instances.
            _secureString?.Dispose();
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
    }
}