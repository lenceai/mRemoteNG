using System;
using System.Text;
using Org.BouncyCastle.Security;

namespace mRemoteNG.Security
{
    public class RandomGenerator
    {
        private static readonly SecureRandom SharedRandom = new();

        public static string RandomString(int length)
        {
            if (length < 0)
                throw new ArgumentException($"{nameof(length)} must be a positive integer");

            SecureRandom randomGen = SharedRandom;
            StringBuilder stringBuilder = new(length);
            const string availableChars =
                @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789`~!@#$%^&*()-_=+|[]{};:',./<>?";
            for (int x = 0; x < length; x++)
            {
                int randomIndex = randomGen.Next(availableChars.Length - 1);
                stringBuilder.Append(availableChars[randomIndex]);
            }

            return stringBuilder.ToString();
        }
    }
}