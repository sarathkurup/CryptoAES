namespace CryptoAES
{
    using System;
    using System.IO;
    using System.Security.Cryptography;
    using System.Text;

    public sealed class CryptoImp : ICrypto
    {
        private const string Salt = "d5fg4df57MyOwnEncRypTiOn745sdfg4";

        /// <summary>
        /// Encrypt a String
        /// </summary>
        /// <param name="Key"></param>
        /// <param name="InputText"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentException"></exception>
        public string EncryptString(string Key, string InputText)
        {
            if (string.IsNullOrEmpty(Key))
                throw new ArgumentException("Key must have valid value.", nameof(Key));
            if (string.IsNullOrEmpty(InputText))
                throw new ArgumentException("The text must have valid value.", nameof(InputText));

            using (Aes myAes = Aes.Create())
            {
                Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(Key, Encoding.ASCII.GetBytes(Salt));
                byte[] bytes = rfc2898DeriveBytes.GetBytes(256 / 8);
                byte[] bytes2 = rfc2898DeriveBytes.GetBytes(128 / 8);
                return EncryptString_Aes(InputText, bytes, bytes2);
            }
        }

        /// <summary>
        /// Decrypt a String
        /// </summary>
        /// <param name="Key"></param>
        /// <param name="encryptedText"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentException"></exception>
        public string DecryptString(string Key, string encryptedText)
        {
            if (string.IsNullOrEmpty(Key))
                throw new ArgumentException("Key must have valid value.", nameof(Key));
            if (string.IsNullOrEmpty(encryptedText))
                throw new ArgumentException("The encrypted text must have valid value.", nameof(encryptedText));

            using (Aes myAes = Aes.Create())
            {
                Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(Key, Encoding.ASCII.GetBytes(Salt));
                byte[] bytes = rfc2898DeriveBytes.GetBytes(256 / 8);
                byte[] bytes2 = rfc2898DeriveBytes.GetBytes(128 / 8);
                byte[] encryptedTextBytes = Convert.FromBase64String(encryptedText);
                return DecryptString_Aes(encryptedTextBytes, bytes, bytes2);
            }
        }

        /// <summary>
        /// Encrypt a File
        /// </summary>
        /// <param name="Key"></param>
        /// <param name="InputStream"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentException"></exception>
        public Stream EncryptFile(string Key, Stream InputStream)
        {
            if (string.IsNullOrEmpty(Key))
                throw new ArgumentException("Key must have valid value.", nameof(Key));
            if (InputStream == null || InputStream.Length <= 0)
                throw new ArgumentException("The Input Stream must have valid value.", nameof(InputStream));

            using (Aes myAes = Aes.Create())
            {
                Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(Key, Encoding.ASCII.GetBytes(Salt));
                byte[] bytes = rfc2898DeriveBytes.GetBytes(256 / 8);
                byte[] bytes2 = rfc2898DeriveBytes.GetBytes(128 / 8);
                return EncryptStream_Aes(InputStream, bytes, bytes2);
            }
        }

        /// <summary>
        /// Decrypt a File
        /// </summary>
        /// <param name="Key"></param>
        /// <param name="CipherStream"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentException"></exception>
        public Stream DecryptFile(string Key, Stream CipherStream)
        {
            if (string.IsNullOrEmpty(Key))
                throw new ArgumentException("Key must have valid value.", nameof(Key));
            if (CipherStream == null || CipherStream.Length <= 0)
                throw new ArgumentException("The Input Stream must have valid value.", nameof(CipherStream));

            using (Aes myAes = Aes.Create())
            {
                Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(Key, Encoding.ASCII.GetBytes(Salt));
                byte[] bytes = rfc2898DeriveBytes.GetBytes(256 / 8);
                byte[] bytes2 = rfc2898DeriveBytes.GetBytes(128 / 8);
                return DecryptStream_Aes(CipherStream, bytes, bytes2);
            }
        }

        #region Private Methods

        private static Stream EncryptStream_Aes(Stream InputStream, byte[] Key, byte[] IV)
        {
            if (InputStream == null || InputStream.Length <= 0)
                throw new ArgumentNullException("Input Stream");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
                try
                {
                    using (CryptoStream csEncrypt = new CryptoStream(InputStream, encryptor, CryptoStreamMode.Write))
                    {
                        return csEncrypt;
                    }
                }
                catch (Exception ex)
                {
                    throw new Exception("Make sure that the keys you use to encrypt and decrypt are the same!! " + ex.Message);
                }
            }
        }

        private static Stream DecryptStream_Aes(Stream CipherStream, byte[] Key, byte[] IV)
        {
            if (CipherStream == null || CipherStream.Length <= 0)
                throw new ArgumentNullException("Input Stream");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
                try
                {
                    using (CryptoStream csEncrypt = new CryptoStream(CipherStream, encryptor, CryptoStreamMode.Read))
                    {
                        return csEncrypt;
                    }
                }
                catch (Exception ex)
                {
                    throw new Exception("Make sure that the keys you use to encrypt and decrypt are the same!! " + ex.Message);
                }
            }
        }

        private static string EncryptString_Aes(string plainText, byte[] Key, byte[] IV)
        {
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            string encrypted = string.Empty;

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
                try
                {
                    using (MemoryStream msEncrypt = new MemoryStream())
                    {
                        using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                        {
                            using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                            {
                                swEncrypt.Write(plainText);
                            }
                            encrypted = Convert.ToBase64String(msEncrypt.ToArray());
                        }
                    }
                }
                catch (Exception ex)
                {
                    throw new Exception("Make sure that the keys you use to encrypt and decrypt are the same!! " + ex.Message);
                }
            }
            return encrypted;
        }

        private static string DecryptString_Aes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            string plaintext = string.Empty;
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                try
                {
                    using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                    {
                        using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                        {
                            using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                            {
                                plaintext = srDecrypt.ReadToEnd();
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    throw new Exception("Make sure that the keys you use to encrypt and decrypt are the same!! " + ex.Message);
                }
            }
            return plaintext;
        }

        #endregion
    }

}