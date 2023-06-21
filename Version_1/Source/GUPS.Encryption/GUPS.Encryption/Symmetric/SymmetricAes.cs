// System
using System;
using System.IO;
using System.Security.Cryptography;

namespace GUPS.Encryption.Symmetric
{
    /// <summary>
    /// This class implements the ISymmetric interface and provides the logic for performing encryption and decryption using the AES algorithm.
    /// </summary>
    public class SymmetricAes : ISymmetric
    {
        /// <summary>
        /// Key size in bits.
        /// </summary>
        private int keySize;

        /// <summary>
        /// Used cipher mode.
        /// </summary>
        private CipherMode cipherMode;

        /// <summary>
        /// Used padding mode.
        /// </summary>
        private PaddingMode paddingMode;

        /// <summary>
        /// Used AES algorithm.
        /// </summary>
        private Aes aes;

        /// <summary>
        /// Create a new instance of SymmetricAes with the specified key size in bits (AES-128: 16 bytes (128 bits), AES-192: 24 bytes(192 bits), AES-256: 32 bytes(256 bits)). 
        /// Default cipher mode is CBC and default padding mode is PKCS7.
        /// </summary>
        /// <param name="_KeySize">The key size in bits (128, 192, or 256).</param>
        public SymmetricAes(int _KeySize) 
            : this(_KeySize, CipherMode.CBC, PaddingMode.PKCS7)
        {
        }

        /// <summary>
        /// Create a new instance of SymmetricAes with the specified key size, cipher mode and padding mode. Generate random new key and iv.
        /// </summary>
        /// <param name="_KeySize">The key size in bits (128, 192, or 256).</param>
        /// <param name="_CipherMode">The cipher mode to use for encryption and decryption.</param>
        /// <param name="_PaddingMode">The padding mode to use for encryption and decryption.</param>
        public SymmetricAes(int _KeySize, CipherMode _CipherMode, PaddingMode _PaddingMode)
        {
            // Pass the parameters to the variables.
            this.keySize = _KeySize;
            this.cipherMode = _CipherMode;
            this.paddingMode = _PaddingMode;

            // Create a new instance of AES.
            this.aes = Aes.Create();
            this.aes.KeySize = this.keySize;
            this.aes.Mode = this.cipherMode;
            this.aes.Padding = this.paddingMode;

            // Generate the IV and key.
            this.aes.GenerateKey();
            this.aes.GenerateIV();
        }

        /// <summary>
        /// Create a new instance of SymmetricAes with the specified key size, cipher mode, padding mode, key and iv.
        /// </summary>
        /// <param name="_KeySize">The key size in bits (128, 192, or 256).</param>
        /// <param name="_CipherMode">The cipher mode to use for encryption and decryption.</param>
        /// <param name="_PaddingMode">The padding mode to use for encryption and decryption.</param>
        /// <param name="_Key">The key used for encryption and decryption.</param>
        /// <param name="_Iv">The iv used for encryption and decryption.</param>
        public SymmetricAes(int _KeySize, CipherMode _CipherMode, PaddingMode _PaddingMode, byte[] _Key, byte[] _Iv)
        {
            // Pass the parameters to the variables.
            this.keySize = _KeySize;
            this.cipherMode = _CipherMode;
            this.paddingMode = _PaddingMode;

            // Create a new instance of AES.
            this.aes = Aes.Create();
            this.aes.KeySize = this.keySize;
            this.aes.Mode = this.cipherMode;
            this.aes.Padding = this.paddingMode;
            this.aes.Key = _Key;
            this.aes.IV = _Iv;
        }

        /// <summary>
        /// Returns the key, used in the symmetric encryption algorithms.
        /// </summary>
        /// <returns>The key used for encryption and decryption.</returns>
        public byte[] GetKey()
        {
            return this.aes.Key;
        }

        /// <summary>
        /// Returns the iv, used in the symmetric encryption algorithms.
        /// </summary>
        /// <returns>The initialization vector (IV) used for encryption and decryption.</returns>
        public byte[] GetIV()
        {
            return this.aes.IV;
        }

        /// <summary>
        /// Encrypts the input data using the AES algorithm.
        /// </summary>
        /// <param name="_Data">The data to be encrypted.</param>
        /// <returns>The encrypted data.</returns>
        public byte[] Encrypt(byte[] _Data)
        {
            using (ICryptoTransform var_Encryptor = this.aes.CreateEncryptor(this.aes.Key, this.aes.IV))
            {
                using (MemoryStream var_MemoryStream = new MemoryStream())
                {
                    using (CryptoStream var_CryptoStream = new CryptoStream(var_MemoryStream, var_Encryptor, CryptoStreamMode.Write))
                    {
                        var_CryptoStream.Write(_Data, 0, _Data.Length);
                        var_CryptoStream.FlushFinalBlock();
                    }
                    return var_MemoryStream.ToArray();
                }
            }
        }

        /// <summary>
        /// Decrypts the input data using the AES algorithm.
        /// </summary>
        /// <param name="_EncryptedData">The data to be decrypted.</param>
        /// <returns>The decrypted data.</returns>
        public byte[] Decrypt(byte[] _EncryptedData)
        {
            using (ICryptoTransform decryptor = this.aes.CreateDecryptor(this.aes.Key, this.aes.IV))
            {
                using (MemoryStream var_MemoryStream = new MemoryStream(_EncryptedData))
                {
                    using (CryptoStream var_CryptoStream = new CryptoStream(var_MemoryStream, decryptor, CryptoStreamMode.Read))
                    {
                        byte[] var_DecryptedData = new byte[_EncryptedData.Length];
                        int var_DecryptedLength = var_CryptoStream.Read(var_DecryptedData, 0, var_DecryptedData.Length);
                        byte[] var_Result = new byte[var_DecryptedLength];
                        Array.Copy(var_DecryptedData, var_Result, var_DecryptedLength);
                        return var_Result;
                    }
                }
            }
        }
    }
}
