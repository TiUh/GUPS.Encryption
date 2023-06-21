// System
using System;
using System.IO;
using System.Security.Cryptography;

namespace GUPS.Encryption.Symmetric
{
    /// <summary>
    /// This class implements the ISymmetric interface and provides the logic for performing encryption and decryption using the DES algorithm.
    /// But it is recommended to use AES instead of DES. Use only for compatibility with legacy systems.
    /// </summary>
    public class SymmetricDes : ISymmetric
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
        /// Used DES algorithm.
        /// </summary>
        private DES des;

        /// <summary>
        /// Create a new instance of SymmetricDes with the specified key size in bits. 
        /// Default key size is 64 bits, default cipher mode is CBC and default padding mode is PKCS7.
        /// </summary>
        public SymmetricDes()
            : this(64, CipherMode.CBC, PaddingMode.PKCS7)
        {
        }

        /// <summary>
        /// Create a new instance of SymmetricDes with the specified key size, cipher mode and padding mode.
        /// </summary>
        /// <param name="_KeySize">The key size in bits (64).</param>
        /// <param name="_CipherMode">The cipher mode to use for encryption and decryption.</param>
        /// <param name="_PaddingMode">The padding mode to use for encryption and decryption.</param>
        public SymmetricDes(int _KeySize, CipherMode _CipherMode, PaddingMode _PaddingMode)
        {
            // Pass the parameters to the variables.
            this.keySize = _KeySize;
            this.cipherMode = _CipherMode;
            this.paddingMode = _PaddingMode;

            // Create a new instance of DES.
            this.des = DES.Create();
            this.des.KeySize = this.keySize;
            this.des.Mode = this.cipherMode;
            this.des.Padding = this.paddingMode;

            // Generate the IV and key.
            this.des.GenerateKey();
            this.des.GenerateIV();
        }

        /// <summary>
        /// Create a new instance of SymmetricDes with the specified key size, cipher mode, padding mode, key and iv.
        /// </summary>
        /// <param name="_KeySize">The key size in bits (64).</param>
        /// <param name="_CipherMode">The cipher mode to use for encryption and decryption.</param>
        /// <param name="_PaddingMode">The padding mode to use for encryption and decryption.</param>
        /// <param name="_Key">The key used for encryption and decryption.</param>
        /// <param name="_Iv">The iv used for encryption and decryption.</param>
        public SymmetricDes(int _KeySize, CipherMode _CipherMode, PaddingMode _PaddingMode, byte[] _Key, byte[] _Iv)
        {
            // Pass the parameters to the variables.
            this.keySize = _KeySize;
            this.cipherMode = _CipherMode;
            this.paddingMode = _PaddingMode;

            // Create a new instance of DES.
            this.des = DES.Create();
            this.des.KeySize = this.keySize;
            this.des.Mode = this.cipherMode;
            this.des.Padding = this.paddingMode;
            this.des.Key = _Key;
            this.des.IV = _Iv;
        }

        /// <summary>
        /// Returns the key, used in the symmetric encryption algorithms.
        /// </summary>
        /// <returns>The key used for encryption and decryption.</returns>
        public byte[] GetKey()
        {
            return this.des.Key;
        }

        /// <summary>
        /// Returns the iv, used in the symmetric encryption algorithms.
        /// </summary>
        /// <returns>The initialization vector (IV) used for encryption and decryption.</returns>
        public byte[] GetIV()
        {
            return this.des.IV;
        }

        /// <summary>
        /// Encrypts the input data using the DES algorithm.
        /// </summary>
        /// <param name="_Data">The data to be encrypted.</param>
        /// <returns>The encrypted data.</returns>
        public byte[] Encrypt(byte[] _Data)
        {
            using (ICryptoTransform var_Encryptor = this.des.CreateEncryptor(this.des.Key, this.des.IV))
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
        /// Decrypts the input data using the DES algorithm.
        /// </summary>
        /// <param name="_EncryptedData">The data to be decrypted.</param>
        /// <returns>The decrypted data.</returns>
        public byte[] Decrypt(byte[] _EncryptedData)
        {
            using (ICryptoTransform decryptor = this.des.CreateDecryptor(this.des.Key, this.des.IV))
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
