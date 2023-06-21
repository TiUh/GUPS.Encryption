// System
using System;
using System.Security.Cryptography;

namespace GUPS.Encryption.Asymmetric
{
    /// <summary>
    /// This class provides an EC-DSA (Elliptic-Curve Digital Signature Algorithm) encryption implementation that supports key initialization from public or private keys, signing, verification, and key retrieval.
    /// </summary>
    public class AsymmetricECDsa : IAsymmetric
    {
        /// <summary>
        /// The ec algorithm used for encryption and decryption and signing and verification.
        /// </summary>
        private ECDsaCng ec;

        /// <summary>
        /// Initializes a new instance of the AsymmetricEC class with a new EC key pair (EC-256, EC-384, EC-521).
        /// </summary>
        /// <param name="_KeySize">The key size EC-256, EC-384, EC-521.</param>
        public AsymmetricECDsa(int _KeySize)
        {
            // Init the ec algorithm with the key size.
            this.ec = new ECDsaCng(_KeySize);

            // TODO: new ECDiffieHellmanCng(CngKey.Create(CngAlgorithm.ECDiffieHellmanP256, null, new CngKeyCreationParameters {ExportPolicy = CngExportPolicies.AllowPlaintextExport}));
        }

        /// <summary>
        /// Initializes a new instance of the AsymmetricEC class with the key xml.
        /// </summary>
        /// <param name="_KeySize">The key size EC-256, EC-384, EC-521.</param>
        /// <param name="_KeyType">The type of the key, public or private.</param>
        /// <param name="_KeyBlob">The key as blob.</param>
        public AsymmetricECDsa(int _KeySize, EKeyType _KeyType, byte[] _KeyBlob)
        {
            // Initialize the ec algorithm with the key xml.
            this.ec = new ECDsaCng(CngKey.Import(_KeyBlob, _KeyType == EKeyType.PUBLIC ? CngKeyBlobFormat.EccPublicBlob : CngKeyBlobFormat.EccPrivateBlob));
        }

        /// <summary>
        /// Returns the public key used for encryption and verification.
        /// </summary>
        /// <returns>The public key as byte blob.</returns>
        public byte[] GetPublicKey()
        {
            return this.ec.Key.Export(CngKeyBlobFormat.EccPublicBlob);
        }

        /// <summary>
        /// Returns the private key used for decryption and signing.
        /// </summary>
        /// <returns>The private key as byte blob.</returns>
        public byte[] GetPrivateKey()
        {
            return this.ec.Key.Export(CngKeyBlobFormat.EccPrivateBlob);
        }

        /// <summary>
        /// Encrypts the data using the public key.
        /// </summary>
        /// <param name="_Data">The data to be encrypted.</param>
        /// <returns>The encrypted data.</returns>
        public byte[] Encrypt(byte[] _Data)
        {
            throw new NotImplementedException("DSA does not encrypt data.");
        }

        /// <summary>
        /// Decrypts the data using the private key.
        /// </summary>
        /// <param name="_EncryptedData">The data to be decrypted.</param>
        /// <returns>The decrypted data.</returns>
        public byte[] Decrypt(byte[] _EncryptedData)
        {
            throw new NotImplementedException("DSA does not decrypt data.");
        }

        /// <summary>
        /// Signs the data using the private key.
        /// </summary>
        /// <param name="_Data">The data to be signed.</param>
        /// <returns>The digital signature.</returns>
        public byte[] Sign(byte[] _Data)
        {
            return this.ec.SignData(_Data, HashAlgorithmName.SHA256);
        }

        /// <summary>
        /// Verifies the data against the signature using the public key.
        /// </summary>
        /// <param name="_Data">The data to be verified.</param>
        /// <param name="_Signature">The digital signature to be verified.</param>
        /// <returns>True if the data is verified, false otherwise.</returns>
        public bool Verify(byte[] _Data, byte[] _Signature)
        {
            return this.ec.VerifyData(_Data, _Signature, HashAlgorithmName.SHA256);
        }
    }
}
