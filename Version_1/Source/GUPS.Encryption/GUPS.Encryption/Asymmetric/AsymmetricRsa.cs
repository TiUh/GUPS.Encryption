// System
using System;
using System.Security.Cryptography;

namespace GUPS.Encryption.Asymmetric
{
    /// <summary>
    /// This class provides an RSA (Rivest–Shamir–Adleman) encryption implementation that supports key initialization from public or private keys, encryption, decryption, signing, verification, and key retrieval.
    /// </summary>
    public class AsymmetricRsa : IAsymmetric
    {
        /// <summary>
        /// The rsa algorithm used for encryption and decryption and signing and verification.
        /// </summary>
        private RSACng rsa;

        /// <summary>
        /// Initializes a new instance of the RSAEncryption class with a new RSA key pair (RSA-512, RSA-1024, RSA-2048, RSA-4096, ...).
        /// </summary>
        /// <param name="_KeySize">The key size RSA-512, RSA-1024, RSA-2048, RSA-4096, ...</param>
        public AsymmetricRsa(int _KeySize)
        {
            // Init the rsa algorithm with the key size.
            this.rsa = new RSACng(_KeySize);
        }

        /// <summary>
        /// Initializes a new instance of the RSAEncryption class with the key xml.
        /// </summary>
        /// <param name="_KeySize">The key size RSA-512, RSA-1024, RSA-2048, RSA-4096, ...</param>
        /// <param name="_KeyType">The type of the key, public or private.</param>
        /// <param name="_KeyBlob">The key as blob.</param>
        public AsymmetricRsa(int _KeySize, EKeyType _KeyType, byte[] _KeyBlob)
        {
            // Initialize the rsa algorithm with the key xml.
            this.rsa = new RSACng(CngKey.Import(_KeyBlob, _KeyType == EKeyType.PUBLIC ? CngKeyBlobFormat.GenericPublicBlob : CngKeyBlobFormat.GenericPrivateBlob));
        }

        /// <summary>
        /// Returns the public key used for encryption and verification.
        /// </summary>
        /// <returns>The public key as byte blob.</returns>
        public byte[] GetPublicKey()
        {
            return this.rsa.Key.Export(CngKeyBlobFormat.GenericPublicBlob);
        }

        /// <summary>
        /// Returns the private key used for decryption and signing.
        /// </summary>
        /// <returns>The private key as byte blob.</returns>
        public byte[] GetPrivateKey()
        {
            return this.rsa.Key.Export(CngKeyBlobFormat.GenericPrivateBlob);
        }

        /// <summary>
        /// Encrypts the data using the public key.
        /// </summary>
        /// <param name="_Data">The data to be encrypted.</param>
        /// <returns>The encrypted data.</returns>
        public byte[] Encrypt(byte[] _Data)
        {
            return this.rsa.Encrypt(_Data, RSAEncryptionPadding.Pkcs1);
        }

        /// <summary>
        /// Decrypts the data using the private key.
        /// </summary>
        /// <param name="_EncryptedData">The data to be decrypted.</param>
        /// <returns>The decrypted data.</returns>
        public byte[] Decrypt(byte[] _EncryptedData)
        {
            return this.rsa.Decrypt(_EncryptedData, RSAEncryptionPadding.Pkcs1);
        }

        /// <summary>
        /// Signs the data using the private key.
        /// </summary>
        /// <param name="_Data">The data to be signed.</param>
        /// <returns>The digital signature.</returns>
        public byte[] Sign(byte[] _Data)
        {
            return this.rsa.SignData(_Data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }

        /// <summary>
        /// Verifies the data against the signature using the public key.
        /// </summary>
        /// <param name="_Data">The data to be verified.</param>
        /// <param name="_Signature">The digital signature to be verified.</param>
        /// <returns>True if the data is verified, false otherwise.</returns>
        public bool Verify(byte[] _Data, byte[] _Signature)
        {
            return this.rsa.VerifyData(_Data, _Signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
    }
}
