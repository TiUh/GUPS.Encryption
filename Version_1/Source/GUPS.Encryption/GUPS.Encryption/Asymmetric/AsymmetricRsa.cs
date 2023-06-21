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
        private RSA rsa;

        /// <summary>
        /// Initializes a new instance of the RSAEncryption class with a new RSA key pair (RSA-512, RSA-1024, RSA-2048, RSA-4096, ...).
        /// </summary>
        /// <param name="_KeySize">The key size RSA-512, RSA-1024, RSA-2048, RSA-4096, ...</param>
        public AsymmetricRsa(int _KeySize)
        {
            // Init the rsa algorithm with the key size.
            this.rsa = RSA.Create();
            this.rsa.KeySize = _KeySize;
        }

        /// <summary>
        /// Initializes a new instance of the RSAEncryption class with the key xml.
        /// </summary>
        /// <param name="_KeySize">The key size RSA-512, RSA-1024, RSA-2048, RSA-4096, ...</param>
        /// <param name="_KeyXml">The key xml used for encryption/decryption and signing/verification.</param>
        public AsymmetricRsa(int _KeySize, String _KeyXml)
        {
            // Initialize the rsa algorithm with the key xml.
            this.rsa = RSA.Create();
            this.rsa.KeySize = _KeySize;
            this.rsa.FromXmlString(_KeyXml);
        }

        /// <summary>
        /// Returns the public key used for encryption and verification.
        /// </summary>
        /// <returns>The public key as XML string.</returns>
        public string GetPublicKey()
        {
            return this.rsa.ToXmlString(false);
        }

        /// <summary>
        /// Returns the private key used for decryption and signing.
        /// </summary>
        /// <returns>The private key as a XML string.</returns>
        public string GetPrivateKey()
        {
            return this.rsa.ToXmlString(true);
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
