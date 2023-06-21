﻿// System
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
        private ECDsa ec;

        /// <summary>
        /// Initializes a new instance of the AsymmetricEC class with a new EC key pair (EC-256, EC-384, EC-521).
        /// </summary>
        /// <param name="_KeySize">The key size EC-256, EC-384, EC-521.</param>
        public AsymmetricECDsa(int _KeySize)
        {
            // Init the ec algorithm with the key size.
            this.ec = ECDsa.Create();
            this.ec.KeySize = _KeySize;
        }

        /// <summary>
        /// Initializes a new instance of the AsymmetricEC class with the key xml.
        /// </summary>
        /// <param name="_KeySize">The key size EC-256, EC-384, EC-521.</param>
        /// <param name="_KeyXml">The key xml used for encryption/decryption and signing/verification.</param>
        public AsymmetricECDsa(int _KeySize, String _KeyXml)
        {
            // Initialize the ec algorithm with the key xml.
            this.ec = ECDsa.Create();
            this.ec.KeySize = _KeySize;
            this.ec.FromXmlString(_KeyXml);
        }

        /// <summary>
        /// Returns the public key used for encryption and verification.
        /// </summary>
        /// <returns>The public key as XML string.</returns>
        public string GetPublicKey()
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Returns the private key used for decryption and signing.
        /// </summary>
        /// <returns>The private key as a XML string.</returns>
        public string GetPrivateKey()
        {
            throw new NotImplementedException();
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