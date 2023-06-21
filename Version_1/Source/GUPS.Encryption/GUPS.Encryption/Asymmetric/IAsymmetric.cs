namespace GUPS.Encryption.Asymmetric
{
    /// <summary>
    /// Implementations of this interface would provide the actual logic for performing asymmetric encryption and decryption.
    /// </summary>
    public interface IAsymmetric
    {
        /// <summary>
        /// Returns the public key used for encryption and verification.
        /// </summary>
        /// <returns>The public key as blob.</returns>
        byte[] GetPublicKey();

        /// <summary>
        /// Returns the private key used for decryption and signing.
        /// </summary>
        /// <returns>The private key as blob.</returns>
        byte[] GetPrivateKey();

        /// <summary>
        /// Encrypts the data using the public key.
        /// </summary>
        /// <param name="_Data">The data to be encrypted.</param>
        /// <returns>The encrypted data.</returns>
        byte[] Encrypt(byte[] _Data);

        /// <summary>
        /// Decrypts the data using the private key.
        /// </summary>
        /// <param name="_EncryptedData">The data to be decrypted.</param>
        /// <returns>The decrypted data.</returns>
        byte[] Decrypt(byte[] _EncryptedData);

        /// <summary>
        /// Signs the data using the private key.
        /// </summary>
        /// <param name="_Data">The data to be signed.</param>
        /// <returns>The digital signature.</returns>
        byte[] Sign(byte[] _Data);

        /// <summary>
        /// Verifies the data against the signature using the public key.
        /// </summary>
        /// <param name="_Data">The data to be verified.</param>
        /// <param name="_Signature">The digital signature to be verified.</param>
        /// <returns>True if the data is verified, false otherwise.</returns>
        bool Verify(byte[] _Data, byte[] _Signature);
    }
}
