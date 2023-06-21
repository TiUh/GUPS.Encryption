namespace GUPS.Encryption.Symmetric
{
    /// <summary>
    /// Implementations of this interface would provide the actual logic for performing symmetric encryption and decryption.
    /// </summary>
    public interface ISymmetric
    {
        /// <summary>
        /// Returns the key, used in the symmetric encryption algorithms.
        /// </summary>
        /// <returns></returns>
        byte[] GetKey();

        /// <summary>
        /// Returns the iv, used in the symmetric encryption algorithms.
        /// </summary>
        /// <returns></returns>
        byte[] GetIV();

        /// <summary>
        /// This method takes the input data, key, and IV as parameters and returns the encrypted data as an array of bytes.
        /// </summary>
        /// <param name="_Data"></param>
        /// <returns></returns>
        byte[] Encrypt(byte[] _Data);

        /// <summary>
        /// This method takes the encrypted data, key, and IV as parameters and returns the decrypted data as an array of bytes.
        /// </summary>
        /// <param name="_EncryptedData"></param>
        /// <returns></returns>
        byte[] Decrypt(byte[] _EncryptedData);
    }
}
