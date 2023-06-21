// System
using System.Security.Cryptography;

// Test
using NUnit.Framework;

namespace GUPS.Encryption.Tests
{
    public class SymmetricTests
    {
        #region AES

        [Test]
        public void SymmetricAesTest()
        {
            // Init Encryptor
            var encryptor = new Symmetric.SymmetricAes(128, CipherMode.CBC, PaddingMode.PKCS7);

            // Encrypt
            var key = encryptor.GetKey();
            var iv = encryptor.GetIV();
            var data = new byte[] { 0x01, 0x02, 0x03, 0x04 };
            var encryptedData = encryptor.Encrypt(data);

            // Init Decryptor
            var decryptor = new Symmetric.SymmetricAes(128, CipherMode.CBC, PaddingMode.PKCS7, key, iv);

            var decryptedData = decryptor.Decrypt(encryptedData);

            // Assert
            Assert.That(decryptedData, Is.EqualTo(data));
        }

        [Test]
        public void SymmetricAes128Test()
        {
            // Arrange
            var symmetric = new Symmetric.SymmetricAes(128);

            // Act
            var key = symmetric.GetKey();
            var iv = symmetric.GetIV();
            var data = new byte[] { 0x01, 0x02, 0x03, 0x04 };
            var encryptedData = symmetric.Encrypt(data);
            var decryptedData = symmetric.Decrypt(encryptedData);

            // Assert
            Assert.That(decryptedData, Is.EqualTo(data));
        }

        [Test]
        public void SymmetricAes192Test()
        {
            // Arrange
            var symmetric = new Symmetric.SymmetricAes(192);

            // Act
            var key = symmetric.GetKey();
            var iv = symmetric.GetIV();
            var data = new byte[] { 0x01, 0x02, 0x03, 0x04 };
            var encryptedData = symmetric.Encrypt(data);
            var decryptedData = symmetric.Decrypt(encryptedData);

            // Assert
            Assert.That(decryptedData, Is.EqualTo(data));
        }

        [Test]
        public void SymmetricAes256Test()
        {
            // Arrange
            var symmetric = new Symmetric.SymmetricAes(256);

            // Act
            var key = symmetric.GetKey();
            var iv = symmetric.GetIV();
            var data = new byte[] { 0x01, 0x02, 0x03, 0x04 };
            var encryptedData = symmetric.Encrypt(data);
            var decryptedData = symmetric.Decrypt(encryptedData);

            // Assert
            Assert.That(decryptedData, Is.EqualTo(data));
        }

        #endregion

        #region DES

        [Test]
        public void SymmetricDesTest()
        {
            // Init Encryptor
            var encryptor = new Symmetric.SymmetricDes(64, CipherMode.CBC, PaddingMode.PKCS7);

            // Encrypt
            var key = encryptor.GetKey();
            var iv = encryptor.GetIV();
            var data = new byte[] { 0x01, 0x02, 0x03, 0x04 };
            var encryptedData = encryptor.Encrypt(data);

            // Init Decryptor
            var decryptor = new Symmetric.SymmetricDes(64, CipherMode.CBC, PaddingMode.PKCS7, key, iv);

            var decryptedData = decryptor.Decrypt(encryptedData);

            // Assert
            Assert.That(decryptedData, Is.EqualTo(data));
        }

        [Test]
        public void SymmetricDes128Test()
        {
            // Arrange
            var symmetric = new Symmetric.SymmetricDes();

            // Act
            var key = symmetric.GetKey();
            var iv = symmetric.GetIV();
            var data = new byte[] { 0x01, 0x02, 0x03, 0x04 };
            var encryptedData = symmetric.Encrypt(data);
            var decryptedData = symmetric.Decrypt(encryptedData);

            // Assert
            Assert.That(decryptedData, Is.EqualTo(data));
        }

        #endregion

        #region RC2

        [Test]
        public void SymmetricRC2Test()
        {
            // Init Encryptor
            var encryptor = new Symmetric.SymmetricRC2(128, CipherMode.CBC, PaddingMode.PKCS7);

            // Encrypt
            var key = encryptor.GetKey();
            var iv = encryptor.GetIV();
            var data = new byte[] { 0x01, 0x02, 0x03, 0x04 };
            var encryptedData = encryptor.Encrypt(data);

            // Init Decryptor
            var decryptor = new Symmetric.SymmetricRC2(128, CipherMode.CBC, PaddingMode.PKCS7, key, iv);

            var decryptedData = decryptor.Decrypt(encryptedData);

            // Assert
            Assert.That(decryptedData, Is.EqualTo(data));
        }

        [Test]
        public void SymmetricRC2128Test()
        {
            // Arrange
            var symmetric = new Symmetric.SymmetricRC2(128);

            // Act
            var key = symmetric.GetKey();
            var iv = symmetric.GetIV();
            var data = new byte[] { 0x01, 0x02, 0x03, 0x04 };
            var encryptedData = symmetric.Encrypt(data);
            var decryptedData = symmetric.Decrypt(encryptedData);

            // Assert
            Assert.That(decryptedData, Is.EqualTo(data));
        }

        [Test]
        public void SymmetricRC2192Test()
        {
            // Arrange
            var symmetric = new Symmetric.SymmetricRC2(192);

            // Act
            var key = symmetric.GetKey();
            var iv = symmetric.GetIV();
            var data = new byte[] { 0x01, 0x02, 0x03, 0x04 };
            var encryptedData = symmetric.Encrypt(data);
            var decryptedData = symmetric.Decrypt(encryptedData);

            // Assert
            Assert.That(decryptedData, Is.EqualTo(data));
        }

        [Test]
        public void SymmetricRC2256Test()
        {
            // Arrange
            var symmetric = new Symmetric.SymmetricRC2(256);

            // Act
            var key = symmetric.GetKey();
            var iv = symmetric.GetIV();
            var data = new byte[] { 0x01, 0x02, 0x03, 0x04 };
            var encryptedData = symmetric.Encrypt(data);
            var decryptedData = symmetric.Decrypt(encryptedData);

            // Assert
            Assert.That(decryptedData, Is.EqualTo(data));
        }

        #endregion
    }
}