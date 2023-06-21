// System
using System.Security.Cryptography;

// Test
using NUnit.Framework;

namespace GUPS.Encryption.Tests
{
    public class AsymmetricTests
    {
        #region RSA

        [Test]
        public void AsymmetricRsaTest()
        {
            // Init Encryptor
            var asymmetric = new Asymmetric.AsymmetricRsa(2048);

            // Keys
            var publicKey = asymmetric.GetPublicKey();
            var privateKey = asymmetric.GetPrivateKey();

            // Init Encryptor
            var encryptor = new Asymmetric.AsymmetricRsa(2048, publicKey);

            var data = new byte[] { 0x01, 0x02, 0x03, 0x04 };
            var encryptedData = encryptor.Encrypt(data);

            // Init Decryptor
            var decryptor = new Asymmetric.AsymmetricRsa(2048, privateKey);

            var decryptedData = decryptor.Decrypt(encryptedData);

            // Assert
            Assert.That(decryptedData, Is.EqualTo(data));
        }

        [Test]
        public void AsymmetricRsa512Test()
        {
            // Init Asymmetric
            var asymmetric = new Asymmetric.AsymmetricRsa(512);

            // Encrypt
            var data = new byte[] { 0x01, 0x02, 0x03, 0x04 };
            var encryptedData = asymmetric.Encrypt(data);

            // Decrypt
            var decryptedData = asymmetric.Decrypt(encryptedData);

            // Assert
            Assert.That(decryptedData, Is.EqualTo(data));
        }

        [Test]
        public void AsymmetricRsa1024Test()
        {
            // Init Asymmetric
            var asymmetric = new Asymmetric.AsymmetricRsa(1024);

            // Encrypt
            var data = new byte[] { 0x01, 0x02, 0x03, 0x04 };
            var encryptedData = asymmetric.Encrypt(data);

            // Decrypt
            var decryptedData = asymmetric.Decrypt(encryptedData);

            // Assert
            Assert.That(decryptedData, Is.EqualTo(data));
        }

        [Test]
        public void AsymmetricRsa2048Test()
        {
            // Init Asymmetric
            var asymmetric = new Asymmetric.AsymmetricRsa(2048);

            // Encrypt
            var data = new byte[] { 0x01, 0x02, 0x03, 0x04 };
            var encryptedData = asymmetric.Encrypt(data);

            // Decrypt
            var decryptedData = asymmetric.Decrypt(encryptedData);

            // Assert
            Assert.That(decryptedData, Is.EqualTo(data));
        }

        [Test]
        public void AsymmetricRsa4096Test()
        {
            // Init Asymmetric
            var asymmetric = new Asymmetric.AsymmetricRsa(4096);

            // Encrypt
            var data = new byte[] { 0x01, 0x02, 0x03, 0x04 };
            var encryptedData = asymmetric.Encrypt(data);

            // Decrypt
            var decryptedData = asymmetric.Decrypt(encryptedData);

            // Assert
            Assert.That(decryptedData, Is.EqualTo(data));
        }

        [Test]
        public void AsymmetricRsaSignCorrectTest()
        {
            // Init Asymmetric
            var asymmetric = new Asymmetric.AsymmetricRsa(4096);

            // Sign
            var data = new byte[] { 0x01, 0x02, 0x03, 0x04 };

            var signature = asymmetric.Sign(data);

            // Verify
            var verified = asymmetric.Verify(data, signature);

            // Assert
            Assert.That(verified, Is.True);
        }

        [Test]
        public void AsymmetricRsaSignNotCorrectTest()
        {
            // Init Asymmetric
            var asymmetric = new Asymmetric.AsymmetricRsa(4096);

            // Sign
            var data = new byte[] { 0x01, 0x02, 0x03, 0x04 };

            var signature = asymmetric.Sign(data);

            // Verify
            var data_False = new byte[] { 0x01, 0x02, 0x03, 0x05 };

            var verified = asymmetric.Verify(data_False, signature);

            // Assert
            Assert.That(verified, Is.False);
        }

        #endregion

        #region DSA

        [Test]
        public void AsymmetricDsaTest()
        {
            // Init Encryptor
            var asymmetric = new Asymmetric.AsymmetricDsa(2048);

            // Keys
            var publicKey = asymmetric.GetPublicKey();
            var privateKey = asymmetric.GetPrivateKey();

            // Init Sign
            var signer = new Asymmetric.AsymmetricDsa(2048, privateKey);

            var data = new byte[] { 0x01, 0x02, 0x03, 0x04 };

            var signature = signer.Sign(data);

            // Init Verify
            var validator = new Asymmetric.AsymmetricDsa(2048, publicKey);

            var verified = validator.Verify(data, signature);

            // Assert
            Assert.That(verified, Is.True);
        }

        [Test]
        public void AsymmetricDsaSignCorrectTest()
        {
            // Init Asymmetric
            var asymmetric = new Asymmetric.AsymmetricDsa(3072);

            // Sign
            var data = new byte[] { 0x01, 0x02, 0x03, 0x04 };

            var signature = asymmetric.Sign(data);

            // Verify
            var verified = asymmetric.Verify(data, signature);

            // Assert
            Assert.That(verified, Is.True);
        }

        [Test]
        public void AsymmetricDsaSignNotCorrectTest()
        {
            // Init Asymmetric
            var asymmetric = new Asymmetric.AsymmetricDsa(3072);

            // Sign
            var data = new byte[] { 0x01, 0x02, 0x03, 0x04 };

            var signature = asymmetric.Sign(data);

            // Verify
            var data_False = new byte[] { 0x01, 0x02, 0x03, 0x05 };

            var verified = asymmetric.Verify(data_False, signature);

            // Assert
            Assert.That(verified, Is.False);
        }

        #endregion
    }
}