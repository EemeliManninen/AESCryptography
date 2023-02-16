using NUnit.Framework;
using System;

namespace Frends.Community.AESCryptography.Tests
{
    public class Tests
    {
        private string _PlainTextSecret { get; set; }
        private string _SecretKey16 { get; set; }
        private string _SecretKey32 { get; set; }
        private string _EncryptedSecret16 { get; set; }
        private string _EncryptedSecret32 { get; set; }

        [SetUp]
        public void SetUp()
        {
            this._PlainTextSecret = "HYZ:gd6@otxFFVG~,|'vcc5oQN5A7#ZU";
            this._SecretKey16 = "o&*eAw~ak1U+c*j@";
            this._SecretKey32 = "k\\%E|/AFVR$oDF3Meu8|Gm:#D4f#*q*A";
            this._EncryptedSecret16 = "aacvRzaaH4uyn2eisQQNdHWhWo2LuSLpcm1849w79nKkD2NncUOByyU/JIXhC06W";
            this._EncryptedSecret32 = "U37vwffvCnXHZcX8bp94YHISqumWdeQABnu1HQ8MmgUbwpMc/08w/LWwxnEN9zZl";
        }

        [Test]
        public void EncryptString_NullParameters_ArgumentException()
        {
             Assert.Throws<ArgumentNullException>(() => AESCryptography.EncryptString(null, new System.Threading.CancellationToken()));
        }

        [Test]
        public void EncryptString_EmptySecret_ArgumentException()
        {
            var parameters = new EncryptParameters
            {
                SecretKey = string.Empty,
                PlainText = this._PlainTextSecret
            };

            Assert.Throws<ArgumentException>(() => AESCryptography.EncryptString(parameters, new System.Threading.CancellationToken()));
        }

        [Test]
        public void EncryptString_EmptyPlainText_ArgumentException()
        {
            var parameters = new EncryptParameters
            {
                SecretKey = this._SecretKey16,
                PlainText = string.Empty
            };

            Assert.Throws<ArgumentException>(() => AESCryptography.EncryptString(parameters, new System.Threading.CancellationToken()));
        }

        [Test]
        public void EncryptString_8CharSecret_CryptographicException()
        {
            var parameters = new EncryptParameters
            {
                SecretKey = "12345678",
                PlainText = this._PlainTextSecret
            };

            Assert.Throws<System.Security.Cryptography.CryptographicException>(() => AESCryptography.EncryptString(parameters, new System.Threading.CancellationToken()));
        }

        [Test]
        public void EncryptString_16CharSecret_Successful()
        {
            var parameters = new EncryptParameters
            {
                SecretKey = this._SecretKey16,
                PlainText = this._PlainTextSecret
            };

            var actual = AESCryptography.EncryptString(parameters, new System.Threading.CancellationToken());

            Assert.AreEqual(this._EncryptedSecret16, actual);
        }

        [Test]
        public void EncryptString_32CharSecret_Successful()
        {
            var parameters = new EncryptParameters
            {
                SecretKey = this._SecretKey32,
                PlainText = this._PlainTextSecret
            };

            var actual = AESCryptography.EncryptString(parameters, new System.Threading.CancellationToken());

            Assert.AreEqual(this._EncryptedSecret32, actual);
        }

        [Test]
        public void EncryptString_64CharSecret_CryptographicException()
        {
            var parameters = new EncryptParameters
            {
                SecretKey = "1234567891123456789212345678931234567894123456789512345678961234",
                PlainText = this._PlainTextSecret
            };

            Assert.Throws<System.Security.Cryptography.CryptographicException>(() => AESCryptography.EncryptString(parameters, new System.Threading.CancellationToken()));
        }

        [Test]
        public void EncryptString_128CharSecret_CryptographicException()
        {
            var parameters = new EncryptParameters
            {
                SecretKey = "12345678911234567892123456789312345678941234567895123456789612341234567891123456789212345678931234567894123456789512345678961234",
                PlainText = this._PlainTextSecret
            };

            Assert.Throws<System.Security.Cryptography.CryptographicException>(() => AESCryptography.EncryptString(parameters, new System.Threading.CancellationToken()));
        }

        [Test]
        public void DecryptString_NullParameters_ArgumentException()
        {
            Assert.Throws<ArgumentNullException>(() => AESCryptography.DecryptString(null, new System.Threading.CancellationToken()));
        }

        [Test]
        public void DecryptSString_EmptySecret_ArgumentException()
        {
            var parameters = new DecryptParameters
            {
                SecretKey = string.Empty,
                EncryptedString = this._EncryptedSecret16
            };

            Assert.Throws<ArgumentException>(() => AESCryptography.DecryptString(parameters, new System.Threading.CancellationToken()));
        }

        [Test]
        public void DecryptSString_EmptyCipherText_ArgumentException()
        {
            var parameters = new DecryptParameters
            {
                SecretKey = this._SecretKey16,
                EncryptedString = string.Empty
            };

            Assert.Throws<ArgumentException>(() => AESCryptography.DecryptString(parameters, new System.Threading.CancellationToken()));
        }

        [Test]
        public void DecryptString_InvalidCipherText_CryptographicException()
        {
            var parameters = new DecryptParameters
            {
                SecretKey = this._SecretKey16,
                EncryptedString = "NotBase64CipherText"
            };

            Assert.Throws<ArgumentException>(() => AESCryptography.DecryptString(parameters, new System.Threading.CancellationToken()));
        }

        [Test]
        public void DecryptString_8CharSecret_CryptographicException()
        {
            var parameters = new DecryptParameters
            {
                SecretKey = "12345678",
                EncryptedString = this._EncryptedSecret16
            };

            Assert.Throws<System.Security.Cryptography.CryptographicException>(() => AESCryptography.DecryptString(parameters, new System.Threading.CancellationToken()));
        }

        [Test]
        public void DecryptString_16CharSecret_CryptographicException()
        {
            var parameters = new DecryptParameters
            {
                SecretKey = this._SecretKey16,
                EncryptedString = this._EncryptedSecret16
            };

            var actual = AESCryptography.DecryptString(parameters, new System.Threading.CancellationToken());

            Assert.AreEqual(this._PlainTextSecret, actual);
        }

        [Test]
        public void DecryptString_32CharSecret_CryptographicException()
        {
            var parameters = new DecryptParameters
            {
                SecretKey = this._SecretKey32,
                EncryptedString = this._EncryptedSecret32
            };

            var actual = AESCryptography.DecryptString(parameters, new System.Threading.CancellationToken());

            Assert.AreEqual(this._PlainTextSecret, actual);
        }

        [Test]
        public void DecryptString_64CharSecret_CryptographicException()
        {
            var parameters = new DecryptParameters
            {
                SecretKey = "1234567891123456789212345678931234567894123456789512345678961234",
                EncryptedString = this._EncryptedSecret16
            };

            Assert.Throws<System.Security.Cryptography.CryptographicException>(() => AESCryptography.DecryptString(parameters, new System.Threading.CancellationToken()));
        }

        [Test]
        public void DecryptString_128CharSecret_CryptographicException()
        {
            var parameters = new DecryptParameters
            {
                SecretKey = "12345678911234567892123456789312345678941234567895123456789612341234567891123456789212345678931234567894123456789512345678961234",
                EncryptedString = this._EncryptedSecret16
            };

            Assert.Throws<System.Security.Cryptography.CryptographicException>(() => AESCryptography.DecryptString(parameters, new System.Threading.CancellationToken()));
        }
    }
}