#pragma warning disable 1591

using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace Frends.Community
{
    public class EncryptParameters
    {
        /// <summary>
        /// The secret key to use for the AES algorithm, 16 or 32 bit.
        /// </summary>
        [DisplayFormat(DataFormatString = "Text")]
        [DefaultValue("")]
        public string SecretKey { get; set; }

        /// <summary>
        /// Plain text string to be encrypted.
        /// </summary>
        [DisplayFormat(DataFormatString = "Text")]
        [DefaultValue("")]
        public string PlainText { get; set; }
    }

    public class DecryptParameters
    {
        /// <summary>
        /// The secret key to use for the AES algorithm, 16 or 32 bit.
        /// </summary>
        [DisplayFormat(DataFormatString = "Text")]
        [DefaultValue("")]
        public string SecretKey { get; set; }

        /// <summary>
        /// Encrypted secret string to be decrypted.
        /// </summary>
        [DisplayFormat(DataFormatString = "Text")]
        [DefaultValue("")]
        public string EncryptedString { get; set; }
    }

    public class EncryptResult
    {
        /// <summary>
        /// Secret encrypted with given secret key
        /// </summary>
        [DisplayFormat(DataFormatString = "Text")]
        public string EncryptedString;
    }

    public class DecryptedResult
    {
        /// <summary>
        /// Plain text string decrypted with given secret key
        /// </summary>
        [DisplayFormat(DataFormatString = "Text")]
        public string DecryptedString;
    }
}
