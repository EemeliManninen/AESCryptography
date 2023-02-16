using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using Microsoft.CSharp; // You can remove this if you don't need dynamic type in .NET Standard frends Tasks

#pragma warning disable 1591

namespace Frends.Community.AESCryptography
{
    public class AESCryptography
    {
		/// <summary>
		/// Encrypts a plain text string with either 16 or 32 bit secret key, returned secret is Base64 encoded
		/// </summary>
		/// <param name="input"></param>
		/// <param name="cancellationToken"></param>
		/// <returns>{string}</returns>
		public static string EncryptString(EncryptParameters input, CancellationToken cancellationToken)
        {
			if (input == null)
			{
				throw new ArgumentNullException(nameof(EncryptParameters));
			}

			if (string.IsNullOrEmpty(input.SecretKey))
            {
				throw new ArgumentException(nameof(EncryptParameters.SecretKey));
            }

			if (string.IsNullOrEmpty(input.PlainText))
			{
				throw new ArgumentException(nameof(EncryptParameters.PlainText));
			}

			byte[] array;
			byte[] iv = new byte[16];

			using (Aes aes = Aes.Create())
			{
				aes.Key = Encoding.UTF8.GetBytes(input.SecretKey);
				aes.IV = iv;

				ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

				using (MemoryStream memoryStream = new MemoryStream())
				{
					using (CryptoStream cryptoStream = new CryptoStream((Stream)memoryStream, encryptor, CryptoStreamMode.Write))
					{
						using (StreamWriter streamWriter = new StreamWriter((Stream)cryptoStream))
						{
							streamWriter.Write(input.PlainText);
						}

						array = memoryStream.ToArray();
					}
				}
			}

			return Convert.ToBase64String(array);
		}

		/// <summary>
		/// Decrypts a secret string with either 16 or 32 bit secret key
		/// </summary>
		/// <param name="input"></param>
		/// <param name="cancellationToken"></param>
		/// <returns>{string}</returns>
		public static string DecryptString(DecryptParameters input, CancellationToken cancellationToken)
		{
			if (input == null)
			{
				throw new ArgumentNullException(nameof(DecryptParameters));
			}

			if (string.IsNullOrEmpty(input.SecretKey))
			{
				throw new ArgumentException(nameof(DecryptParameters.SecretKey));
			}

			if (string.IsNullOrEmpty(input.EncryptedString))
			{
				throw new ArgumentException(nameof(DecryptParameters.EncryptedString));
			}

			byte[] iv = new byte[16];
			byte[] buffer;

			try
            {
				buffer = Convert.FromBase64String(input.EncryptedString);
			}
			catch (Exception ex)
            {
				throw new ArgumentException(nameof(DecryptParameters.EncryptedString), ex);
            }

			using (Aes aes = Aes.Create())
			{
				aes.Key = Encoding.UTF8.GetBytes(input.SecretKey);
				aes.IV = iv;
				ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

				using (MemoryStream memoryStream = new MemoryStream(buffer))
				{
					using (CryptoStream cryptoStream = new CryptoStream((Stream)memoryStream, decryptor, CryptoStreamMode.Read))
					{
						using (StreamReader streamReader = new StreamReader((Stream)cryptoStream))
						{
							return streamReader.ReadToEnd();
						}
					}
				}
			}
		}
	}
}
