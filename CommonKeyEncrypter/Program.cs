using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;

namespace CommonKeyEncrypter
{
	class CommonKeyEncrypter
	{
		static public byte[] SaltHashGenerater(string salt){
			byte[] bSalt = Encoding.UTF8.GetBytes(salt);
			SHA256 crypto = new SHA256CryptoServiceProvider();
			byte[] bHashedSalt = crypto.ComputeHash(bSalt);
			return bHashedSalt;
		}
		static public byte[] Encrypter(string password, byte[] salt, string sTarget)
		{
			using(AesManaged aes = new AesManaged())
			{
				aes.BlockSize = 128;
				aes.KeySize = 128;
				aes.Mode = CipherMode.CBC;
				aes.Padding = PaddingMode.PKCS7;
				try
				{
					Rfc2898DeriveBytes deriveBytes = new Rfc2898DeriveBytes(password, salt, 1000);
					aes.Key = deriveBytes.GetBytes(16);
					aes.IV = deriveBytes.GetBytes(16);
				}
				catch (Exception e)
				{
					Console.WriteLine(e);
					return BitConverter.GetBytes(0);
				}
				using (MemoryStream encryptionStream = new MemoryStream())
				{
					ICryptoTransform encryptInterface = aes.CreateEncryptor(aes.Key, aes.IV);
					using(CryptoStream encryptStream = new CryptoStream(encryptionStream,encryptInterface,CryptoStreamMode.Write))
					{
						byte[] bTarget = new UTF8Encoding(false).GetBytes(sTarget);
						encryptStream.Write(bTarget, 0, bTarget.Length);
						encryptStream.FlushFinalBlock();
					}
					return encryptionStream.ToArray();
				}
			}
		}
		static public string Decrypter(string password, byte[] salt, byte[] bTarget){
			using(AesManaged aes = new AesManaged())
			{
				aes.BlockSize = 128;
				aes.KeySize = 128;
				aes.Mode = CipherMode.CBC;
				aes.Padding = PaddingMode.PKCS7;
				try
				{
					Rfc2898DeriveBytes deriveBytes = new Rfc2898DeriveBytes(password, salt, 1000);
					aes.Key = deriveBytes.GetBytes(16);
					aes.IV = deriveBytes.GetBytes(16);
				}
				catch (Exception e)
				{
					Console.WriteLine(e);
					return "";
				}
				using (MemoryStream decryptionStream = new MemoryStream())
				{
					ICryptoTransform decryptInterface = aes.CreateDecryptor(aes.Key, aes.IV);
					using(CryptoStream decryptStream = new CryptoStream(decryptionStream,decryptInterface,CryptoStreamMode.Write))
					{
						decryptStream.Write(bTarget, 0, bTarget.Length);
						decryptStream.FlushFinalBlock();
					}
					return new UTF8Encoding(false).GetString(decryptionStream.ToArray());
				}
			}

		}
		static void Main(string[] args)
		{
			/* Rfc2898DeriveBytes deryveBytes = new Rfc2898DeriveBytes("password",Encoding.ASCII.GetBytes("saltsalt"),16);
			byte[] bBufferKey = deryveBytes.GetBytes(16);
			Console.WriteLine("sBufferKey: " + BitConverter.ToString(bBufferKey));
			bBufferKey = deryveBytes.GetBytes(16);
			Console.WriteLine("sBufferKey: " + BitConverter.ToString(bBufferKey));*/
			byte[] bResult = Encrypter("password", SaltHashGenerater("salt"), "target");
			Console.WriteLine("bResult: " + BitConverter.ToString(bResult));
			string sResult = Decrypter("password", SaltHashGenerater("salt"), bResult);
			Console.WriteLine("sResult: " + sResult);
			Console.ReadKey();
		}
	}
}
