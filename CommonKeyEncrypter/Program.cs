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
		static public byte[] encrypter(string password, string salt, string sTarget)
		{
			using(AesManaged aes = new AesManaged())
			{
				aes.BlockSize = 128;
				aes.KeySize = 128;
				aes.Mode = CipherMode.CBC;
				aes.Padding = PaddingMode.PKCS7;
				try
				{
					byte[] bSalt = Encoding.UTF8.GetBytes(salt);
					SHA256 crypto = new SHA256CryptoServiceProvider();
					byte[] bHashedSalt = crypto.ComputeHash(bSalt);
					Rfc2898DeriveBytes deriveBytes = new Rfc2898DeriveBytes(password, bHashedSalt, 1000);
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
					using(CryptoStream encrypt = new CryptoStream(encryptionStream,encryptInterface,CryptoStreamMode.Write))
					{
						byte[] bTarget = new UTF8Encoding(false).GetBytes(sTarget);
						encrypt.Write(bTarget, 0, bTarget.Length);
						encrypt.FlushFinalBlock();
					}
					return encryptionStream.ToArray();
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
			byte[] bResult = encrypter("password", "saltsalt", "target");
			Console.WriteLine("bResult: " + BitConverter.ToString(bResult));
			Console.ReadKey();
		}
	}
}
