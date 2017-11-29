using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace CertMSGA
{
	public static class Util
	{
		public static AsymmetricCipherKeyPair GenerateKeyPair()
		{
			var generator = new RsaKeyPairGenerator();
			generator.Init(new RsaKeyGenerationParameters(
				new BigInteger("10001", 16),
				new SecureRandom(),
				2048,
				80));
			return generator.GenerateKeyPair();
		}
	}
}