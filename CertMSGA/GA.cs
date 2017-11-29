using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;

namespace CertMSGA
{
	public class GA : IGA
	{
		private AsymmetricCipherKeyPair keys;

		public GA(AsymmetricCipherKeyPair keys) => this.keys = keys;

		public GA()
		{
		}

		public byte[] Sign(byte[] request)
		{
			var engine = new RsaEngine();
			engine.Init(true, keys.Private);

			return engine.ProcessBlock(request, 0, request.Length);
		}

		public bool Verify(byte[] data, byte[] signature)
		{
			var signer = new PssSigner(new RsaEngine(), new Sha512Digest(), 20);
			signer.Init(false, keys.Public);

			signer.BlockUpdate(data, 0, data.Length);

			return signer.VerifySignature(signature);
		}

		public string SerializeKey() => string.Join(";", GetPublicKey().Modulus.ToString(10), GetPublicKey().Exponent.ToString(10), GetPrivateKey().Exponent.ToString(10));

		public void DeserializeKey(string data)
		{
			var pkElements = data.Split(';');
			keys = new AsymmetricCipherKeyPair(new RsaKeyParameters(false, new BigInteger(pkElements[0]), new BigInteger(pkElements[1])),
				new RsaKeyParameters(true, new BigInteger(pkElements[0]), new BigInteger(pkElements[2])));
		}

		private RsaKeyParameters GetPublicKey() => (RsaKeyParameters) keys.Public;
		private RsaKeyParameters GetPrivateKey() => (RsaKeyParameters) keys.Private;
	}
}