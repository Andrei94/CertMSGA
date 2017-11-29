using Org.BouncyCastle.Crypto.Parameters;

namespace CertMSGA
{
	public interface IGA
	{
		byte[] Sign(byte[] request);
		bool Verify(byte[] data, byte[] signature);
		string SerializeKey();
		void DeserializeKey(string data);
	}
}