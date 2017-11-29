using System;
using System.Configuration;
using static System.IO.File;

namespace CertMSGA
{
	internal static class Program
	{
		private static IGA ga;

		static void Main(string[] args)
		{
			var response = string.Empty;
			var keyFile = ConfigurationManager.AppSettings["keyFile"];
			if(args[0].Equals("pbk"))
			{
				if(Exists(keyFile))
				{
					ga = new GA();
					ga.DeserializeKey(ReadAllText(keyFile));
				}
				else
				{
					var keyPair = Util.GenerateKeyPair();
					ga = new GA(keyPair);
					WriteAllText(keyFile, ga.SerializeKey());
				}
				response = ga.SerializeKey();
			}
			else if(args[0].Equals("sign"))
			{
				if(Exists(keyFile))
				{
					ga = new GA();
					ga.DeserializeKey(ReadAllText(keyFile));
					response = Convert.ToBase64String(ga.Sign(Convert.FromBase64String(args[1])));
				}
			}
			else if(args[0].Equals("verify"))
			{
				if(Exists(keyFile))
				{
					ga = new GA();
					ga.DeserializeKey(ReadAllText(keyFile));
					response = ga.Verify(Convert.FromBase64String(args[1]), Convert.FromBase64String(args[2])).ToString();
				}
			}
			Console.WriteLine(response);
		}
	}
}