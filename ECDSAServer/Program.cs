using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ECDSAServer
{
    class Program
    {
        static X9ECParameters Curve;
        static ECDomainParameters DomainParams;
        static ECKeyGenerationParameters KeyParams;
        static ECKeyPairGenerator Generator;
        static AsymmetricCipherKeyPair Keys;

        static byte[] RawPubKey, RawPrivKey;
        static string StrPubKey, StrPrivKey;

        static async Task Main(string[] args)
        {
            Console.WriteLine("BEGIN!");
            Console.ReadKey();

            // Generate keys on the bouncy castle
            Console.WriteLine("Generating ecdsa keys \n");

            Curve = ECNamedCurveTable.GetByName("secp256k1");
            DomainParams = new ECDomainParameters(Curve.Curve, Curve.G, Curve.N, Curve.H, Curve.GetSeed());

            var secureRandom = new SecureRandom();
            KeyParams = new ECKeyGenerationParameters(DomainParams, secureRandom);

            Generator = new ECKeyPairGenerator("ECDSA");
            Generator.Init(KeyParams);
            Keys = Generator.GenerateKeyPair();

            var eCPrivateKey = (ECPrivateKeyParameters)Keys.Private;
            var eCPublicKey = (ECPublicKeyParameters)Keys.Public;

            //Get the public/private key has a hex string representation
            StrPubKey = BitConverter.ToString(eCPublicKey.Q.GetEncoded()).Replace("-", "").ToLower();
            StrPrivKey = BitConverter.ToString(eCPrivateKey.D.ToByteArray()).Replace("-", "").ToLower();


            //Console.WriteLine($"{eCPrivateKey.D.ToString(16).Length} bytes PRIVATE KEY {eCPrivateKey.D.ToString(16)}");
            Console.WriteLine($" PRIVATE KEY STRING {StrPrivKey}");
            Console.WriteLine($"PUBLIC KEY STRING {StrPubKey}");

            Console.ReadKey();
        }

        static string ToHex(byte[] data) => String.Concat(data.Select(x => x.ToString("x2")));


        static void GenerateKeys()
        {
            
        }
    }
}
