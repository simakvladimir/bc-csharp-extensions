using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Extension;
using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Extensions.Crypto.Parameters
{
    public class Gost34310PublicKeyFactory : IKeyFactoryExtension
    {
        public bool CanCreateKey(SubjectPublicKeyInfo keyInfo)
        {
            AlgorithmIdentifier algID = keyInfo.AlgorithmID;
            DerObjectIdentifier algOid = algID.Algorithm;
            return algOid.Equals(ObjectIdentifiers.GostR34310Key);
        }

        public AsymmetricKeyParameter CreateKey(SubjectPublicKeyInfo keyInfo)
        {
            AlgorithmIdentifier algID = keyInfo.AlgorithmID;

            Gost3410PublicKeyAlgParameters algParams = new Gost3410PublicKeyAlgParameters(
                (Asn1Sequence)algID.Parameters);

            DerOctetString derY;
            try
            {
                derY = (DerOctetString)keyInfo.GetPublicKey();
            }
            catch (IOException)
            {
                throw new ArgumentException("invalid info structure in GOST3410 public key");
            }

            byte[] keyEnc = derY.GetOctets();
            byte[] keyBytes = new byte[keyEnc.Length];

            for (int i = 0; i != keyEnc.Length; i++)
            {
                keyBytes[i] = keyEnc[keyEnc.Length - 1 - i]; // was little endian
            }

            BigInteger y = new BigInteger(1, keyBytes);

            return new Gost34310PublicKeyParameters(y, algParams.PublicKeyParamSet);
        }
    }
}
