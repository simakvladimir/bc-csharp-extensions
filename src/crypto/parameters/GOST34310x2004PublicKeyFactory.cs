using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Extension;
using Org.BouncyCastle.Extensions.Asn1;
using Org.BouncyCastle.Extensions.src.asn1;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;

namespace Org.BouncyCastle.Extensions.Crypto.Parameters
{
    public class Gost34310x2004PublicKeyFactory : IKeyFactoryExtension
    {
        public bool CanCreateKey(SubjectPublicKeyInfo keyInfo)
        {
            AlgorithmIdentifier algID = keyInfo.AlgorithmID;
            DerObjectIdentifier algOid = algID.Algorithm;
            return algOid.Equals(ObjectIdentifiers.GostR34310x2004Key);
        }

        public AsymmetricKeyParameter CreateKey(SubjectPublicKeyInfo keyInfo)
        {
            AlgorithmIdentifier algID = keyInfo.AlgorithmID;

            Gost3410PublicKeyAlgParameters gostParams = new Gost3410PublicKeyAlgParameters(
                (Asn1Sequence)algID.Parameters);

            Asn1OctetString key;
            try
            {
                key = (Asn1OctetString)keyInfo.GetPublicKey();
            }
            catch (IOException)
            {
                throw new ArgumentException("invalid info structure in GOST34310.2004 public key");
            }

            byte[] keyEnc = key.GetOctets();
            byte[] x = new byte[32];
            byte[] y = new byte[32];

            for (int i = 0; i != y.Length; i++)
            {
                x[i] = keyEnc[32 - 1 - i];
            }

            for (int i = 0; i != x.Length; i++)
            {
                y[i] = keyEnc[64 - 1 - i];
            }

            ECDomainParameters ecP = Gost34310NamedCurves.GetByOid(gostParams.PublicKeyParamSet);

            if (ecP == null)
                return null;

            ECPoint q = ecP.Curve.CreatePoint(new BigInteger(1, x), new BigInteger(1, y));

            return new Gost34310X2004PublicKeyParameters("ECGOST3410", q, gostParams.PublicKeyParamSet);
        }
    }
}
