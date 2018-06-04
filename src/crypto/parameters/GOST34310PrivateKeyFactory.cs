using System;
using System.Collections.Generic;
using System.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Extension;

namespace Org.BouncyCastle.Extensions.Crypto.Parameters
{
    internal class Gost34310PrivateKeyFactory : IKeyFactoryExtension
    {
        public bool CanCreateKey(SubjectPublicKeyInfo keyInfo)
        {
            AlgorithmIdentifier algID = keyInfo.AlgorithmID;
            DerObjectIdentifier algOid = algID.Algorithm;
            return algOid.Equals(ObjectIdentifiers.GostR34310Key);
        }

        public AsymmetricKeyParameter CreateKey(SubjectPublicKeyInfo key)
        {
            return new Gost34310PrivateKeyParameters(false);
        }
    }
}
