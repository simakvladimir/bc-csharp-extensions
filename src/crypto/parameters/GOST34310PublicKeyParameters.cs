using System;
using System.Collections.Generic;
using System.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Extensions.Crypto.Parameters
{
    public class Gost34310PublicKeyParameters : Gost3410PublicKeyParameters
    {
        public Gost34310PublicKeyParameters(BigInteger y, Gost3410Parameters parameters) 
            : base(y, parameters)
        {
        }

        public Gost34310PublicKeyParameters(BigInteger y, DerObjectIdentifier publicKeyParamSet) 
            : base(y, publicKeyParamSet)
        {
        }
    }
}
