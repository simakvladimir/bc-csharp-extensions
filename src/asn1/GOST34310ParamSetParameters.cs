using System;
using System.Collections.Generic;
using System.Text;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Extensions.Asn1
{
    public class Gost34310ParamSetParameters : Gost3410ParamSetParameters
    {
        public Gost34310ParamSetParameters(int keySize, BigInteger p, BigInteger q, BigInteger a) 
            : base(keySize, p, q, a)
        {
        }

    }
}
