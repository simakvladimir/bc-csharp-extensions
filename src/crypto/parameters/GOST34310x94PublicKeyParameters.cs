using System;
using System.Collections.Generic;
using System.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Extensions.Crypto.Parameters
{
    public class Gost34310x94PublicKeyParameters 
        : Gost34310KeyParameters
    {
        private readonly BigInteger y;

        public Gost34310x94PublicKeyParameters(
            BigInteger y,
            Gost3410Parameters parameters)
            : base(false, parameters)
        {
            if (y.SignValue < 1 || y.CompareTo(Parameters.P) >= 0)
                throw new ArgumentException("Invalid y for GOST34310 public key", "y");

            this.y = y;
        }

        public Gost34310x94PublicKeyParameters(
            BigInteger y,
            DerObjectIdentifier publicKeyParamSet)
            : base(false, publicKeyParamSet)
        {
            if (y.SignValue < 1 || y.CompareTo(Parameters.P) >= 0)
                throw new ArgumentException("Invalid y for GOST34310 public key", "y");

            this.y = y;
        }

        public BigInteger Y
        {
            get { return y; }
        }
    }
}
