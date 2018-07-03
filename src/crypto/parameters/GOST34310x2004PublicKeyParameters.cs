using System;
using System.Collections.Generic;
using System.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Extensions.src.asn1;
using Org.BouncyCastle.Math.EC;

namespace Org.BouncyCastle.Extensions.Crypto.Parameters
{
    public class Gost34310X2004PublicKeyParameters : AsymmetricKeyParameter
    {
        private readonly string algorithm;
        private readonly ECPoint q;
        private readonly DerObjectIdentifier publicKeyParamSet;
        private ECDomainParameters parameters;

        private static ECPoint Validate(ECPoint q)
        {
            if (q == null)
                throw new ArgumentNullException("q");
            if (q.IsInfinity)
                throw new ArgumentException("point at infinity", "q");

            q = q.Normalize();

            if (!q.IsValid())
                throw new ArgumentException("point not on curve", "q");

            return q;
        }

        public Gost34310X2004PublicKeyParameters(
            string algorithm,
            ECPoint q,
            DerObjectIdentifier publicKeyParamSet)
            : base(false)
        {
            this.algorithm = algorithm;
            this.q = Validate(q);
            this.publicKeyParamSet = publicKeyParamSet;
            this.parameters = Gost34310NamedCurves.GetByOid(publicKeyParamSet);
        }

        public ECPoint Q
        {
            get { return q; }
        }

        public ECDomainParameters Parameters
        {
            get { return parameters; }
        }

    }
}
