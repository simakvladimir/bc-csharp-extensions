using System;
using System.Collections.Generic;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Signers;

namespace Org.BouncyCastle.Extensions.Crypto.Signers
{
    public class Gost34310DigestSigner : Gost3410DigestSigner
    {
        private readonly IDigest digest;
        private readonly IDsa dsaSigner;

        public Gost34310DigestSigner(IDsa signer, IDigest digest) 
            : base(signer, digest)
        {
            this.digest = digest;
            this.dsaSigner = signer;
        }

        public override string AlgorithmName
        {
            get { return this.digest.AlgorithmName + "with" + "Gost34310"; }
        }
    }
}
