using System;
using System.Collections.Generic;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

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

        public override bool VerifySignature(
            byte[] signature)
        {
            byte[] hash = new byte[digest.GetDigestSize()];
            digest.DoFinal(hash, 0);

            BigInteger R, S;
            try
            {
                var reverseSignature = (byte[])signature.Clone();
                Array.Reverse(reverseSignature);

                R = new BigInteger(1, reverseSignature, 32, 32);
                S = new BigInteger(1, reverseSignature, 0, 32);
            }
            catch (Exception e)
            {
                throw new SignatureException("error decoding signature bytes.", e);
            }

            if (dsaSigner.VerifySignature(hash, R, S))
            {
                return true;
            }
            
            try
            {
                R = new BigInteger(1, signature, 32, 32);
                S = new BigInteger(1, signature, 0, 32);
            }
            catch (Exception e)
            {
                throw new SignatureException("error decoding signature bytes.", e);
            }

            return dsaSigner.VerifySignature(hash, R, S);
        }
    }
}
