using System;
using System.Collections.Generic;
using System.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Extensions.Crypto.Digests;
using Org.BouncyCastle.src.extension;

namespace Org.BouncyCastle.Extensions.Crypto.Signers
{
    public class Gost34310DigestSignerFactory : IDigestSignerFactoryExtension
    {
        public string AlgorithmName
        {
            get { return "Gost34310"; }
        }

        public DerObjectIdentifier Oid
        {
            get { return ObjectIdentifiers.GostR34310Encryption; }
        }

        public bool CanCreateSigner(string signatureName)
        {
            var signatureNameLower = signatureName.ToLower();
            return signatureNameLower == AlgorithmName.ToLower() ||
                   signatureNameLower == "Gost34311withGost34310".ToLower();
        }

        public ISigner CreateSigner(string signatureName)
        {
            return new Gost34310DigestSigner(new Gost3410Signer(), new Gost34311Digest());
        }
    }
}
