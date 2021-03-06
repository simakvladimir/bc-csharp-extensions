﻿using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Extensions.Crypto.Digests;
using Org.BouncyCastle.src.extension;

namespace Org.BouncyCastle.Extensions.Crypto.Signers
{
    public class Gost34310x94DigestSignerFactory : IDigestSignerFactoryExtension
    {
        public string AlgorithmName
        {
            get { return "Gost34310x94"; }
        }

        public DerObjectIdentifier Oid
        {
            get { return ObjectIdentifiers.GostR34310x94Encryption; }
        }

        public bool CanCreateSigner(string signatureName)
        {
            var signatureNameLower = signatureName.ToLower();
            return signatureNameLower == AlgorithmName.ToLower() ||
                   signatureNameLower == "Gost34311withGost34310x94".ToLower();
        }

        public ISigner CreateSigner(string signatureName)
        {
            return new Gost34310DigestSigner(new Gost34310x94Signer(), new Gost34311Digest());
        }
    }
}
