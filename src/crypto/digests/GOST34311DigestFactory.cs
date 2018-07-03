using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Extension;
using Org.BouncyCastle.Extensions.Crypto.Digests;

namespace Org.BouncyCastle.Extensions.Crypto.Digests
{
    internal class Gost34311DigestFactory : IDigestFactoryExtension
    {
        public string AlgorithmName
        {
            get { return "Gost34311"; }
        }

        public DerObjectIdentifier Oid
        {
            get { return ObjectIdentifiers.GostR34311Digest; }
        }

        public bool CanCreateDigest(string algName)
        {
            return algName == AlgorithmName;
        }

        public bool CanCreateDigest(DerObjectIdentifier oid)
        {
            return Oid.Equals(oid);
        }

        public IDigest CreateDigest()
        {
            return new Gost34311Digest();
        }
    }
}
