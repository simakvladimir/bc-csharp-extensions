using System;
using System.Collections.Generic;
using System.Text;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Extension;
using Org.BouncyCastle.Extensions.Crypto.Parameters;
using Org.BouncyCastle.Extensions.Crypto.Signers;
using Org.BouncyCastle.Extensions.src.crypto.digests;

namespace Org.BouncyCastle.Extensions
{
    public static class ExtensionsHandler
    {
        /// <summary>
        /// IMPORTANT! call it before using extensions
        /// </summary>
        public static void Init()
        {
            // keys
            ExtensionManager.RegisterPublicKeyFactory(new Gost34310x94PublicKeyFactory());
            ExtensionManager.RegisterPublicKeyFactory(new Gost34310x94PrivateKeyFactory());
            ExtensionManager.RegisterPublicKeyFactory(new Gost34310x2004PublicKeyFactory());

            // digests
            ExtensionManager.RegisterDigestFactory(new Gost34311DigestFactory());

            // encryptions
            ExtensionManager.AddEncryptionAlgorithm(ObjectIdentifiers.GostR34310x94Encryption, "Gost34310x94");
            ExtensionManager.AddEncryptionAlgorithm(ObjectIdentifiers.GostR34310x2004Encryption, "Gost34310x2004");

            // signers
            ExtensionManager.RegisterDigestSignerFactory(new Gost34310x94DigestSignerFactory());
            ExtensionManager.RegisterDigestSignerFactory(new Gost34310x2004DigestSignerFactory());
        }
    }
}
