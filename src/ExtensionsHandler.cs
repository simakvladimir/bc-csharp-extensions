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
            ExtensionManager.RegisterPublicKeyFactory(new Gost34310PublicKeyFactory());
            ExtensionManager.RegisterPublicKeyFactory(new Gost34310PrivateKeyFactory());

            // digests
            ExtensionManager.RegisterDigestFactory(new Gost34311DigestFactory());

            // encryptions
            ExtensionManager.AddEncryptionAlgorithm(ObjectIdentifiers.GostR34310Encryption, "Gost34310");

            // signers
            ExtensionManager.RegisterDigestSignerFactory(new Gost34310DigestSignerFactory());
        }
    }
}
