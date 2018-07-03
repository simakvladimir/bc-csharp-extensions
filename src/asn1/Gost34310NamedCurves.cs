using System;
using System.Collections;
using System.Collections.Generic;
using System.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Extensions.src.asn1
{
    public sealed class Gost34310NamedCurves
    {
        private Gost34310NamedCurves()
        {

        }

        internal static readonly IDictionary parameters = Platform.CreateHashtable();

        static Gost34310NamedCurves()
        {
            BigInteger mod_p = new BigInteger("115792089237316195423570985008687907853269984665640564039457584007913129639319");
            BigInteger mod_q = new BigInteger("115792089237316195423570985008687907853073762908499243225378155805079068850323");
                                              //57896044618658097711785492504343953926634992332820282019728792003956564821041
            FpCurve curve = new FpCurve(
                mod_p, // p
                new BigInteger("115792089237316195423570985008687907853269984665640564039457584007913129639316"), // a
                new BigInteger("166"), // b
                mod_q,
                BigInteger.One);

            ECDomainParameters ecParams = new ECDomainParameters(
                curve,
                curve.CreatePoint(
                    new BigInteger("1"), // x
                    new BigInteger("64033881142927202683649881450433473985931760268884941288852745803908878638612")), // y
                mod_q);

            parameters[ObjectIdentifiers.GostR34310x2004A] = ecParams;


            /*

            mod_p = new BigInteger("115792089237316195423570985008687907853269984665640564039457584007913129639319");
            mod_q = new BigInteger("115792089237316195423570985008687907853073762908499243225378155805079068850323");

            curve = new FpCurve(
                mod_p, // p
                new BigInteger("115792089237316195423570985008687907853269984665640564039457584007913129639316"),
                new BigInteger("166"),
                mod_q,
                BigInteger.One);

            ecParams = new ECDomainParameters(
                curve,
                curve.CreatePoint(
                    new BigInteger("1"), // x
                    new BigInteger("64033881142927202683649881450433473985931760268884941288852745803908878638612")), // y
                mod_q);

            //parameters[ObjectIdentifiers.GostR34310x2004A] = ecParams;

            mod_p = new BigInteger("115792089237316195423570985008687907853269984665640564039457584007913129639319"); //p
            mod_q = new BigInteger("115792089237316195423570985008687907853073762908499243225378155805079068850323"); //q
            curve = new FpCurve(
                mod_p, // p
                new BigInteger("115792089237316195423570985008687907853269984665640564039457584007913129639316"), // a
                new BigInteger("166"), // b
                mod_q,
                BigInteger.One);

            ecParams = new ECDomainParameters(
                curve,
                curve.CreatePoint(
                    new BigInteger("1"), // x
                    new BigInteger("64033881142927202683649881450433473985931760268884941288852745803908878638612")), // y
                mod_q); // q

            parameters[ObjectIdentifiers.GostR34310x2004A] = ecParams;
            */
        }

        public static ECDomainParameters GetByOid(
            DerObjectIdentifier oid)
        {
            return (ECDomainParameters)parameters[oid];
        }
    }
}
