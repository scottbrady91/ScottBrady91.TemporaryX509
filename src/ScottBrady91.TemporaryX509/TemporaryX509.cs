using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace ScottBrady91.TemporaryX509
{
    public class TemporaryX509
    {
        public static SigningCredentials CreateSigningCredentials()
        {
            return new SigningCredentials(CreateX509SecurityKey(), "RS256");
        }

        public static X509SecurityKey CreateX509SecurityKey()
        {
            var certificate = CreateX509Certificate2();
            return new X509SecurityKey(certificate);
        }

        public static X509Certificate2 CreateX509Certificate2()
        {
            var keypairgen = new RsaKeyPairGenerator();
            keypairgen.Init(new KeyGenerationParameters(new SecureRandom(), 1024));
            var keypair = keypairgen.GenerateKeyPair();

            ISignatureFactory signatureFactory =
                new Asn1SignatureFactory("SHA512WITHRSA", keypair.Private, new SecureRandom());
            var gen = new X509V3CertificateGenerator();
            var cn = new X509Name("CN=test");
            var sn = BigInteger.ProbablePrime(120, new SecureRandom());

            gen.SetSerialNumber(sn);
            gen.SetSubjectDN(cn);
            gen.SetIssuerDN(cn);
            gen.SetNotAfter(DateTime.Now.AddYears(1));
            gen.SetNotBefore(DateTime.Now.Subtract(new TimeSpan(7, 0, 0, 0)));
            gen.SetPublicKey(keypair.Public);
            
            var bouncyCert = gen.Generate(signatureFactory);
            
            var store = new Pkcs12Store();
            var alias = bouncyCert.SubjectDN.ToString();
            var certificateEntry = new X509CertificateEntry(bouncyCert);
            store.SetCertificateEntry(alias, certificateEntry);
            store.SetKeyEntry(alias, new AsymmetricKeyEntry(keypair.Private), new[] { certificateEntry });

            var stream = new MemoryStream();
            const string password = "password";

            store.Save(stream, password.ToCharArray(), new SecureRandom());
            return new X509Certificate2(stream.ToArray(), password, X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);
        }
    }
}
