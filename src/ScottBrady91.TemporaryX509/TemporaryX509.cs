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
        public static SigningCredentials CreateSigningCredentials(string algorithm = SecurityAlgorithms.RsaSha256, string digest = null)
        {
            return new SigningCredentials(CreateX509SecurityKey(), algorithm, digest);
        }

        public static X509SecurityKey CreateX509SecurityKey()
        {
            return new X509SecurityKey(CreateX509Certificate2());
        }

        public static X509Certificate2 CreateX509Certificate2()
        {
            // generate new key pair
            var keypairgen = new RsaKeyPairGenerator();
            keypairgen.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
            var keypair = keypairgen.GenerateKeyPair();

            // generate x509
            var signatureFactory = new Asn1SignatureFactory("SHA256WithRSA", keypair.Private, new SecureRandom());
            var generator = new X509V3CertificateGenerator();
            var commonName = new X509Name("CN=test");
            var serialNumber = BigInteger.ProbablePrime(120, new SecureRandom());

            generator.SetSerialNumber(serialNumber);
            generator.SetSubjectDN(commonName);
            generator.SetIssuerDN(commonName);
            generator.SetNotAfter(DateTime.UtcNow.AddYears(99));
            generator.SetNotBefore(DateTime.UtcNow);
            generator.SetPublicKey(keypair.Public);
            
            var bouncyCert = generator.Generate(signatureFactory);
            
            // convert to .NET certificate
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
