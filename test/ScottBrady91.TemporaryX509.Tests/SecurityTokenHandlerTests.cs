using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml;
using Microsoft.IdentityModel.Tokens.Saml2;
using Xunit;

namespace ScottBrady91.TemporaryX509.Tests
{
    public class SecurityTokenHandlerTests
    {
        public static TheoryData<TestData> Data = new TheoryData<TestData>
        {
            new TestData(new JwtSecurityTokenHandler(), SecurityAlgorithms.RsaSha256, null),
            new TestData(new Saml2SecurityTokenHandler(), SecurityAlgorithms.RsaSha256Signature, SecurityAlgorithms.Sha256Digest),
            new TestData(new SamlSecurityTokenHandler(), SecurityAlgorithms.RsaSha256Signature, SecurityAlgorithms.Sha256Digest)
        };

        [Theory, MemberData(nameof(Data))]
        public void WhenTokenCreatedUsingTempCert_ExpectValidToken(TestData data)
        {
            const string audience = "http://you";
            const string issuer = "http://me";
            var signingCredentials = TemporaryX509.CreateSigningCredentials(data.Algorithm, data.Digest);

            var securityToken = data.Handler.CreateToken(new SecurityTokenDescriptor
            {
                Audience = audience,
                Issuer = issuer,
                Expires = DateTime.UtcNow.AddDays(1),
                Subject = new ClaimsIdentity(new List<Claim>
                {
                    new Claim(ClaimTypes.NameIdentifier, Guid.NewGuid().ToString()),
                    new Claim(ClaimTypes.Name, "Scott")
                }),
                SigningCredentials = signingCredentials
            });
            var token = data.Handler.WriteToken(securityToken);

            var claimsPrincipal = data.Handler.ValidateToken(token, new TokenValidationParameters
            {
                ValidAudience = audience,
                ValidIssuer = issuer,
                IssuerSigningKey = signingCredentials.Key
            }, out var validatedToken);

            Assert.NotNull(validatedToken);
            Assert.NotNull(claimsPrincipal);
        }
    }

    public class TestData
    {
        public readonly SecurityTokenHandler Handler;
        public readonly string Algorithm;
        public readonly string Digest;

        public TestData(SecurityTokenHandler handler, string algorithm, string digest)
        {
            Handler = handler;
            Algorithm = algorithm;
            Digest = digest;
        }
    }
}