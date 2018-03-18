# Temporary X509 Certificate Generator

A simple helper library that generates a temporary x509 certificate. Primarily developed for use with IdentityServer 4 when using WS-Federation and SAML2P. **Not intended for use in production**.

Hardcoded with:

- Key Size: 2048

- Subject & Issuer: CN=test

- Password: password

## Usage

```c#
TemporaryX509.CreateX509Certificate2()
TemporaryX509.CreateX509SecurityKey()
TemporaryX509.CreateSigningCredentials()
```
