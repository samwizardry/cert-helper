using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;

namespace CertHelper;

class Program
{
    static void Main(string[] args)
    {
        var signingCert = CreateCertificate(
            "CN=Renna EStore Signing Certificate",
            "Renna EStore Signing Certificate",
            X509KeyUsageFlags.DigitalSignature,
            DateTimeOffset.UtcNow.AddYears(5));

        var encryptionCert = CreateCertificate(
            "CN=Renna EStore Encryption Certificate",
            "Renna EStore Encryption Certificate",
            X509KeyUsageFlags.KeyEncipherment,
            DateTimeOffset.UtcNow.AddYears(5));

        ExportCertificate(signingCert, @"D:\certs");
        ExportCertificate(encryptionCert, @"D:\certs");
    }

    static X509Certificate2 CreateCertificate(
        string distinguishedName,
        string friendlyName,
        X509KeyUsageFlags x509KeyUsageFlags,
        DateTimeOffset notAfter)
    {
        using var algorithm = RSA.Create(keySizeInBits: 2048);
        var subject = new X500DistinguishedName(distinguishedName);
        var request = new CertificateRequest(subject, algorithm, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509KeyUsageExtension(x509KeyUsageFlags, critical: true));
        var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow, notAfter);

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            certificate.FriendlyName = friendlyName;
        }

        return certificate;
    }

    static void ExportCertificate(X509Certificate2 certificate, string path)
    {
        var filename = certificate.Subject
            .ToLower()
            .Replace(' ', '-')
            .Substring(3);

        if (!Directory.Exists(path))
        {
            Directory.CreateDirectory(path);
        }

        File.WriteAllBytes(Path.Combine(path, filename + ".pfx"), certificate.Export(X509ContentType.Pfx, string.Empty));
        File.WriteAllBytes(Path.Combine(path, filename + ".cer"), certificate.Export(X509ContentType.Cert, string.Empty));
    }
}
