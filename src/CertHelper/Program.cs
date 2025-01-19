using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;

namespace CertHelper;

class Program
{
    static void Main(string[] args)
    {
#if DEBUG
        string outputDirectory = @"D:\certs\";
        string signingDistinguishedName = "Development Signing Certificate";
        string encryptionDistinguishedName = "Development Encryption Certificate";
        int years = 5;
        bool exportCert = false;
#else
        if (args.Length < 5)
        {
            Console.WriteLine("Использование: программа <путь_к_папке> <signing_distinguished_name> <encryption_distinguished_name> <срок_в_годах> <cert>");
            return;
        }

        string outputDirectory = args[0];
        string signingDistinguishedName = args[1];
        string encryptionDistinguishedName = args[2];

        if (!int.TryParse(args[3], out int years) || years <= 0)
        {
            Console.WriteLine("Срок действия сертификата должен быть положительным числом.");
            return;
        }

        if (!bool.TryParse(args[4], out bool exportCert))
        {
            Console.WriteLine("cert: может принимать значения true или false.");
            return;
        }

        if (!Directory.Exists(outputDirectory))
        {
            Console.WriteLine($"Указанная папка не существует: {outputDirectory}");
            return;
        }
#endif

        var signingCert = CreateCertificate(
            $"CN={signingDistinguishedName}",
            $"{signingDistinguishedName}",
            X509KeyUsageFlags.DigitalSignature,
            DateTimeOffset.UtcNow.AddYears(years));

        var encryptionCert = CreateCertificate(
            $"CN={encryptionDistinguishedName}",
            $"{encryptionDistinguishedName}",
            X509KeyUsageFlags.KeyEncipherment,
            DateTimeOffset.UtcNow.AddYears(years));

        ExportCertificate(signingCert, outputDirectory, exportCert);
        ExportCertificate(encryptionCert, outputDirectory, exportCert);
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

    static void ExportCertificate(X509Certificate2 certificate, string path, bool exportCert)
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

        if (exportCert)
        {
            File.WriteAllBytes(Path.Combine(path, filename + ".cer"), certificate.Export(X509ContentType.Cert, string.Empty));
        }
    }
}
