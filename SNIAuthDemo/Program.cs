using Azure;
using Azure.Core;
using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Secrets;
using System.Security.Cryptography.X509Certificates;


namespace SNIAuthDemo
{
    public class Program
    {
        public static void Main(string[] args)
        {
            string vaultUrl = Environment.GetEnvironmentVariable("vaultUrl") ?? throw new ArgumentNullException("vaultUrl");
            string certName = Environment.GetEnvironmentVariable("certName") ?? throw new ArgumentNullException("certName");
            string clientId = Environment.GetEnvironmentVariable("clientId") ?? throw new ArgumentNullException("certName");
            string tenantId = Environment.GetEnvironmentVariable("tenantId") ?? throw new ArgumentNullException("certName");
            string scope = Environment.GetEnvironmentVariable("scope") ?? throw new ArgumentNullException("scope");

            TokenRequestContext requestContext = new TokenRequestContext(new string[] { scope });
            TokenCredential tokenCredential = GetCertificateTokenCredential(tenantId, clientId, vaultUrl, certName);
            AccessToken token = tokenCredential.GetToken(requestContext, default);
            Console.WriteLine(token.Token);
        }

        private static X509Certificate2 GetCertificate(string vaultUrl, string certName)
        {
            var certClient = new CertificateClient(new Uri(vaultUrl), new VisualStudioCredential());
            var secretClient = new SecretClient(vaultUri: new Uri(vaultUrl), credential: new VisualStudioCredential());
            Response<KeyVaultCertificateWithPolicy> certResponse = certClient.GetCertificate(certName);
            KeyVaultSecretIdentifier identifier = new KeyVaultSecretIdentifier(certResponse.Value.SecretId);
            Response<KeyVaultSecret> secretResponse = secretClient.GetSecret(identifier.Name, identifier.Version);
            KeyVaultSecret secret = secretResponse.Value;
            byte[] privateKeyBytes = Convert.FromBase64String(secret.Value);
            return new X509Certificate2(privateKeyBytes);
        }

        private static TokenCredential GetCertificateTokenCredential(string tenantId, string clientId, string vaultUrl, string certName)
        {
            return new ClientCertificateCredential(tenantId, clientId, GetCertificate(vaultUrl, certName), new ClientCertificateCredentialOptions() { SendCertificateChain = true });
        }
    }
}
