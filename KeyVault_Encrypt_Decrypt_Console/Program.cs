using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System.Configuration;
using Microsoft.Azure;
using Microsoft.Azure.Storage;
using Microsoft.Azure.Storage.Auth;
using Microsoft.Azure.Storage.Blob;
using Microsoft.Azure.KeyVault;
using System.Threading;
using System.IO;

namespace KeyVault_Encrypt_Decrypt_Console
{
    class Program
    {
        private async static Task<string> GetToken(string authority, string resource, string scope)
        {
            var authContext = new AuthenticationContext(authority);
            ClientCredential clientCred = new ClientCredential(
                CloudConfigurationManager.GetSetting("clientId"),
                CloudConfigurationManager.GetSetting("clientSecret"));
            AuthenticationResult result = await authContext.AcquireTokenAsync(resource, clientCred);

            if (result == null)
                throw new InvalidOperationException("Failed to obtain the JWT token");

            return result.AccessToken;
        }
        static void Main(string[] args)
        {
            // This is standard code to interact with Blob storage.
            StorageCredentials creds = new StorageCredentials(
                CloudConfigurationManager.GetSetting("accountName"),
                CloudConfigurationManager.GetSetting("accountKey"));
            CloudStorageAccount account = new CloudStorageAccount(creds, useHttps: true);
            CloudBlobClient client = account.CreateCloudBlobClient();
            CloudBlobContainer contain = client.GetContainerReference(CloudConfigurationManager.GetSetting("container"));
            contain.CreateIfNotExists();

            // The Resolver object is used to interact with Key Vault for Azure Storage.
            // This is where the GetToken method from above is used.
            KeyVaultKeyResolver cloudResolver = new KeyVaultKeyResolver(GetToken);


            //Encrypt Blob and upload
            // Retrieve the key that you created previously.
            // The IKey that is returned here is an RsaKey.
            var rsa = cloudResolver.ResolveKeyAsync(
                        "https://phupaa-vault.vault.azure.net/keys/key01",
                        CancellationToken.None).GetAwaiter().GetResult();

            // Now you simply use the RSA key to encrypt by setting it in the BlobEncryptionPolicy.
            BlobEncryptionPolicy policy = new BlobEncryptionPolicy(rsa, null);
            BlobRequestOptions options = new BlobRequestOptions() { EncryptionPolicy = policy };

            // Reference a block blob.
            CloudBlockBlob blob = contain.GetBlockBlobReference("MyFile.txt");

            // Upload using the UploadFromStream method.
            using (var stream = System.IO.File.OpenRead(@"C:\Temp\MyFile.txt"))
                blob.UploadFromStream(stream, stream.Length, null, options, null);




            //Decrypt blob
            // In this case, we will not pass a key and only pass the resolver because
            // this policy will only be used for downloading / decrypting.
            BlobEncryptionPolicy policy2 = new BlobEncryptionPolicy(null, cloudResolver);
            BlobRequestOptions options2 = new BlobRequestOptions() { EncryptionPolicy = policy };

            using (var np = File.Open(@"C:\temp\MyFileDecrypted.txt", FileMode.Create))
                blob.DownloadToStream(np, null, options, null);
        }
    }
}
