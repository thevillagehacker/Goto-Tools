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
