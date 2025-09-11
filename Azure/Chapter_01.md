Good catch 👍 — you’ll need the **Object ID** when assigning roles, modifying Key Vault policies, or creating backdoors.

Here’s how to get it in Azure:

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
