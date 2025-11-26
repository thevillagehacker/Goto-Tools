# Reverse Engineering C++ Application

## 1. High-level methodology for RE-based security review

Think in four layers:

1. **Recon & Surface Mapping**

   * What does this binary do?
   * What are its inputs/outputs and trust boundaries?
   * How does it interact with the OS, network, files, registry, IPC, crypto APIs, etc.?

2. **Attack Surface & Entry Points**

   * All external interfaces that untrusted data can reach (network messages, config files, environment variables, registry, IPC, plugins, COM, RPC, etc.).
   * UI event handlers, exported functions, RPC handlers, command handlers, etc.

3. **Vulnerability Classes**

   * Memory-safety issues (classic C/C++).
   * Logic / auth flaws.
   * Crypto misuse.
   * Persistence / privilege escalation angles.
   * Anti-reverse engineering or obfuscation weaknesses that can be bypassed.

4. **Abuse Scenarios**

   * Code execution, sandbox escape, local privilege esc, lateral movement.
   * Secrets exfiltration, integrity loss, bypassing license checks or security checks.

---

## 2. Tooling & Workflow (Ghidra-centric, MSVC C++)

### 2.1 Initial triage

Use: `pefile`, `Detect It Easy`, `diec`, `CFF Explorer`, `PE-bear`, or Ghidra’s own PE analyzer.

Check:

* **PE properties**:

  * Is it 32-bit or 64-bit?
  * ASLR (Dynamic base), DEP (NX), CFG, HIGHENTROPYVA flags.
  * SafeSEH, GS (`/GS`), `/DYNAMICBASE`, `/NXCOMPAT`, `/guard:cf` indicators.
* **Compiler / packer / obfuscator**:

  * MSVC version (look for msvcrt imports, toolset signatures).
  * Packed? UPX/Themida/VMProtect/etc. If packed, you may need an unpacking step.
* **Imports/exports**:

  * Network: `WSARecv`, `send`, `WinInet`, `WinHTTP`, `WinHTTPOpenRequest`, `InternetReadFile`.
  * File/registry: `CreateFileA/W`, `ReadFile`, `WriteFile`, `RegSetValueEx`, `SHFileOperation`.
  * Process/privilege: `CreateProcess`, `ShellExecute`, `OpenProcess`, `AdjustTokenPrivileges`, etc.
  * Crypto: `CryptEncrypt`, `BCryptEncrypt`, `CryptProtectData`, `BCryptDeriveKeyPBKDF2`, etc.
* **Resources**:

  * Embedded configuration, certificates, scripts, secondary binaries, icons, dialogs.

Security angle: you are building a mental model of capabilities and attack surface without reading deep code yet.

---

### 2.2 Loading in Ghidra

1. Import the PE into Ghidra, run:

   * **PE** analyzer
   * **Symbol** recovery (PDB search if available)
   * **Function ID / Signature analysis**
   * **Decompile and analyze**

2. Organise the project:

   * Tag namespaces: `network`, `auth`, `crypto`, `update`, `ipc`, etc.
   * Bookmark important functions (e.g., entrypoints, `WinMain`, notable exports, handlers).

3. Leverage:

   * **Strings window** (search for format strings, error messages, SQL queries, URLs, tokens, etc.).
   * **Function call graphs** to identify hubs: auth checks, packet handlers, parsing routines, etc.
   * **Dataflow analysis**: track how user-controlled buffers propagate to dangerous sinks.

---

### 2.3 Identifying sources, sinks and trust boundaries

In your notes, explicitly mark:

* **Sources of untrusted data**:

  * Network sockets, HTTP endpoints, named pipes, mailslots.
  * File inputs, config files, logs that might be modified.
  * Environment variables, registry keys, command line arguments.
  * IPC from lower-integrity or unprivileged processes.

* **Sinks**:

  * Memory writes, stack buffers, `strcpy`, `sprintf`, `memcpy`, custom serialization routines.
  * System commands (`CreateProcess`, `ShellExecute`, `system`).
  * SQL APIs, template engines, script evaluators.
  * Crypto APIs that accept keys/IVs, certificate validation logic.

* **Trust Boundary Crossings**:

  * Any time data moves from lower to higher privilege / trust level (client → service, low-integrity → medium/high, external → internal modules).

---

## 3. Vulnerability hunting dimensions (what to look for)

I will group these by vulnerability class; these directly translate into a checklist.

### 3.1 Memory-safety & unsafe APIs

Focus on:

* Classic unsafe CRT/Win32 APIs:

  * `strcpy`, `strcat`, `sprintf`, `vsprintf`, `gets`, `scanf` without bounds.
  * `wcscpy`, `lstrcpy`, `wsprintf`.
  * `memcpy`, `memmove` where length is derived from untrusted input or unvalidated size fields.
  * Custom serialization/deserialization using raw pointers/buffers.
* Manual buffer allocations:

  * `new`/`new[]`, `malloc`, `HeapAlloc` with size derived from user input.
  * Integer overflows in size calculations (e.g., `count * sizeof(struct)`).
* Stack buffer usage:

  * Large local arrays.
  * Data copied to these arrays without robust length checks.
* Use-after-free / double-free patterns:

  * Functions that `delete` or `free` pointers then continue using those references.
  * Multiple code paths freeing same pointer.
* Type confusion / unsafe casting:

  * Frequent use of C-style casts and reinterpret_cast between unrelated object types.
  * Manual vtable manipulations or custom RTTI logic.

Security questions:

* Can untrusted data reach `memcpy` length?
* Might attacker control size of allocation leading to overflow/underflow?
* Are there integer overflows in `length + 1`, `count * sizeof`?

---

### 3.2 Input validation and parsing weak points

Look for:

* Custom parsing of:

  * Network protocols, binary messages, TLVs, lengths, offsets.
  * File formats (custom logs, config, resource files).
  * Text/command protocols (CLI/commands embedded in data).
* Patterns where:

  * Length fields are trusted without cross-checking against buffer size.
  * Indices or offsets are used directly as array indexes/pointers.
* Recursion or loops that parse repeated structures (potential DoS / complexity attacks).

Checks to perform:

* Are lengths validated against actual buffer boundaries?
* Are nested structures validated recursively?
* Are unexpected types/IDs handled gracefully or do they fall through to dangerous behaviour?

---

### 3.3 Authentication, authorization and license/feature checks

In C++ business apps and services, RE often reveals:

* Hard-coded usernames/passwords, tokens, API keys.
* Logic like:

  * `if (isPremium || isTrialBypassed) { ... }`
  * License checks that can be patched or bypassed.
* Role/ACL checks implemented inconsistently or client-side only.

Analysis approach:

* Find all references to:

  * `Login`, `Auth`, `Token`, `JWT`, `License`, `Key`, `Serial`, `Trial`, `Premium`.
* Trace the logic:

  * How are credentials checked?
  * Is the check performed both client and server side or only in client?
* Spot vulnerable patterns:

  * String comparison replaced by weak checks (`strstr`, `memcmp` on fixed prefix).
  * Early returns that grant access on certain errors.

Security issues:

* Client-side only authorization.
* Weak or patchable license/feature gates.
* Missing checks for specific operations.

---

### 3.4 Crypto misuse

Typical MSVC C++ issues:

* Use of obsolete/weak algorithms:

  * MD5, SHA1, RC4, DES, 3DES without justification.
  * Static AES keys and IVs hard-coded in the binary.
* Incorrect modes and parameters:

  * ECB mode on sensitive structured data.
  * Constant IVs or non-random nonces.
* Insecure key handling:

  * Keys derived from predictable values (username, system time, MAC address).
  * Keys or secrets stored in plain in data segments.
* Improper certificate/SSL validation:

  * Calls to `WinHTTPSetOption`, `WinInet` certificate callbacks that disable validation.
  * Logic that always returns “true” in cert validation callback.

What to do:

* Map all calls to `Crypt*`, `BCrypt*`, `Cert*`, `WinHTTP*`, `WinInet*`.
* Identify algorithm IDs, key lengths, modes.
* Check random source (`CryptGenRandom`, `BCryptGenRandom` vs custom RNG).

---

### 3.5 Process, privilege and OS interaction

Look at:

* Privilege escalation patterns:

  * Services running as `LocalSystem` interacting with user-writable locations.
  * Writes to directories under `C:\ProgramData`, `%TEMP%`, or non-ACL-protected paths.
  * Loading DLLs from insecure paths (DLL search order hijacking).
* Process creation:

  * `CreateProcess`, `ShellExecute`, `system`, `WinExec` using untrusted data for command line.
  * Quoted/unquoted paths that can lead to untrusted binary execution.
* Token manipulation and impersonation:

  * `OpenProcessToken`, `AdjustTokenPrivileges`, `ImpersonateLoggedOnUser`, etc.
* Named pipes / RPC / COM:

  * Are ACLs on IPC channels enforced?
  * Is there any “client authentication” or is it trusting all local clients?

Risks:

* Local privilege escalation.
* Arbitrary command execution.
* Lateral movement via weak IPC authentication.

---

### 3.6 Persistence, auto-update and self-update mechanisms

If the app has updater / agent components:

* Registry run keys, scheduled tasks, services, startup folder entries.
* Update logic:

  * Downloading unsigned binaries or updates over HTTP.
  * Signature check logic that can be bypassed.
  * Insecure use of temp directories for new binaries (TOCTOU, DLL hijack, path traversal).
* File replacement logic:

  * Writes to `.exe` or `.dll` files in directories writable by non-admin users.

---

### 3.7 Anti-debugging, obfuscation, and their weaknesses

Even though this is more offensive-leaning, from a defensive/review angle you want to know:

* Which anti-debugging techniques are used:

  * `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, `NtQueryInformationProcess`, timing checks, SEH tricks.
* Obfuscation / packing:

  * Are functions inlined, control flow flattened, strings encrypted?
* Weaknesses:

  * Simple, reversible string encryption.
  * Key derivation for string decoding being easily patchable.

Why it matters for security review:

* Tends to hide sensitive code (auth, license check, crypto).
* If anti-debugging can be trivially bypassed, protection claims are weak (license, DRM, etc.).

---

## 4. Concrete Reverse Engineering Security Checklist

Use this as a “section” in your overall test plan / report under “Reverse Engineering Review of MSVC++ Binary.”

You can adapt into headings + checkboxes.

---

### 4.1 Binary & Build-time Hardening

* [ ] PE headers reviewed for:

  * [ ] `/DYNAMICBASE` (ASLR) enabled.
  * [ ] `/NXCOMPAT` (DEP) enabled.
  * [ ] `/GS` (stack cookies) enabled.
  * [ ] Control Flow Guard (CFG) enabled.
  * [ ] SafeSEH (for 32-bit) presence.
* [ ] No obvious use of insecure linker flags (e.g., `/SAFESEH:NO`, disabled GS).
* [ ] No unnecessary exported functions that widen attack surface.
* [ ] Binary not packed/obfuscated without clear business justification (or packing documented and robust).

---

### 4.2 Attack Surface Mapping

* [ ] Network endpoints identified (ports, protocols, client/server roles).
* [ ] File formats and data files used identified.
* [ ] IPC mechanisms enumerated (named pipes, shared memory, COM/RPC).
* [ ] External dependencies mapped (DLLs, drivers, services).
* [ ] Authentication boundaries and privilege boundaries for each interface documented.

---

### 4.3 Memory-Safety Review

For each untrusted data path:

* [ ] All uses of unsafe string/buffer functions identified and assessed.
* [ ] Buffer allocations and size calculations checked for integer overflows.
* [ ] Stack buffers receiving data from external inputs checked for overflow risk.
* [ ] Dynamic allocations with user-controlled sizes validated with upper bounds.
* [ ] Potential use-after-free / double-free patterns reviewed.
* [ ] Custom allocators or pool managers inspected for edge cases.

---

### 4.4 Input Parsing & Validation

* [ ] Network / file / IPC parsing routines identified and documented.
* [ ] All length fields validated against buffer boundaries.
* [ ] Indexes/offsets derived from attacker data validated before use.
* [ ] Malformed/unknown message types handled gracefully.
* [ ] Recursion/deep nesting protected with depth limits or size caps.
* [ ] Any data deserialization (binary or text) checked for controlled object creation.

---

### 4.5 Authentication & Authorization Logic

* [ ] Credentials handling examined; no hard-coded passwords/keys for production.
* [ ] All authentication flows mapped (login, token refresh, etc.).
* [ ] Client-side auth logic checked for bypassability (simple patches).
* [ ] Authorization checks present on all sensitive operations (not just UI level).
* [ ] Role/permission logic consistent and centralised, not scattered and ad-hoc.
* [ ] License / feature gates evaluated to detect trivially patchable checks where it matters.

---

### 4.6 Cryptographic Usage

* [ ] All crypto API usage located (CNG, CryptoAPI, OpenSSL, custom).
* [ ] Algorithms and modes reviewed for strength and suitability.
* [ ] Key lengths meet modern standards.
* [ ] Keys, secrets, API keys not hard-coded or stored in plain text.
* [ ] Randomness sourced from secure PRNG (no custom LCG/XOR shifts for security).
* [ ] TLS/certificate validation logic validated (no wholesale disabling of validation).
* [ ] Any proprietary crypto scheme flagged as high risk and documented.

---

### 4.7 OS & Privilege Interactions

* [ ] Process creation and command execution points identified.
* [ ] Command line construction validated to prevent injection from untrusted data.
* [ ] Service binaries and privilege levels documented.
* [ ] Any service / privileged component checked for:

  * [ ] Use of user-writable directories.
  * [ ] Insecure DLL search paths (DLL hijacking potential).
  * [ ] Weak ACLs on IPC channels (pipes, shared memory, objects).
* [ ] Token manipulation reviewed for least privilege adherence.
* [ ] File and registry writes to sensitive locations verified for correct ACLs.

---

### 4.8 Update, Installation & Persistence

* [ ] Updater/installer components identified.
* [ ] Update channel security:

  * [ ] Uses TLS with proper certificate validation.
  * [ ] Update packages signed; signature checks enforced.
* [ ] Temporary file usage and install paths checked for privilege issues.
* [ ] Persistence mechanisms documented (services, run keys, startup shortcuts).
* [ ] No ability for unprivileged user to replace executables or DLLs used by privileged services.

---

### 4.9 Anti-Debugging / Obfuscation / Tamper Protections

* [ ] Anti-debug techniques identified and their robustness evaluated.
* [ ] String/constant protection mechanisms identified (if any).
* [ ] Integrity checks (self-hashing, signature checks) located and assessed:

  * [ ] Are they easily bypassed with a few patches?
  * [ ] Do they protect meaningful assets (keys, license logic, anti-cheat, etc.)?
* [ ] Any claim of “tamper proof” or “anti-reverse” validated against actual protection.

---

### 4.10 Secrets & Sensitive Data Handling

* [ ] Hard-coded secrets searched via:

  * [ ] Strings in binary.
  * [ ] Data segments.
  * [ ] Obvious encoding (base64, XOR).
* [ ] In-memory handling of secrets assessed (zeroization, minimal exposure).
* [ ] Local storage of tokens/keys checked (files, registry, DPAPI usage).
* [ ] Logging evaluated (no secrets in logs).

---

### 4.11 Exploitability & Impact Assessment

For each identified weakness:

* [ ] Reachability from realistic attacker positions (local user, network client, etc.).
* [ ] Required privileges and conditions.
* [ ] Exploitability estimate (theoretical / limited / practical).
* [ ] Potential impact (RCE, LPE, data exfil, DoS, auth bypass, license bypass).
* [ ] Recommended mitigations (code fix, configuration, compiler flags, OS protections).

---
