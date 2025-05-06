# mfa-cache-ssh-key-PAMSH-RESTAPI
Cache MFA for SSH Connections via PSM for SSH Proxy - PAM Self Hosted
# CyberArk PAM SSH Key Generation Script

This PowerShell script automates the process of authenticating to **CyberArk PAM Self-Hosted (PVWA)** using **LDAP credentials**, and then generates a **MFA-caching SSH private key** via the CyberArk REST API.

It supports multiple SSH key formats and includes basic metadata reporting and expiration monitoring (if supported by the API).

---

## Features

- ✅ LDAP-based authentication to CyberArk PVWA
- 🔐 Secure generation of SSH MFA-caching private key
- 🔄 Support for key formats: `PPK`, `PEM`, and `OpenSSH`
- 📁 Secure file write with strict permissions (`icacls`)

---

## 📋 Requirements

- PowerShell 5.1 or later
- Access to a CyberArk PVWA instance with API access enabled
- A valid LDAP user with permission to generate SSH keys

---

## 🛠️ Configuration

Update the following variables at the top of the script as needed:

```powershell
$PVWA_URL     = "https://comp01.cybr.com"
$key_path     = "C:\Users\john\Documents\mfassh"
$key_filename = "mfa_caching_key"

