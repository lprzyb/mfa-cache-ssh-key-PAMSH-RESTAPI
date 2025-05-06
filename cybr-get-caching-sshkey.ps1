<#
Title: CyberArk PAM SSH Key Generator
Author: luke.przybylski@cyberark.com
Date: 2025-05-06
Description:
    This PowerShell script authenticates to CyberArk PAM Self-Hosted (PVWA) using LDAP,
    and generates an SSH private key that supports MFA caching.

Features:
    - Secure LDAP authentication via API
    - SSH key generation with selectable format (PPK, PEM, OpenSSH)
    - Saves the key to a local file with restricted permissions using icacls

Configuration:
    - Set PVWA URL and key output path in the config section
    - Script prompts for LDAP username and password securely
    - Choose from supported formats during execution

Security:
    - Credentials are not stored
    - File permissions are restricted to the current user

Output:
    - The key is saved as: <key_filename>.<format> in the defined path

Usage:
    Run the script in PowerShell. You will be prompted to select key format and log in.

Example:
    PS> .\Generate-CyberArk-SSHKey.ps1

#>

# === [CONFIGURATION] ===
$PVWA_URL     = "https://comp01.cybr.com"
$url_auth     = "$PVWA_URL/PasswordVault/api/auth/LDAP/logon"
$url_get_key  = "$PVWA_URL/PasswordVault/api/users/secret/sshkeys/cache"
$key_path     = "C:\Users\john\Documents\mfassh"
$key_filename = "mfa_caching_key"

# === [FUNCTIONS] ===

function Select-KeyFormat {
    Write-Host "Select SSH key format:" -ForegroundColor Cyan
    Write-Host "1. PPK (PuTTY)"
    Write-Host "2. PEM (X.509-compatible)"
    Write-Host "3. OpenSSH (default for Linux/macOS)"
    $choice = Read-Host "Enter choice [1-3]"
    switch ($choice) {
        '1' { return "PPK" }
        '2' { return "PEM" }
        '3' { return "OpenSSH" }
        default {
            Write-Host "Invalid choice. Defaulting to OpenSSH." -ForegroundColor Yellow
            return "OpenSSH"
        }
    }
}

function Get-AuthToken {
    param (
        [string]$Url,
        [PSCredential]$Credential
    )
    $headers = @{ "Content-Type" = "application/json" }
    $body = @{
        UserName          = $Credential.UserName
        Password          = $Credential.GetNetworkCredential().Password
        concurrentSession = "true"
    } | ConvertTo-Json -Depth 3

    try {
        $response = Invoke-RestMethod -Uri $Url -Method POST -Headers $headers -Body $body
        if (-not $response) { throw "No token returned from API." }
        Write-Host "[+] Successfully authenticated." -ForegroundColor Green
        return $response
    } catch {
        Write-Host "[-] Authentication failed: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}

function Generate-SSHKey {
    param (
        [string]$Url,
        [string]$Token,
        [string]$Format
    )
    $headers = @{
        Authorization = $Token
        "Content-Type" = "application/json"
    }

    $payload = @{ formats = @($Format) } | ConvertTo-Json

    try {
        $response = Invoke-RestMethod -Uri $Url -Method POST -Headers $headers -Body $payload
        if (-not $response.value.privateKey) { throw "No private key returned." }
        return $response.value
    } catch {
        Write-Host "[-] SSH key generation failed: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}

function Save-PrivateKey {
    param (
        [string]$KeyContent,
        [string]$Path,
        [string]$Filename,
        [string]$Extension
    )

    $filePath = Join-Path $Path "$Filename.$Extension"

	 # Check if the file already exists and delete if true
        if (Test-Path $filePath) {
            Write-Host "[!] Key file already exists. Deleting the existing file..." -ForegroundColor Yellow
            Remove-Item $filePath
        }


    $KeyContent | Out-File -FilePath $filePath -Encoding ascii -Force

    # Harden file permissions to current user only
    $currentUser = "$env:USERDOMAIN\$env:USERNAME"
    icacls $filePath /inheritance:r | Out-Null
    icacls $filePath /grant:r "$($env:USERNAME):(RX,D)" | Out-Null

    Write-Host "[+] SSH key saved and secured at $filePath" -ForegroundColor Green
}

# === [MAIN EXECUTION] ===

$key_format = Select-KeyFormat
$cred = Get-Credential
$token = Get-AuthToken -Url $url_auth -Credential $cred
$keyInfo = Generate-SSHKey -Url $url_get_key -Token $token -Format $key_format
Save-PrivateKey -KeyContent $keyInfo.privateKey -Path $key_path -Filename $key_filename -Extension $key_format