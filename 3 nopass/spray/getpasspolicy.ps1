# Function to display usage
function Show-Usage {
    Write-Host "`nSyntax: getpasspolicy.ps1"
    Write-Host "You will be prompted to enter the DC IP address, username, and password.`n"
}

# Check if the user is running the script with admin privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Please run as administrator"
    exit
}

Show-Usage

# Prompt for DC IP address, username, and password
$DC_IP = Read-Host "Enter the IP address of the Domain Controller"
$DOMAIN_USERNAME = Read-Host "Enter the domain\username"
$PASSWORD = Read-Host "Enter the password" -AsSecureString

# Validate input
if ([string]::IsNullOrWhiteSpace($DC_IP) -or [string]::IsNullOrWhiteSpace($DOMAIN_USERNAME) -or ($PASSWORD.Length -eq 0)) {
    Write-Host "Error: DC IP address, username, and password are required."
    exit
}

# Create credentials object
$cred = New-Object System.Management.Automation.PSCredential ($DOMAIN_USERNAME, $PASSWORD)

# Run the command to get the password policy from the domain controller
try {
    $session = New-PSSession -ComputerName $DC_IP -Credential $cred
    Import-Module ActiveDirectory -PSSession $session
    $policy = Invoke-Command -Session $session -ScriptBlock { Get-ADDefaultDomainPasswordPolicy }
    Write-Host $policy
}
catch {
    Write-Host "An error occurred: $_"
}
finally {
    Remove-PSSession -Session $session
}
