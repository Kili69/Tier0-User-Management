<#
Script Info

Author: Andreas Lucas [MSFT]
Download: https://github.com/Kili69/Tier0-User-Management

Disclaimer:
This sample script is not supported under any Microsoft standard support program or service. 
The sample script is provided AS IS without warranty of any kind. Microsoft further disclaims 
all implied warranties including, without limitation, any implied warranties of merchantability 
or of fitness for a particular purpose. The entire risk arising out of the use or performance of 
the sample scripts and documentation remains with you. In no event shall Microsoft, its authors, 
or anyone else involved in the creation, production, or delivery of the scripts be liable for any 
damages whatsoever (including, without limitation, damages for loss of business profits, business 
interruption, loss of business information, or other pecuniary loss) arising out of the use of or 
inability to use the sample scripts or documentation, even if Microsoft has been advised of the 
possibility of such damages

.SYNOPSIS
Apply Tier 1 Kerberos authentication policies to Tier 1 administrators 

.DESCRIPTION
This script applies the Tier 1 Kerberos Authentication policy to Tier 1 administrators to avoid 
Tier 1 privileged account logon to Tier 2 computers. This script should run on domain controllers
as a schedule task. In a single-domain-forest it's recommended to run the script in the system context. 
On mulit-domain-forest it's recommended to run the script as a GMSA with privilege to modify all users in 
the Tier 1 administrator OU    

if the Kerberos Authentication policy is not available, the script terminates with error code 0xA3.

.PARAMETER KerberosAuthenticationPolicyName
    Is the name of the Tier 1 Kerberos authentication policy
.PARAMETER Tier1UserOU
    Is the relative path of the tier 1 User OU e.g.: OU=Users,OU=Tier 1,OU=Admin
    to apply the Kerberos Authentication policy to users in mulitple OU's separate the OU with ";"
.PARAMETER EnableMulitDomainSupport
    enables the mulit domain mode. In this mode the kerberos authentication policy will be applied to all 
    Tier 1 users in every domain the forest

.EXAMPLE
    .\Tier1UserManagement -KerberosAuthenticationPolicyName "Tier 1 Isolation" -Tier1UserOU "OU=Users,OU=Tier 1,OU=Admin"
        Applies the "Tier 1 Isolation" Kerberos policy to any user located in the OU=Users,OU=Tier 1,OU=Admin,DC=<domain>
    .\Tier1UserManagement -KerberosAuthenticationPolicyName "Tier 1 Isolation" -Tier1UserOU "OU=Users,OU=Tier 1,OU=Admin" -EnableMulitdomainSupport
        Applies the "Tier 1 Isolation" Kerberos policy to any user located in the OU=Users,OU=Tier 1,OU=Admin in every domain of the forest
    .\Tier1UserManagement -KerberosAuthenticationPolicyName "Tier 1 Isolation" -Tier1UserOU "OU=Users,OU=Tier 1,OU=Admin;OU=Org1,OU=Admins"
        Applies the "Tier 1 Isolation" Kerberos policy to any user located in the OU=Users,OU=Tier 1,OU=Admin,DC=<domain> and "OU=Org1,OU=Admins"
.NOTES
    Version 0.1.20240409 Initial version
#>
[cmdletbinding(SupportsShouldProcess=$true)]
param (
    # Name of the Kerberos Authentication Policy
    [Parameter(Mandatory = $true)]
    [string] $KerberosAuthenticationPolicyName,
    # OU for Tier 1 administrators
    [Parameter(Mandatory = $true)]
    [string] $Tier1UserOU,
    #Use this script in a mulit domain configuration
    [Parameter (Mandatory = $false)]
    [switch] $EnableMulitDomainSupport
)

<#
.SYNOPSIS
    Write status message to the console and to the log file
.DESCRIPTION
    the script status messages are writte to the log file located in the app folder. the the execution date and detailed error messages
    The log file syntax is [current data and time],[severity],[Message]
    On error message the current stack trace will be written to the log file
.PARAMETER Message
    status message written to the console and to the logfile
.PARAMETER Severity
    is the severity of the status message. Values are Error, Warning, Information and Debug. Except Debug all messages will be written 
    to the console
#>
function Write-Log {
    param (
        # status message
        [Parameter(Mandatory=$true)]
        [string]
        $Message,
        #Severity of the message
        [Parameter (Mandatory = $true)]
        [Validateset('Error', 'Warning', 'Information', 'Debug') ]
        $Severity
    )
    #Format the log message and write it to the log file
    $LogLine = "$(Get-Date -Format o), [$Severity], $Message"
    Add-Content -Path $LogFile -Value $LogLine 
    switch ($Severity) {
        'Error'   { 
            Write-Host $Message -ForegroundColor Red
            Add-Content -Path $LogFile -Value $Error[0].ScriptStackTrace  
        }
        'Warning' { Write-Host $Message -ForegroundColor Yellow}
        'Information' { Write-Host $Message }
    }
}

#region main program
$ScriptVersion = "1.0.20240409"
#region Manage log file
[int]$MaxLogFileSize = 1048576 #Maximum size of the log file
$LogFile = "$($env:LOCALAPPDATA)\$($MyInvocation.MyCommand).log" #Name and path of the log file
#rename existing log files to *.sav if the currentlog file exceed the size of $MaxLogFileSize
if (Test-Path $LogFile){
    if ((Get-Item $LogFile ).Length -gt $MaxLogFileSize){
        if (Test-Path "$LogFile.sav"){
            Remove-Item "$LogFile.sav"
        }
        Rename-Item -Path $LogFile -NewName "$logFile.sav"
    }
}
#endregion
Write-Log -Message "Tier 1 user management version $scriptVersion" -Severity Information
Write-Log -Message $MyInvocation.Line -Severity Debug

#Validate the Kerberos Authentication policy exists. If not terminate the script with error code 0xA3. 
$KerberosAuthenticationPolicy = Get-ADAuthenticationPolicy -Filter {Name -eq $KerberosAuthenticationPolicyName}
if ($null -eq $KerberosAuthenticationPolicy){
    Write-Log -Message "$KerberosAuthenticationPolicy not found" -Severity Error
    exit 0xA3
}
# enumerate the target domains. If the EnableMultiDomain switch is enabeled in a mulit domain forest, any domain will be part of the 
# Tier 0 user management. This is the recommended configuration, because the security boundary of Active Directory is the forest not the 
# domain. Any target domain will be captured in the $aryDomainName variable
$aryDomainName = @() #contains all domains for script validation
if ($EnableMulitDomainSupport){
    #MulitdomainSupport is enabled get all forest domains
    $aryDomainName += (Get-ADForest).Domains
} else {
    $aryDomainName += (Get-ADDomain).DNSRoot
}
foreach ($DomainName in $aryDomainName){
    try {
        Write-Log -Message "Searching users in $DomainName" -Severity Information
        foreach ($OU in $Tier1UserOU.Split(";")){
            #searching in every domain
            $PrivilegedOUPath = "$OU,$((Get-ADDomain -Server $DomainName).DistinguishedName)"
            if ($null -eq (Get-ADObject -Filter "DistinguishedName -eq '$PrivilegedOUPath'" -Server $domainName)){
                Write-Log -Message "OU $PrivilegedOUPath on $domainName doesn't exists" -Severity Warning
            } else {
                foreach ($user in Get-ADUser -SearchBase $PrivilegedOUPath  -Filter * -Properties msDS-AssignedAuthNPolicy, memberOf -SearchScope Subtree -Server $DomainName){
                    if ($user.'msDS-AssignedAuthNPolicy' -ne $KerberosAuthenticationPolicy.DistinguishedName){
                        Write-Log -Message "applying Authentication policy '$($KerberosAuthenticationPolicy.Name)' to $($User.DistinguishedName)" -Severity Information
                        try {
                            #Apply the Kerberos Authentication policy to the user
                            Set-ADUser $user -AuthenticationPolicy $KerberosAuthenticationPolicy -Server $DomainName
                        }
                        catch [Microsoft.ActiveDirectory.Management.ADException]{
                            #typical access denied to the user object
                            Write-Log -Message "Can not assign Authentication policy '$($KerberosAuthenticationPolicy.Name)' to $user due a AD exception --> $($Error[0].Exception.Message)" -Severity Error
                        }
                        catch {
                            #write any unhandled error to the log file
                            Write-Log -Message "The Kerberos Authentication policy '$($KerberosAuthenticationPolicy.Name)' could not be added to $($user.DistinguishedName) --> $($Error[0].Exception.Message)" -Severity Error
                        }
                    }
                }
            }
        }
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]{
        #this error occurs if the user is in the global catalog but not available on the DC
        Write-Log -Message "Can't get the users in $PrivilegedOUPath on $DomainName. --> $($Error[0].Exception.Message)" -Severity Error
    }
    catch {
        #write any unhandled error to the log file
        Write-Log -Message "A unexpected error $($Error[0].CategoryInfo.Reason) has occured while working on user $($user.DistinguishedName) --> $($Error[0].Exception.Message)" -Severity Error
    }
}
#endregion 