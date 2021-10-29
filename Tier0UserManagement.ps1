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
#>
<#
.Synopsis
    This script manage Tier 0 users 

.DESCRIPTION
	In the modern Tier 0 level Tier 0 user are located in the T0 OU and member of Tier 0 users group and authentication policy

.EXAMPLE
	.\T0usermgmt.ps1 $true
.INPUTS
    -RemoveUserFromPrivilegedGroups [$true|$false]
        If this paramter is set to $true users are not on the Tier 0 OU or in the AD default users container will be removed from privileged groups
        if this parameter is set to $false groups will beno be changed
    -PrivilegedOUPath
        is the DistinguishedName of the Tier 0 OU
    -Tier0UserGroupName   
        is the name of the Tier 0 Deny user group
    -KerberosPolicyName
        Is the name of the Kerberos authentication policy

.OUTPUTS
   none
.NOTES
    Version Tracking
    2021-10-29
    Initial Version available on GitHub
#>
<#
    script parameters
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [bool]
    $RemoveUserFromPrivilegedGroups,
    [Parameter(Mandatory=$false)]
	[string]
	$PrivilegedOUPath,
	# Parameter help description
	[Parameter(Mandatory=$false)]
	[string]
	$Tier0UserGroupName,
	[Parameter(Mandatory=$false)]
	[string]
	$KerberosPolicyName
)

function validateAndRemoveUser{
    param(
        [string] $SID
    )
    $UserDefaultContainer = (Get-ADDomain).UsersContainer
    $Group = Get-ADGroup -Identity $SID
    if ($null -eq $Group){
        Write-Debug "$SID not found"
        return
    }

    foreach ($member in (Get-ADGroupMember -Identity $Group))
    {
        if ($member.Sid -notlike "*-500") #Do not change the build in administrators group membership
        {
        if (($member.distinguishedName -notlike "*,$PrivilegedOUPath") -and ($member.DistinguishedName -notlike "*,$UserDefaultContainer")){
                if ($RemoveUserFromPrivilegedGroups){
                    Write-Debug "remove $member from $($Group.DistinguishedName)"
                    Remove-ADGroupMember -Identity $GroupName -Members $member
                }
                else {
                    Write-Host "Unexpected user $($member.distinguishedName)) found in $Group"
                }
            }
        }
    }
}
#region setting variables default values
if($PrivilegedOUPath -eq ""){ 
    $PrivilegedOUPath = "OU=Tier 0 - Accounts,OU=Admin," + (Get-ADDomain).DistinguishedName
}

if ($Tier0UserGroupName -eq ""){
    $Tier0UserGroupName = "T0-AllUsers"
}
if ($KerberosPolicyName -eq ""){ 
    $KerberosPolicyName = "Tier 0"
}
$ProtectedUsers = Get-ADGroup -Identity "$((Get-ADDomain).DomainSID)-525"
#endregion
#region Variables validation
if ($null -eq $ProtectedUsers){
    Write-Host "Protected Users not available"
    exit 0xA1   
}
$Tier0UsersGroup = Get-ADGroup -Identity $Tier0UserGroupName
if ($null -eq $Tier0UsersGroup){
    Write-Host "$Tier0UserGrupName not found"
    exit 0xA2
}
$KerberosAuthenticationPolicy = Get-ADAuthenticationPolicy -Filter {Name -eq $KerberosPolicyName}
if ($null -eq $KerberosAuthenticationPolicy){
    Write-Host "$KerberosPolicyName not found"
    exit 0xA3
}
if ($null -eq (Get-ADOrganizationalUnit -Filter {DistinguishedName -eq $PrivilegedOUPath})){
    Write-Output "Tier 0 OU $PrivilegedOUPath not available"
    exit 0xA4
}
#endregion

#region Validate the group membership and authentication policy settings in the Tier 0 OU 
foreach ($user in Get-ADUser -SearchBase $PrivilegedOUPath -Filter * -Properties msDS-AssignedAuthNPolicy, memberOf){
	#validate the user is member of Protected Users
    if ($user.memberOf -notcontains $ProtectedUsers.DistinguishedName){
        Add-ADGroupMember $ProtectedUsers $user
    }
	#validate the user is member of the Tier 0 users group
	if ($user.memberOf -notcontains $Tier0UsersGroup.DistinguishedName){
		Add-ADGroupMember $Tier0UserGroupName $user
    }
	#validate the Kerberos Authentication policy is assigned to the user
	if ($user.'msDS-AssignedAuthNPolicy' -ne $KerberosAuthenticationPolicy.DistinguishedName){
        Set-ADUser $user -AuthenticationPolicy $KerberosPolicyName}
}
#endregion

#region validate Critical Group Membership
#Well-known critical domain group relative domain sid
$PrivlegeDomainSid = @(
    "512", #Domain Admins
    "518", #Schema Admins
    "519", #"Enterprise Admins"
    "520", #Group Policy Creator Owner
    "522", #Cloneable Domain Controllers
    "527" #Enterprise Key Admins
    
)

foreach ($relativeSid in $PrivlegeDomainSid) {
    validateAndRemoveUser -SID "$((Get-ADDomain).DomainSID)-$RelativeSid"
}
#Backup Operators
validateAndRemoveUser -SID "S-1-5-32-551"
#Print Operators
validateAndRemoveUser -SID "S-1-5-32-550"
#Server Operators
validateAndRemoveUser -SID "S-1-5-32-549"
#Server Operators
validateAndRemoveUser -SID "S-1-5-32-548"
#Administrators
validateAndRemoveUser -SID "S-1-5-32-544"

#endregion
