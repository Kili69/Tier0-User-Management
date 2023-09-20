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
	In the modern Tier 0 level Tier 0 user are located in the T0 OU and member of Tier 0 users group and authentication policy. This script will remove unexpcted users from privileged groups,
    if they are not located in the Tier 0 users OU, Tier 0 service account ou, in the users container or in the group management service account container. 
    Ther Tier 0 Kerberos Authentication Policy will be automatically atted to sers located in the Tier 0 User OU, but not for service acocunts and GMSA

.EXAMPLE
	.\T0usermgmt.ps1 $true
.PARAMETER RemoveUserFromPrivilegedGroups [$true|$false]
        If this paramter is set to $true users are not on the Tier 0 OU or in the AD default users container will be removed from privileged groups
        if this parameter is set to $false groups will beno be changed
.PARAMETER PrivilegedOUPath 
        is the DistinguishedName of the Tier 0 OU
.PARAMETER Tier0UserGroupName   
        is the name of the Tier 0 Deny user group
.PARAMETER KerberosPolicyName
        Is the name of the Kerberos authentication policy
.PARAMETER PrivilegedServiceAccountOUPath
        is the distinguisehdname of the Tier 0 service accounts
.PARAMETER ExcludeUsers
        a list ob users who will not be removed from the privileged groups

.OUTPUTS
   none
.NOTES
    Version Tracking
    2021-10-29
    Initial Version available on GitHub
    2023-05-24
    T0 service accounts located in the T0 service account OU, will be automatically added to Tier 0 users Group
    T0 will not added to Protected User Group anymore
    Managed User Accounts can now be member of a privileged Groups
    1.0.20230914
        Version numbering changed
        users from child will be removed if they are in a privileged group
        new parameter introduced -excludeusers is a list of users who will be ignored by the script
    1.0.20230920
        write output if users removed from a privileged group
#>
<#
    script parameters
#>
[CmdletBinding()]
param (
    #If this parameter is $true, users located not in the T0 Users OU automaticaly removed from privileged Groups
    [Parameter(Mandatory=$false)]
    [bool]
    $RemoveUserFromPrivilegedGroups=$true,
    #Is the OU Path for T0 Users
    [Parameter(Mandatory=$false)]
	[string]
	$PrivilegedOUPath,
    #Is the OU path for T0 user accounts
    [Parameter(Mandatory=$false)]
    [string]
    $PrivilegedServiceAccountOUPath,
	#Name of the Tier 0 users group
	[Parameter(Mandatory=$false)]
	[string]
	$Tier0UserGroupName = "T0 - All Users",
    #Is the name of the KerberosAuthentication Policy
	[Parameter(Mandatory=$false)]
	[string]
	$KerberosPolicyName,
    #users of domain admins which should be disabled by the script
    [Parameter (Mandatory=$false)]
    [string]
    $ExcludeUser

)

<#
.SYNOPSIS
    Remove unexpected user to the privileged group 
.DESCRIPTION 
    Searches for users in privileged groups and remove those user if the are not 
    - in the correct OU
    - the built-In Administrator

#>
function validateAndRemoveUser{
    param(
        [string] $SID
    )
    $Group = Get-ADGroup -Identity $SID -Properties members
    $Domain = Get-ADDomain
    #validate the SID exists
    if ($null -eq $Group){
        Write-Debug "$SID not found"
        return
    }

    foreach ($Groupmember in $Group.members)
    {
        $member = Get-ADObject -Filter {DistinguishedName -eq $Groupmember} -Properties * -server "$($Domain.DnsRoot):3268"
        if (($member.ObjectSid.Value -notlike "*-500") -and ($member.objectClass -eq "user")){ #Do not change the build in administrators group membership
            #ignore any user listes in the exclude parameter
            if (($member.distinguishedName -notlike "*,$PrivilegedOUPath") -and ($member.distinguishedName -notlike "*,$PrivilegedServiceAccountOUPath") -and ($ExcludeUser -notlike "*$($Domain.NetBIOSName)\$($member.SamAccountName)*")){    
                if ($RemoveUserFromPrivilegedGroups){
                Write-Host "remove $member from $($Group.DistinguishedName)"
                Set-ADObject -Identity $Group -Remove @{member="$($member.DistinguishedName)"} 
                } else {
                    Write-Output "Unexpected user $($member.distinguishedName)) found in $Group"
                }
            }
        }
    }
}

#main program
$ScriptVersion = "1.0.20230920"
Write-Output "Tier 0 user management version $scriptVersion"

#region setting variables default values
if($PrivilegedOUPath -eq ""){ 
    $PrivilegedOUPath = "OU=Tier 0 - User Privileged,OU=Admin," + (Get-ADDomain).DistinguishedName
}

if ($PrivilegedServiceAccountOUPath -eq ""){
    $PrivilegedServiceAccountOUPath = "OU=Tier 0 - Service Accounts,OU=Admin,$((Get-ADDomain).DistinguishedName)" 
}

if ($KerberosPolicyName -eq ""){ 
    $KerberosPolicyName = "Tier 0 Logon Restriction"
}

#region Parameter validation
#Validate the Tier 0 group is available
$Tier0UsersGroup = Get-ADGroup -Identity $Tier0UserGroupName
if ($null -eq $Tier0UsersGroup){
    Write-Host "$Tier0GroupName not found"
    exit 0xA2
}
#Validate the Kerboers Authentication policy exists
$KerberosAuthenticationPolicy = Get-ADAuthenticationPolicy -Filter {Name -eq $KerberosPolicyName}
if ($null -eq $KerberosAuthenticationPolicy){
    Write-Host "$KerberosPolicyName not found"
    exit 0xA3
}
#Validate the Tier 0 users OU exists
if ($null -eq (Get-ADOrganizationalUnit -Filter {DistinguishedName -eq $PrivilegedOUPath})){
    Write-Output "Tier 0 OU $PrivilegedOUPath not available"
    exit 0xA4
}
#Validate the Tier 0 service OU exists
if ($null -eq (Get-ADOrganizationalUnit -Filter {DistinguishedName -eq $PrivilegedServiceAccountOUPath})){
    Write-Output "Service Account OU $PrivilegedServiceAccountOUPath not available"
    exit 0xA5
}
#endregion

#region Validate the group membership and authentication policy settings in the Tier 0 OU 
foreach ($user in Get-ADUser -SearchBase $PrivilegedOUPath -Filter * -Properties msDS-AssignedAuthNPolicy, memberOf){
	#validate the user is member of the Tier 0 users group
        if ($user.memberOf -notcontains $Tier0UsersGroup.DistinguishedName){
		    Add-ADGroupMember $Tier0UserGroupName $user
        }
	#validate the Kerberos Authentication policy is assigned to the user
	if ($user.'msDS-AssignedAuthNPolicy' -ne $KerberosAuthenticationPolicy.DistinguishedName){
        Set-ADUser $user -AuthenticationPolicy $KerberosPolicyName}
}
foreach ($user in Get-ADUser -SearchBase $PrivilegedServiceAccountOUPath -Filter * -Properties memberOf){
    if ($user.memberOf -notcontains $Tier0UsersGroup.DistinguishedName){
        Add-GroupMember $Tier0UserGroupName $user
    }
}
#endregion

#region validate Critical Group Membership
#Well-known critical domain group relative domain sid
$PrivlegeDomainSid = @(
    "512", #Domain Admins
    "518", #Schema Admins
    "519", #"Enterprise Admins"
    "520", #Group Policy Creator Owner
    "522" #Cloneable Domain Controllers
#    "527" #Enterprise Key Admins
    
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
