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
.PARAMETER ExcludeUser
        a list ob users who will not be removed from the privileged groups
.PARAMETER RemoveUserFromPrivilegedGroups
        if this paraemter is $false users will not be removed from privileged default groups
        if this parameter is $true (Default) users outside of the PrivilegedServiceAccountOUPath and not mentioned in the ExcludeUser
        will be removed from Administrators, Domain Admins, Backup Operators, Server managers, Account opertors
.PARAMETER EnableMulitDomainSupport
        the script wil manage all privileged users / groups in every domain of the forest. Take care the user has the required rights
        in the child domains

.OUTPUTS
   none
.EXAMPLE
    Tier0UserManagement.ps1 -PrivilegedOUPath "OU=Privileged Accounts,OU=Tier 0,OU=Admin" -KerberosPolicyName "Tier 0 Isolation" -PrivilegedServiceAcocuntOU "OU=service accounts,OU=Tier 0,OU=Admin"  -EnableMultiDomainSupport
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
    1.0.20231113
        enable MulitdomainSupport
    1.0.2023114
        Bugfix searching schemaadmins and Enterprise admins only in forest root domain
    1.0.20231324
        The script remove any kind of AD objects from the privilege groups even they are not a privileged SID, GMSA, service account or member of excludes users
    1.0.20231124
        The script catches now errors if a user ADIdentityNotFoundException if a userobject cannot read from the privileged OU
        The script support the WhatIf parameter
    1.0.20231205
        PrivilegedOUPath, PrivilegedServiceAcocuntOUPath and KerberosAuthenticationPolicyName are mandatory
        exit code 0x3E8 and 0x3E9 deprecated
    1.0 Release Date 30. January 2024
    1.0.20240211
        If the Kerberos Authentication Policy is applied to a user, the "Mark this user as sensitive and could not be delegated" flag
        Error Message update on insufficient privileges
    1.0.20240305
        Code formating
    1.0.20240306
        the exclude user parameter support multiple distinguishednames
    1.0.20240507
        The validateAndRemoveUser function now support groupnesting in the forest. 

#>
[cmdletbinding(SupportsShouldProcess=$true)]
param (
    #If this parameter is $true, users located not in the T0 Users OU automaticaly removed from privileged Groups, service account or a member of the exlude users
    [Parameter(Mandatory=$false)]
    [bool]$RemoveUserFromPrivilegedGroups=$true,
    #Is the OU Path for T0 Users
    [Parameter(Mandatory=$true)]
	[string]$PrivilegedOUPath,
    #Is the OU path for T0 user accounts
    [Parameter(Mandatory=$true)]
    [string]$PrivilegedServiceAccountOUPath,
	#Name of the Tier 0 users group
	[Parameter(Mandatory=$false)]
	[string]$Tier0UserGroupName,
    #Is the name of the KerberosAuthentication Policy
	[Parameter(Mandatory=$true)]
	[string]$KerberosPolicyName,
    #users of domain admins which should be disabled by the script
    [Parameter (Mandatory=$false)]
    [string]$ExcludeUser,
    #Enable mulitdomain support to add all tier 0 users into a single Kerberos Authenticatin Policy
    [Parameter(Mandatory=$false)]
    [switch]$EnableMulitDomainSupport

)


<#
.SYNOPSIS
    Remove unexpected user to the privileged group 
.DESCRIPTION 
    Searches for users in privileged groups and remove those user if the are not 
    - in the correct OU
    - the built-In Administrator
.PARAMETER SID
    - is the SID of the AD group
.PARAMETER DomainDNSName
    -is the domain DNS name of the AD object
.EXAMPLE
    validateAndRemoveUser -SID "S-1-5-<domain sid>-<group sid>" -DomainDNS contoso.com

#>
function validateAndRemoveUser{
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        #The SID uof the group
        [string] $SID,
        #The DNS domain Name
        [string] $DomainDNSName
    )
    $Group = Get-ADGroup -Identity $SID -Properties members,canonicalName -Server $DomainDNSName 
    #validate the SID exists
    if ($null -eq $Group){
        Write-Output "$SID not found"
        return
    }
    #walk through all members of the group and check this member is a valid user or group
    foreach ($Groupmember in $Group.members)
    {
        $member = Get-ADObject -Filter {DistinguishedName -eq $Groupmember} -Properties * -server "$($DomainDNSName):3268"
        switch ($member.ObjectClass){
            "user"{
                if (($member.ObjectSid.value   -notlike "*-500")                              -and ` #ignore if the member is Built-In Administrator
                    ($member.objectSid.value   -notlike "*-512")                              -and ` #ignoer if the member is Domain Admins group
                    ($member.ObjectSid.value   -notlike "*-518")                              -and ` #ignore if the member is Schema Admins
                    ($member.ObjectSid.Value   -notlike "*-519")                              -and ` #ignore if the member is Enterprise Admins
                    ($member.objectSid.Value   -notlike "*-520")                              -and ` #ignore if the member is Group Policy Creator
                    ($member.objectSid.Value   -notlike "*-522")                              -and ` #ignore if the member is cloneable domain controllers
                    ($member.objectSid.Value   -notlike "*-527")                              -and ` #ignore if the member is Enterprise Key Admins
                    ($member.objectClass       -ne "msDS-GroupManagedServiceAccount")         -and ` #ignore if the member is a GMSA
                    ($member.distinguishedName -notlike "*,$PrivilegedOUPath,*")              -and ` #ignore if the member is located in the Tier 0 user OU
                    ($member.distinguishedName -notlike "*,$PrivilegedServiceAccountOUPath*") -and ` #ignore if the member is located in the service account OU
                    ($excludeUser              -notlike "*$($member.DistinguishedName)*" )           #ignore if the member is in the exclude user list
                    ) {    
                        try{
                            Write-Output "remove $member from $($Group.DistinguishedName)"
                            Set-ADObject -Identity $Group -Remove @{member="$($member.DistinguishedName)"} -Server $DomainDNSName
                        }
                        catch [Microsoft.ActiveDirectory.Management.ADServerDownException]{
                            Write-Output "can't connect to AD-WebServices. $($member.DistinguishedName) is not remove from $($Group.DistinguishedName)"
                        }
                        catch [Microsoft.ActiveDirectory.Management.ADException]{
                            Write-Output "Cannot remove $($member.DistinguishedName) from $($Error[0].CategoryInfo.TargetName) $($Error[0].Exception.Message)"
                        }
                        catch{
                            Write-Output $Error[0].GetType().Name
                        }
                    }
                }
            "group"{
                $MemberDomainDN = [regex]::Match($member.DistinguishedName,"DC=.*").value
                $MemberDNSroot = (Get-ADObject -Filter "ncName -eq '$MemberDomainDN'" -SearchBase (Get-ADForest).Partitionscontainer -Properties dnsRoot).dnsRoot
                validateAndRemoveUser -SID $member.ObjectSid.Value -DomainDNSName $MemberDNSroot
                }
        }
    }        
}

#region main program
$ScriptVersion = "1.0.20240306"
Write-Output "Tier 0 user management version $scriptVersion"

#Validate the Kerboers Authentication policy exists. If not terminate the script with error code 0xA3. 
$KerberosAuthenticationPolicy = Get-ADAuthenticationPolicy -Filter {Name -eq $KerberosPolicyName}
if ($null -eq $KerberosAuthenticationPolicy){
    Write-Host "$KerberosPolicyName not found"
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
    #region Validate the group membership and authentication policy settings in the Tier 0 OU 
    try{
        #search for any user in the privileged OU
        foreach ($user in Get-ADUser -SearchBase "$PrivilegedOUPath,$((Get-ADDomain -Server $DomainName).DistinguishedName)" -Filter * -Properties msDS-AssignedAuthNPolicy, memberOf -SearchScope Subtree -Server $DomainName){
            <#region Tier0UserGroup
            #Tier 0 user group is deprecated. Adding users into a Tier 0 user group does not provide any security benefit
            #validate the user is member of the Tier 0 users group if not add them 
            if ($Tier0UserGroupName -ne ""){
                if ($user.memberOf -notcontains $Tier0UsersGroup.DistinguishedName){
                    Add-ADGroupMember $Tier0UserGroupName $user
                }
            }
            #>
            #validate the Kerberos Authentication policy is assigned to the user
            if ($user.'msDS-AssignedAuthNPolicy' -ne $KerberosAuthenticationPolicy.DistinguishedName){
                try {
                    Write-Output "Adding Kerberos Authentication Policy $KerberosPolicyName on $User"
                    Set-ADUser $user -AuthenticationPolicy $KerberosPolicyName -Server $DomainName
                    #if the Kerberos Authentication policy is assigned to a user, the user will be marked as "This user is sensitive and cannot be delegated"
                    #This attribute will only applied to the user, while adding the KerbAuthPol. If the attribute will be removed afterwards it will not be 
                    #reapplied
                    Set-ADAccountControl -Identity $user -AccountNotDelegated $True
                }
                catch {
                    Write-Output "The Kerberos Authenticatin Policy $KerberosPolicyName could not be added to $($user.DistinguishedName) $($Error[0])"
                }
            }
        }
    } 
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]{
        Write-Host "Can't get the users in $PrivilegedOUPath on $domain. ADIdentityNotFoundException"
    }
    #endregion

    #region validate Critical Group Membership
    #any user / group object who is not fulfill the criteria will be removed from the privileged groups
    #store any well-known critical domain group with relative domain sid in $PrivilegedDomainSID
    #groups like Backup Operators, Print Operators, Administrators have a well-known SID without domain SID 
    #Using the SID, provides language independency
    $PrivlegeDomainSid = @(
        "512", #Domain Admins
        "520", #Group Policy Creator Owner
        "522" #Cloneable Domain Controllers
    #   "527" #Enterprise Key Admins
    )
    if ($RemoveUserFromPrivilegedGroups){
        foreach ($relativeSid in $PrivlegeDomainSid) {
            validateAndRemoveUser -SID "$((Get-ADDomain -server $DomainName).DomainSID)-$RelativeSid" -DomainDNSName $DomainName
        }
        #Backup Operators
        validateAndRemoveUser -SID "S-1-5-32-551" -DomainDNSName $DomainName
        #Print Operators
        validateAndRemoveUser -SID "S-1-5-32-550" -DomainDNSName $DomainName
        #Server Operators
        validateAndRemoveUser -SID "S-1-5-32-549" -DomainDNSName $DomainName
        #Server Operators
        validateAndRemoveUser -SID "S-1-5-32-548" -DomainDNSName $DomainName
        #Administrators
        validateAndRemoveUser -SID "S-1-5-32-544" -DomainDNSName $DomainName
    }
#endregion
}
#Schema and Enterprise Admins only exists in Forest root domain
if ($RemoveUserFromPrivilegedGroups){
    $forestDNS = (Get-ADDomain).Forest
    $forestSID = (Get-ADDomain -Server $forestDNS).DomainSID.Value
    validateAndRemoveUser -SID "$forestSID-518" -DomainDNSName $forestDNS
    validateAndRemoveUser -SID "$forestSID-519" -DomainDNSName $forestDNS
}
#endregion