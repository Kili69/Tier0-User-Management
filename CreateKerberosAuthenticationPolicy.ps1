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
.Synopsis
    This script creates a Tier 0 Kerberos Authentication Policy for Tier 0 isolation

.DESCRIPTION
    This script creates a Tier 0 Kerberos Authentication Policy for Tier 0 isolation ...

.EXAMPLE

.PARAMETER PolicyName
    Name of the Kerberos Authentication Policy. This parameter is mandatory
.PARAMETER Tier0ComputerGroup
    Name of the Tier 0 computer group. This parameter is mandatory
.PARAMETER TGTLifeTime
    The Kerberos TGT lifetime for accounts protected by this Kerberos Authentication Policy. Default value is 240 minutes
.PARAMETER Tier1KerberosAuthenticationPolicy
    This switch is use to create a Kerberos Authentication Policy for Tier 1. 
.PARAMETER Tier1ComputerGroupName
    This parameter will be used with the Tier1KerberosAuthenticationPolicy switch. It is the name of the Tier 1 computer group
.PARAMETER KerberosAuthenticationPolicyDescription
    This optional parameter adds a description to the Kerberos Authentication policy

.OUTPUTS
   none
.NOTES
    Version Tracking
    0.1.20231117
        Initial Version
    0.1.20231121
        PolicyName and Tier0COmputerGroup parameters are mandatory
    0.1.20231122
        Change the Kerberos Authentication Policy to allow Tier 1 accounts to logon to Tier 0 computers
    0.1.20240119
        Rolling NTLM hases is deprecated and will not be enabled anymore
    0.1.20240124
        Claim for Tier 0 / Tier 1 groups changed from Member_of_each to Member_of_any
        If the Tier1computerGroupName paramter is missing, the user will be asked interactive
    1.0 1.0 Release Date 30. January 2024
    1.0.20240404
        remove service ACL, because it is not functional as expected 
#>
[CmdletBinding()]
Param (
    [Parameter (Mandatory=$true, Position = 0)]
    #Name of the Kerberos Authentication Policy
    [String]$PolicyName,
    [Parameter(Mandatory=$true, Position = 1)]
    # The name of the AD group who contains any Tier 0 member server
    [string]$Tier0ComputerGroup,
    [Parameter(Mandatory=$false, Position = 2)]
    # Life time of the Kerberos TGT
    [string]$TGTLifeTime = 240,
    #Use this switch if this is a Tier 1 Kerberos Authentication Policy
    [switch]$Tier1KerberosAuthenticationPolicy,
    [Parameter(mandatory=$false)]
    [string]$Tier1ComputerGroupName,
    [Parameter(mandatory=$false)]
    [string] $KerberosAuthenticationPolicyDescription = 'This Kerberos Authentication policy used to restrict interactive logon from untrusted computers'
)

try {
    $T0GroupSID = (Get-ADGroup -Identity $Tier0ComputerGroup -Properties ObjectSid).ObjectSid.Value
    if ($Tier1KerberosAuthenticationPolicy){
        #While the paramter $Tier1ComputerGroupName is not mandatroy, the user will be asked interactive
        while ($Tier1ComputerGroupName -eq ""){
            $Tier1ComputerGroupName = Read-Host "Name of the Tier 1 computers group"
        }
        $T1GroupSID = (Get-ADGroup -Identity $Tier1ComputerGroupName -Properties ObjectSid).ObjectSid.Value
        #Claim changed from Member of each to Member of any
        $AllowToAutenticateFromSDDL = "O:SYG:SYD:(XA;OICI;CR;;;WD;((Member_of_any {SID($T0GroupSID)})|| (Member_of_any {SID($T1GroupSID)})))"
    } else {
        $AllowToAutenticateFromSDDL = "O:SYG:SYD:(XA;OICI;CR;;;WD;((Member_of {SID(ED)})         || (Member_of_any {SID($T0GroupSID)})))"
    }
    Write-Host $AllowToAutenticateFromSDDL
    New-ADAuthenticationPolicy -Name $PolicyName -Enforce `
                                -UserTGTLifetimeMins $TGTLifeTime `
                                -Description $KerberosAuthenticationPolicyDescription `
                                -UserAllowedToAuthenticateFrom $AllowToAutenticateFromSDDL `
                                -ProtectedFromAccidentalDeletion $true

                               
}
catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]{
    Write-Host "Can't find group $($Error[0].CategoryInfo.TargetName). Script aborted" -ForegroundColor Red 
}
catch [System.UnauthorizedAccessException]{
    Write-Host "Enterprise Administrator Privileges required $($Error[0].Exception.Message)" -ForegroundColor Red
}
