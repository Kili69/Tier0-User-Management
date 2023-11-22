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

    
.INPUTS
    -PolicyName
        The Name of the Kerberos Authentication Policy
    -Tier0ComputerGroup
        A group who contains any Tier 0 computer
    -TGTLifeTime
        The TGT lifetime in minutes
    -Tier2KerberosAuthenticationPolicy
        This switch indicate the Kerberos Authentication Policy will be created for Tier 1
    -Tier1ComputerGorup
        The name of the Tier 1 computers group

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
        $T1GroupSID = (Get-ADGroup -Identity $Tier1ComputerGroupName -Properties ObjectSid).ObjectSid.Value
        $AllowToAutenticateFromSDDL = "O:SYG:SYD:(XA;OICI;CR;;;WD;((Member_of {SID($T0GroupSID)})|| (Member_of {SID($T1GroupSID)})))"
    } else {
        $AllowToAutenticateFromSDDL = "O:SYG:SYD:(XA;OICI;CR;;;WD;((Member_of {SID(ED)})         || (Member_of {SID($T0GroupSID)})))"
    }
    
    New-ADAuthenticationPolicy -Name $PolicyName -Enforce -RollingNTLMSecret Required `
                                -UserTGTLifetimeMins $TGTLifeTime `
                                -Description $KerberosAuthenticationPolicyDescription `
                                -UserAllowedToAuthenticateFrom $AllowToAutenticateFromSDDL `
                                -UserAllowedToAuthenticateTo $AllowToAutenticateFromSDDL `
                                -ProtectedFromAccidentalDeletion $true

                               
}
catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]{
    Write-Host "Can't find group $($Error[0].CategoryInfo.TargetName). Script aborted" -ForegroundColor Red 
}
catch [System.UnauthorizedAccessException]{
    Write-Host "Enterprise Administrator Privileges required $($Error[0].Exception.Message)" -ForegroundColor Red
}
