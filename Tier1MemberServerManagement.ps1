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
    This script add all member server into on a group. This group can be used as claim on Tier 1 Kerberos Authentication Polices

.DESCRIPTION
    This script add all tier 1 computer object into a AD domain local group. This group can be used as a claim for Tier 1 Kerberos Authentication Polices

.EXAMPLE
	.\Tier0ComputerManagement.ps1 -Tier0ComputerGroupName "Tier0Server" -Tier0ComputerGroupName "OU=Tier 0,OU=Admin"
        The script will search for any computer in the OU=Tier 0,OU=Admin and subfolder on any domain in the forest 
    .\Tier0ComputerManagement.ps1 -Tier0ComputerGroupName "Tier0Server" -Tier0ComputerGroupName "OU=Tier 0,OU=Admin" -MulitDomainForest $False
        The script will search for any computer in the OU=Tier 0,OU=Admin and subfolder in the current domain
	.\Tier0ComputerManagement.ps1 -Tier0ComputerGroupName "Tier0Server" -Tier0ComputerGroupName "OU=Tier 0,OU=Admin,DC=Contoso,DC=com"
        The script will search for any computer in the OU=Tier 0,OU=Admin and subfolder on any domain in the forest. The domain name in the Distiguishedname will be ignored
    .\Tier0ComputerManagement.ps1 -Tier0ComputerGroupName "Tier0Server" -Tier0ComputerGroupName "OU=Tier 0,OU=Admin;OU=2ndOU"
        The script will search for any computer in OU=Tier 0,OU=Admin and OU=2ndOU in all domains in the forest
    
.INPUTS
    -Tier1ComputerGroupName
        The SAM account name of the Tier 1 computers group
    -Tier0COmputerOU
        The relative name of the Tier 0 OU without the domain DN
    -Tier1OU
        The realtive name of the Tier 1 computer OU. This parameter allows multiple domains separated with a ;
    -MulitdomainSupport
        If the switch is available, the script will add Tier 1 computer object from any domain to the Tier1ComputerGroup
    -AnyComputerType
        if this switch is available, the script will only add computer objects to the T1ComputerGroup if the OperatingSystem Attribute contains the string "server"

.OUTPUTS
   none
.NOTES
    Exist codes
        0x3E8   Missing Active Directory Powershell Module
        0x3E9   Tier1computerOU and Tier0ComputerOU not defined
        0x3EA   Tier 1 computer group missing
        0x3EB   Tier 1 computer group cannot be updated (Typical access denied)

    Version Tracking
    0.1.20231117
        Initial Version
#>
[CmdletBinding()]
Param (
    [Parameter (Mandatory=$true, Position = 0)]
    #Name of the group who contains all Tier 0 computers
    [String]$Tier1ComputerGroupName,
    [Parameter(Mandatory=$false, Position = 1)]
    # DistinguishedName of the OU for Tier 0 computer
    [string]$Tier1ComputerOU,
    [Parameter(Mandatory=$false, Position = 2)]
    # DistinguishedName of the OU for Tier 0 computer
    [string]$Tier0ComputerOU,
    #Enable the multidomain mode
    [switch]$MulitDomainForest,
    #add any computer object to the Tier1Computer group
    [switch]$AnyComputerType
)

#script Version 
$_ScriptVersion = "0.1.20231117"
#region Parameter validation
#check the AD Module is available. If the AD Module is missing exit the scirpt with error code 0x3E8
Write-Host "$($MyInvocation.ScriptName) Script Version $_ScriptVersion" -ForegroundColor Yellow
try {
    Import-Module ActiveDirectory    
}
catch {
    Write-Host "Missing Active Directory Module" -ForegroundColor Red
    exit 0x3E8
}
#Validate the Tier 1 computer group exists. If the Tier 1 computer group is missing exit the script with 0xEA
$Tier1ComputerGroup = Get-ADObject -Filter {SamAccountName -eq $Tier1ComputerGroupName} -Properties Member
if ($null -eq $Tier1ComputerGroup){
    Write-Host "The Tier 1 computer group '$Tier1ComputerGroupName' could not be found" -ForegroundColor Red
    exit 0xEA
} 
#Depending on the MulitDomainForest switch, enumare all forest domains
$aryDomains = @()
If ($MulitDomainForest){
    $aryDomains += (Get-ADForest).Domains
} else {
    $aryDomains += (Get-ADDomain).DNSRoot
}
#Define the search string if only servers involved
if ($AnyComputerType){
    $strSearchComputer = "(PrimaryGroupID -ne 516)"
} else {
    $strSearchComputer = "(PrimaryGroupID -ne 516) -and (OperatingSystem -like '*Server*')"
}
#If the script run in mulitple OU mode split the parameter and write each OU into a array
$aryTier1ComputerOU = @()
if ($Tier1ComputerOU -eq ""){
    if ($Tier0ComputerOU -eq ""){
        Write-Host "If the Tier 0 computer OU is not defined, at the Tier 0 Computer OU must be defined" -ForegroundColor Red
        Write-Host " -Tier0ComputerOU OU=Tier0"
        exit 0x3E9
    } else {
    $aryTier1ComputerOU += ""
    }
} else {
    $aryTier1ComputerOU += $Tier1ComputerOU.Split(";")
}

$computertoAdd = @() #This array collects all computers object who should be added to the Tier1computer group. at the end of the script the group will be updated 
Foreach ($domain in $aryDomains){
    try{
    Foreach ($OU in $aryTier1ComputerOU){
        $AryTier1Computer = @()
        if ($OU -eq ""){ #if the $OU is a empty string computers from the entire domain will be added to the Tier 1 group
            $strSearchBase = "$((Get-ADDomain -Server $domain).DistinguishedName)"            
        } else {
            $strSearchBase = "$OU,$((Get-ADDomain -Server $domain).DistinguishedName)"
        }
        if ($null -eq (Get-ADObject $strSearchBase -Server $domain)){
            Write-Host "Can not find $strSeachBase" -ForegroundColor Yellow
        } else {
            if ($Tier0ComputerOU -eq ""){
                #Getting all computer objects except domain Controllers
                $AryTier1Computer += Get-ADcomputer -Filter $strSearchComputer -SearchBase $strSearchBase -Server $domain
            } else {
                #only search for computer objects who are not located in the Tier 0 computer OU
                $aryTier1Computer += Get-ADComputer -Filter $strSearchComputer -SearchBase $strSearchBase -Server $domain| Where-Object {$_.DistinguishedName -notlike "*$Tier0ComputerOU*"}
            }
            foreach ($Computer in $AryTier1Computer){
                if ($Tier1ComputerGroup.member -notcontains $Computer.DistinguishedName){
                    $computertoAdd += $Computer.DistinguishedName
                }
            }    
        }
    }
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]{
        Write-Host "Couln'd find $strSearchBase" -ForegroundColor Yellow
    }
    catch [Microsoft.ActiveDirectory.Management.ADServerDownException]{
        Write-Host "Can not connect to $Domain. Domain not reachable"
    }
}
try{
If ($computertoAdd.count -gt 0){
    $Tier1ComputerGroup.member += $computertoAdd
    Set-ADObject -Instance $Tier1ComputerGroup
}
}
catch [Microsoft.ActiveDirectory.Management.ADException]{
    Write-Host "Update $Tier1Computergroup failed"
    exit 0x3EB
}
