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
    This script manage the Tier 0 computer OU 

.DESCRIPTION
    This script manage the Tier 0 computer group. It adds all computer ojects in the Tier 0 organizational unit to the Tier 0 computer group and remove any object from the 
    Tier 0 computer group, which is not located in the Tier 0 OU
.EXAMPLE
	.\Tier0ComputerManagement.ps1
.INPUTS
    -Tier0ComputerGroupName
        The SAM account name of the Tier 0 computers group
    -Tier0OU
        The relative name of the Tier 0 OU without the domain DN

.OUTPUTS
   none
.NOTES
    Version Tracking
    0.1.20230918
        Initial Version available on GitHub
    0.1.20231020
        Mulit-Domain Forest support.
            If the parameter $MulitDomainForest is enabled all computer objects from any domain in the forest will be added to the Tier 0 computer group
    
#>
[CmdletBinding()]
Param (
    #Sam account name of the Tier 0 computer group
    [Parameter (Mandatory=$false)]
    [String]
    $T0SamAccountName = "Tier 0 Computers",
    # OU Path for Tier 0 computer
    [Parameter(Mandatory=$false)]
    [string]
    $T0OU = "OU=Tier 0 - Computers,OU=Admin",
    [Parameter (Mandatory=$false)]
    [bool]
    $MulitDomainForest = $true
)

#for compatibility reason the Domain component will be removed from the OU path
$T0OU = [regex]::Replace($T0OU,",DC=.+","")
#searching for the T0 computers group
$adoGroup = Get-ADObject -Filter {(SamaccountName -eq $T0SamAccountName) -and (Objectclass -eq "Group")} -Properties member
if ($null -eq $adoGroup){
    Write-Host "can't find a group $T0SamAccountName "
    break
}

if ($MulitDomainForest -eq $false){
    $domains = (Get-ADDomain).DNSRoot
} else {
    $domains = (Get-ADForest).Domains
}

Foreach ($domain in $domains){
    #validate the Tier 0 OU path
    if ($null -eq (Get-ADObject "$T0OU,$((Get-ADDomain -Server $domain).DistinguishedName)" -Server $domain)){
        Write-Host "can't find the Tier 0 OU $T0Ou"
        break
    }
    $T0computers = Get-ADComputer -Filter * -SearchBase "$T0OU,$((Get-ADDomain -Server $domain).DistinguishedName)" -Server $domain
    #$T0computers  = Get-ADObject -Filter {ObjectClass -eq "Computer"} -SearchBase "$T0OU,$((Get-ADDomain -Server $domain).DistinguishedName)" -Properties ObjectSid -SearchScope Subtree -Server $domain
    #validate the computer ain the Tier 0 OU are member of the tier 0 computers group
    Foreach ($T0Computer in $T0computers){
        if ($adoGroup.member -notcontains $T0Computer ){
            Add-ADGroupMember -Identity $adoGroup -Members $T0Computer
        }
    }
}
#remove any object from Tier 0 computer group who is not member of the tier 0 computers list
Foreach ($member in (Get-ADGroupMember $T0SamAccountName)){
    if ($member.DistinguishedName -notlike "*$T0OU*"){
        Remove-ADGroupMember -Identity $T0SamAccountName -Members $member -Confirm:$false
    }
}


