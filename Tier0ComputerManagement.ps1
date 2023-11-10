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
	.\Tier0ComputerManagement.ps1 -Tier0ComputerGroupName "Tier0Server" -Tier0ComputerGroupName "OU=Tier 0,OU=Admin"
        The script will search for any computer in the OU=Tier 0,OU=Admin and subfolder on any domain in the forest 
    .\Tier0ComputerManagement.ps1 -Tier0ComputerGroupName "Tier0Server" -Tier0ComputerGroupName "OU=Tier 0,OU=Admin" -MulitDomainForest $False
        The script will search for any computer in the OU=Tier 0,OU=Admin and subfolder in the current domain
	.\Tier0ComputerManagement.ps1 -Tier0ComputerGroupName "Tier0Server" -Tier0ComputerGroupName "OU=Tier 0,OU=Admin,DC=Contoso,DC=com"
        The script will search for any computer in the OU=Tier 0,OU=Admin and subfolder on any domain in the forest. The domain name in the Distiguishedname will be ignored
    .\Tier0ComputerManagement.ps1 -Tier0ComputerGroupName "Tier0Server" -Tier0ComputerGroupName "OU=Tier 0,OU=Admin;OU=2ndOU"
        The script will search for any computer in OU=Tier 0,OU=Admin and OU=2ndOU in all domains in the forest
    
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
    0.1.20231109
        Writes events to the Application event log
        Rename of the script parameters
        if the group is not accesible the script exist with the error code 0x3E8
    0.1.20231110
        The script support multiple OUs if they are separeated with a ";" in the $Tier0ComputerOU
        Excpetion handling if a webservice of a domain is down
        if the group cannot be updated, the script exit code is 0x3E9
    
#>
[CmdletBinding()]
Param (
    [Parameter (Mandatory=$true, Position = 0)]
    #Name of the group who contains all Tier 0 computers
    [String]$Tier0ComputerGroupName,
    [Parameter(Mandatory=$true, Position = 1)]
    # DistinguishedName of the OU for Tier 0 computer
    [string]$Tier0ComputerOU = "OU=Tier 0 - Computers,OU=Admin",
    [Parameter (Mandatory=$false)]
    #Enable the multidomain mode
    [bool]$MulitDomainForest = $true
)

#for compatibility reason the Domain component will be removed from the OU path
$aryTier0Computer = @()
Foreach ($T0OU in $Tier0ComputerOU.Split(";")){
    $aryTier0Computer += [regex]::Replace($T0OU,",DC=x.+","")
}
#searching for the T0 computers group in all domains
try{
    $adoGroup = Get-ADObject -Filter {(SamaccountName -eq $Tier0ComputerGroupName) -and (Objectclass -eq "Group")} -Properties member
}
catch [Microsoft.ActiveDirectory.Management.ADServerDownException]{
    Write-Host "The AD web service is not available. The group $Tier0ComputerGroupName cannot be updates"
    Write-EventLog -LogName "Application" -source "Application" -EventId 0 -EntryType Error -Message "The AD web service is not available. The group $Tier0ComputerGorupName cannot be updates"
    exit 0x3E9
}
if ($null -eq $adoGroup){
    Write-Host "Tier 0 computer management: Can't find the group $Tier0ComputerGroupName in the current domain. Script aborted" -ForegroundColor Red
    Write-Eventlog -LogName "Application" -Source "Application" -EventId 1000 -EntryType Error -Category 1 -Message "Tier 0 computer management: Can't find the group $Tier0ComputerGroupName in the current domain. Script aborted"
    exit 0x3E8
}


if ($MulitDomainForest -eq $false){
    $domains = (Get-ADDomain).DNSRoot
} else {
    $domains = (Get-ADForest).Domains
}
$bGroupMemberchanged = $false
Foreach ($OU in $aryTier0Computer){
    Foreach ($domain in $domains){
        #validate the Tier 0 OU path
        try {
            if ($null -eq (Get-ADObject "$OU,$((Get-ADDomain -Server $domain).DistinguishedName)" -Server $domain)){
                Write-Host "Missing the Tier 0 computer OU $OU,$((Get-ADDomain -Server $domain).DistinguishedName)" -ForegroundColor Red
                Write-EventLog -LogName "Application" -source "Application" -EventId 0 -EntryType Error -Message "Missing the Tier 0 computer OU $OU,$((Get-ADDomain -Server $domain).DistinguishedName)"
            } else{
                $T0computers = Get-ADObject -Filter {ObjectClass -eq "Computer"} -SearchBase "$OU,$((Get-ADDomain -Server $domain).DistinguishedName)" -Properties ObjectSid -SearchScope Subtree -Server $domain
                #validate the computer ain the Tier 0 OU are member of the tier 0 computers group
                Foreach ($T0Computer in $T0computers){
                    if ($adoGroup.member -notcontains $T0Computer ){
                        $adoGroup.member += $T0Computer.DistinguishedName
                        $bGroupMemberchanged = $true
                        Write-Host "Added $T0computer to $adoGroup" -ForegroundColor Yellow
                        Write-EventLog -LogName "Application" -source "Application" -EventID 0 -EntryType information -Message "Added $T0Computer to $adoGroup"
                    }
                }
            }
        }
        catch [Microsoft.ActiveDirectory.Management.ADServerDownException]{
            Write-Warning "The domain $domain WebService is down or not reachable"
            Write-EventLog -LogName "Application" -Source "Application" -EventID 0 -EntryType Warning -Message "The domain $domain WebService is down or not reachable"
        }
    }
}
try{
    if ($bGroupMemberchanged){
        Set-ADObject -Instance $adoGroup    
        $bGroupMemberchanged = $false
    }
    #remove any object from Tier 0 computer group who is not member of the tier 0 computers list
    $updatedGroupMembers = @()
    Foreach ($member in ($adoGroup.member)){
        $isMember = $false
        foreach ($ComputerOU in $aryTier0Computer){
            if ($member -like "*$ComputerOU*"){
                $isMember = $true
                break
            }
        }
        if ($isMember){
            $updatedGroupMembers += $member
        } else {
            Write-Host "Unexpected computer object $member removed from $($adoGroup.DistinguishedName)" -ForegroundColor Yellow
            Write-EventLog -LogName "Application" -source "Application" -EventID 0 -EntryType Warning -Message "Unexpected computer object $member removed from $($adoGroup.DistinguishedName)"
            $bGroupMemberchanged = $true
        }
    }
    if ($bGroupMemberchanged){
        $adoGroup.member = $updatedGroupMembers
        Set-ADObject -Instance $adoGroup
    }
}
catch [Microsoft.ActiveDirectory.Management.ADServerDownException]{
    Write-Host "The AD web service is not available. The group $adogroup cannot be updates"
    Write-EventLog -LogName "Application" -source "Application" -EventId 0 -EntryType Error -Message "The AD web service is not available. The group $adogroup cannot be updates"
    exit 0x3E9
}
