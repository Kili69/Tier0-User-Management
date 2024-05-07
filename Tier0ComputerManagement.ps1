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
	.\Tier0ComputerManagement.ps1 -Tier0ComputerGroupName "Tier 0 Computers" -Tier0ComputerOU "OU=Tier 0,OU=Admin"
        The script will search for any computer in the OU=Tier 0,OU=Admin and subfolder on any domain in the forest 
    .\Tier0ComputerManagement.ps1 -Tier0ComputerGroupName "Tier 0 Computers" -Tier0ComputerOU "OU=Tier 0,OU=Admin" -MulitDomainForest $False
        The script will search for any computer in the OU=Tier 0,OU=Admin and subfolder in the current domain
	.\Tier0ComputerManagement.ps1 -Tier0ComputerGroupName "Tier 0 Computers" -Tier0ComputerOU "OU=Tier 0,OU=Admin,DC=Contoso,DC=com"
        The script will search for any computer in the OU=Tier 0,OU=Admin and subfolder on any domain in the forest. The domain name in the Distiguishedname will be ignored
    .\Tier0ComputerManagement.ps1 -Tier0ComputerGroupName "Tier 0 Computers" -Tier0ComputerOU "OU=Tier 0,OU=Admin;OU=2ndOU"
        The script will search for any computer in OU=Tier 0,OU=Admin and OU=2ndOU in all domains in the forest
    
.PARAMETER Tier0ComputerGroupName
    Is the Tier 0 computer group Name
.PARAMETER Tier0ComputerOU
    Is the relative DistinguishedName of the Tier 0 computer OU path. If multiple Tier 0 OU path available, separate them with a ";"
.PARAMETER MulitDomainForest

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
    0.1.20231124
        The script support the WhafIf parameter
    1.0 Release Date 30. January 2024
    1.0.20240416
        Log file is created in the AppData\Local folder
        New function to write logfiles 
        
    
#>
[cmdletbinding(SupportsShouldProcess=$true)]
Param (
    [Parameter (Mandatory=$true, Position = 0)]
    #Name of the group who contains all Tier 0 computers
    [String]$Tier0ComputerGroupName,
    [Parameter(Mandatory=$true, Position = 1)]
    # DistinguishedName of the OU for Tier 0 computer
    [string]$Tier0ComputerOU,
    [Parameter (Mandatory=$false)]
    #Enable the multidomain mode
    [bool]$MulitDomainForest = $true
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

#######################################################
# Main Program starts here                            #
#######################################################

#script Version 
$ScriptVersion = "1.0.20240416"
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
Write-Log -Message "Tier 0 computer  management version $ScriptVersion" -Severity Information
Write-Log -Message $MyInvocation.Line -Severity Debug

#for compatibility reason the Domain component will be removed from the OU path
$aryTier0Computer = @()
Foreach ($T0OU in $Tier0ComputerOU.Split(";")){
    $aryTier0Computer += [regex]::Replace($T0OU,",DC=.+","")
}
#searching for the T0 computers group in all domains
try{
    $adoGroup = Get-ADObject -Filter {(SamaccountName -eq $Tier0ComputerGroupName) -and (Objectclass -eq "Group")} -Properties member
}
catch [Microsoft.ActiveDirectory.Management.ADServerDownException]{
    Write-Log "The AD web service is not available. The group $Tier0ComputerGroupName cannot be updates" -Severity Error
    Write-EventLog -LogName "Application" -source "Application" -EventId 0 -EntryType Error -Message "The AD web service is not available. The group $Tier0ComputerGorupName cannot be updates"
    exit 0x3E9
}
if ($null -eq $adoGroup){
    Write-Log "Tier 0 computer management: Can't find the group $Tier0ComputerGroupName in the current domain. Script aborted" -Severity Error
    Write-Eventlog -LogName "Application" -Source "Application" -EventId 1000 -EntryType Error -Category 1 -Message "Tier 0 computer management: Can't find the group $Tier0ComputerGroupName in the current domain. Script aborted"
    exit 0x3E8
}

#on mulit domain mode write all domains into the array otherwise us the current domain name
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
                Write-Log "Missing the Tier 0 computer OU $OU,$((Get-ADDomain -Server $domain).DistinguishedName)" -Severity Warning
                Write-EventLog -LogName "Application" -source "Application" -EventId 0 -EntryType Error -Message "Missing the Tier 0 computer OU $OU,$((Get-ADDomain -Server $domain).DistinguishedName)"
            } else{
                $T0computers = Get-ADObject -Filter {ObjectClass -eq "Computer"} -SearchBase "$OU,$((Get-ADDomain -Server $domain).DistinguishedName)" -Properties ObjectSid -SearchScope Subtree -Server $domain
                #validate the computer ain the Tier 0 OU are member of the tier 0 computers group
                Write-Log -Message "Found $($T0computers.Count) Tier 0 computers in $domain" -Severity Debug
                Foreach ($T0Computer in $T0computers){
                    if ($adoGroup.member -notcontains $T0Computer ){
                        $adoGroup.member += $T0Computer.DistinguishedName
                        $bGroupMemberchanged = $true
                        Write-Log "Added $T0computer to $adoGroup" -Severity Information
                        Write-EventLog -LogName "Application" -source "Application" -EventID 0 -EntryType information -Message "Added $T0Computer to $adoGroup"
                    }
                }
            }
        }
        catch [Microsoft.ActiveDirectory.Management.ADServerDownException]{
            Write-Log "The domain $domain WebService is down or not reachable" -Severity Error
            Write-EventLog -LogName "Application" -Source "Application" -EventID 0 -EntryType Warning -Message "The domain $domain WebService is down or not reachable"
        }
    }
}
try{
    if ($bGroupMemberchanged){
        Set-ADObject -Instance $adoGroup    
        Write-Log "Adding new computers to the Tier 0 computer group" -Severity Debug
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
            Write-Log "Unexpected computer object $member removed from $($adoGroup.DistinguishedName)" -Severity Warning
            Write-EventLog -LogName "Application" -source "Application" -EventID 0 -EntryType Warning -Message "Unexpected computer object $member removed from $($adoGroup.DistinguishedName)"
            $bGroupMemberchanged = $true
        }
    }
    if ($bGroupMemberchanged){
        $adoGroup.member = $updatedGroupMembers
        Set-ADObject -Instance $adoGroup
        Write-Log "Removing non-tier 0 computers from the Tier 0 computer group" -Severity Debug
    }
}
catch [Microsoft.ActiveDirectory.Management.ADServerDownException]{
    Write-Log "The AD web service is not available. The group $adogroup cannot be updates"
    Write-EventLog -LogName "Application" -source "Application" -EventId 0 -EntryType Error -Message "The AD web service is not available. The group $adogroup cannot be updates"
    exit 0x3E9
}
