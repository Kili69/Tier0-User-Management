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
    -EnableMulitdomainSupport
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
        0x3EC   Forest domains are not found
        0x3ED   Missing Tier 1 computer OU path

    Version Tracking
    0.1.20231117
        Initial Version
    0.1.20231124
        The script support the WhatIf parameter
    1.0 Release Date 30. January 2024
    1.0.20240416
        Log files are available in the APPDATA\Local folder of the current user
        
#>
[cmdletbinding(SupportsShouldProcess=$true)]
Param (
    #Name of the group who contains all Tier 1 computers
    [Parameter (Mandatory=$false, Position = 0)]
    [String]$Tier1ComputerGroupName,

    # DistinguishedName of the OU for Tier 0 computer
    [Parameter(Mandatory=$false, Position = 1)]
    [string]$Tier1ComputerOU,

    # DistinguishedName of the OU for Tier 0 computer
    [Parameter(Mandatory=$false, Position = 2)]
    [string]$Tier0ComputerOU,

    #Enable the multidomain mode
    [switch]$EnableMulitDomainSupport,

    #add any computer object to the Tier1Computer group
    [switch]$AnyComputerType
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
$_ScriptVersion = "1.0.20240416"
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
Write-Log -Message "Tier 1 member management version $scriptVersion" -Severity Information
Write-Log -Message $MyInvocation.Line -Severity Debug
#region Parameter validation

#check the AD Module is available. If the AD Module is missing exit the scirpt with error code 0x3E8
Write-Host "$($MyInvocation.ScriptName) Script Version $_ScriptVersion" -ForegroundColor Yellow
try {
    Import-Module ActiveDirectory    
}
catch {
    Write-Log "Missing Active Directory Module. Terminating script with error code 0x3E8" -Severity Error
    exit 0x3E8
}
if ($Tier0ComputerOU -eq ""){
    Write-Log -Message "Missing Tier 0 computer OU. Terminating script with error 0x3E9" -Severity Error
    exit 0x3E9
} else {
    #extracting domain from the DN if the full DN was applied
    $Tier0ComputerOU = [regex]::Match($Tier0ComputerOU,'(OU=[^,]+,)*OU=\w+').Value
}
#Validate the Tier 1 computer group exists in the current domain. If the Tier 1 computer group is missing exit the script with 0xEA
$Tier1ComputerGroup = Get-ADObject -Filter {SamAccountName -eq $Tier1ComputerGroupName} -Properties Member
if ($null -eq $Tier1ComputerGroup){
    Write-Log "The Tier 1 computer group with SAMACCOUNTNAME '$Tier1ComputerGroupName' could not be found. Terminating script with error 0xEA" -Severity Error 
    exit 0xEA
} 
#Depending on the MulitDomainForest switch, enumare all forest domains
$aryDomains = @()
try{
    If ($EnableMulitDomainSupport){
        $aryDomains += (Get-ADForest).Domains
    } else {
        $aryDomains += (Get-ADDomain).DNSRoot
    }
} 
catch{
    if ($MulitDomainForest){
        Write-Log "Failed to enumerate domain names in the current forest. Terminating script" -Severity Error  
    } else {
        Write-Log "Failed to enumerate the currten domain. Terminating script" -Severity Error
    }
    exit 0x3EC    
}
#Define the search string if only servers involved
if ($AnyComputerType){
    #serching for any kind of computers except domain controllers
    $strSearchComputer = "(PrimaryGroupID -ne 516)"
} else {
    #searching for any compupter who is not a domain controller and contains the string "sever" in the operating system attribute
    $strSearchComputer = "(PrimaryGroupID -ne 516) -and (OperatingSystem -like '*Server*')"
}
Write-Log -Message "Computer search string:$strSearchComputer" -Severity Debug


#If the script run in mulitple OU mode split the parameter and write each OU into a array
$aryTier1ComputerOU = @()
if ($Tier1ComputerOU -eq ""){
    #the parameter is empty
    Write-Log -Message "missing Tier 1 computer OU. Terminating script with 0x3ED" -Severity Error
    exit 0x3ED
} else {
    if ($Tier1ComputerOU.Contains(";")){
        $aryTier1ComputerOU += $Tier1ComputerOU.Split(";")
    }
    else {
        $aryTier1ComputerOU += $Tier1ComputerOU
    }
} 

$computertoAdd = @() #This array collects all computers object who should be added to the Tier1computer group. at the end of the script the group will be updated 
#Enumerate any Tier 1 computer in all domains
Foreach ($domain in $aryDomains){
    try{
        Foreach ($OU in $aryTier1ComputerOU){
            $AryTier1Computer = @()
            $strSearchBase = "$OU,$((Get-ADDomain -Server $domain).DistinguishedName)"
            if ($null -eq (Get-ADObject $strSearchBase -Server $domain)){
                Write-Log "Can not find find OU $strSeachBase on domain $domain" -Severity Warning
            } else {
                $aryTier1Computer += Get-ADComputer -Filter $strSearchComputer -SearchBase $strSearchBase -Server $domain| Where-Object {$_.DistinguishedName -notlike "*$Tier0ComputerOU*"}
            }
            foreach ($Computer in $AryTier1Computer){
                if ($Tier1ComputerGroup.member -notcontains $Computer.DistinguishedName){
                    $computertoAdd += $Computer.DistinguishedName
                }
            }    
        }
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]{
        Write-Log "Couln'd find $strSearchBase in $domain" -Severity Warning
    }
    catch [Microsoft.ActiveDirectory.Management.ADServerDownException]{
        Write-Log "Can not connect to $Domain. Domain not reachable" -Severity Error
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
