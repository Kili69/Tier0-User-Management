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
    Automated installation of Tier 0 Active Directory isolation 

.DESCRIPTION
    This script copies the requried scripts to the AD forest root SYSVOL and applies a group policy 
    to the forest root domain controller to run the Tier 0 user management script automated

.EXAMPLE
    .\Install-T0.ps1    
.PARAMETER GMSAName
    Name of the Group Managed Service Account in a multi domain forest. Default value: T0usermgmt
.PARAMETER Tier0OU
    OU Name of the organizational unit for Tier 0 in every domain of the forest. Default value: OU=Tier 0,OU=Admin
.PARAMETER ComputerOUName
    OU name of the Tier 0 computer OU. Default value:Computers
.PARAMETER UserOUName
    OU name of Tier 0 users. Default value:Users
.PARAMETER ServiceAccountOUName
    OU name for Tier 0 service accounts. Default value: service accounts
.PARAMETER GroupOUName
    OU name of Tier 0 groups
.PARAMETER ComputerGroupName
    name of the AD group who contains the Tier 0 computers. Default value: Tier 0 computers
.PARAMETER UserGroupName
    Name of the AD group who contains any Tier 0 user. Default value: Tier 0 users
.PARAMETER KerberosAuthenticationPolicy
    Name of the Tier 0 isolation Kerberos Authenticatin Policy. Default value: Tier 0 Isolation
.PARAMETER SingleDomain
    Use this switch, if you want to install the solution only in one domain in a mulit domain forest
.OUTPUTS
   none
.NOTES
    Version Tracking
    0.1.20231221
        Initial Version
    0.1.20231223
        Enable claim support in the entrie forest while enabling KDC support in the Default Domain Controller Policy
        Enable claim support for clients in the Default Domain Policy
    0.1.20240108
        Catching errors if the default domain controller or default domain policy could not be updated
        General Error while creatig a GMSA will be catched
    0.1.20240110
        Remove bug in group policy settings
        Remove bug in Schedule Task
    0.1.20240111
        Schedule task to change the Tier 0 user Management into a GMSA changed
#>
[CmdletBinding (SupportsShouldProcess)]
param(
    [Parameter (Mandatory = $false)]
    [string]$GMSAName,
    [Parameter (Mandatory = $false)]
    [string]$Tier0OU,
    [Parameter (Mandatory = $false)]
    [string]$ComputerOUName,
    [Parameter (Mandatory = $false)]
    [string]$UserOUName,
    [Parameter (Mandatory = $false)]
    [string]$ServiceAccountOUName,
    [Parameter (Mandatory =$false)]
    [string]$GroupOUName,
    [Parameter(Mandatory = $false)]
    [string]$ComputerGroupName,
    [Parameter (Mandatory = $false)]
    [string]$UserGroupName,
    [Parameter (Mandatory = $false)]
    [string]$KerberosAuthenticationPolicy,
    [switch]$SingleDomain
)
#region functions
<# Function create the entire OU path of the relative distinuished name without the domain component. This function
is required to provide the same OU structure in the entrie forest
.SYNOPSIS 
    Create OU path in the current $DomainDNS
.DESCRIPTION
    create OU and sub OU to build the entire OU path. As an example on a DN like OU=Computers,OU=Tier 0,OU=Admin in
    contoso. The funtion create in the 1st round the OU=Admin if requried, in the 2nd round the OU=Tier 0,OU=Admin
    and so on till the entrie path is created
.PARAMETER OUPath 
    the relative OU path withou domain component
.PARAMETER DomainDNS
    Domain DNS Name
.EXAMPLE
    CreateOU -OUPath "OU=Test,OU=Demo" -DomainDNS "contoso.com"
.OUTPUTS
    $True
        if the OUs are sucessfully create
    $False
        If at least one OU cannot created. It the user has not the required rights, the function will also return $false 
        #>
function CreateOU {
    [CmdletBinding ( SupportsShouldProcess)]
    param (
        [Parameter(Mandatory)]
        [string]$OUPath,
        [Parameter (Mandatory)]
        [string]$DomainDNS
    )
    try{
        #load the OU path into array to create the entire path step by step
        $DomainDN = (Get-ADDomain -Server $DomainDNS).DistinguishedName
        $aryOU=$OUPath.Split(",")
        $BuildOUPath = ""
        #walk through the entire domain 
        For ($i= $aryOU.Count; $i -ne 0; $i--){
            #to create the Organizational unit the string OU= must be removed to the native name
            $OUName = $aryOU[$i-1].Replace("OU=","")
            #if this is the first run of the for loop the OU must in the root. The searbase paramenter is not required 
            if ($i -eq $aryOU.Count){
                #create the OU if it doesn|t exists in the domain root. 
                if([bool](Get-ADOrganizationalUnit -Filter "Name -eq '$OUName'" -SearchScope OneLevel -server $DomainDNS)){
                    Write-Debug "OU=$OUName,$DomainDN already exists no actions needed"
                } else {
                    Write-Host "$OUName doesn't exist in $OUPath. Creating OU" -ForegroundColor Green
                    New-ADOrganizationalUnit -Name $OUName -Server $DomainDNS                        
                }
            } else {
                #create the sub ou if required
                if([bool](Get-ADOrganizationalUnit -Filter "Name -eq '$OUName'" -SearchBase "$BuildOUPath$DomainDN" -Server $DomainDNS)){
                    Write-Debug "$OUName,$OUPath already exists no action needed" 
                } else {
                    Write-Host "$OUPath,$DomainDN doesn't exist. Creating" -ForegroundColor Green
                    New-ADOrganizationalUnit -Name $OUName -Path "$BuildOUPath$DomainDN" -Server $DomainDNS
                }
            }
            #extend the OU searchbase with the current OU
            $BuildOUPath  ="$($aryOU[$i-1]),$BuildOUPath"
        }
    } 
    catch [System.UnauthorizedAccessException]{
        Write-Host "Access denied to create $OUPath in $domainDNS"
        Return $false
    } 
    catch{
        Write-Host "A error occured while create OU Structure"
        Write-Host $Error[0].CategoryInfo.GetType()
        Return $false
    }
    Return $true
}

<#
.DESCRIPTION
    This funtion is called if a non critical error occurs and the user can decide to continue or terminate the script
.SYNOPSIS
    Terminat script if the user response with "n" or no
#>
function ContinueOnError {
    do {
        $UserInput = Read-Host "Continue(Yes/No)"
        if ($UserInput[0] -eq "n"){
            Exit
        }
    } while ($UserInput -ne "y")
}

<#
.DESCRIPTION 
    This function enable claim support on domain controllers via Default Domain Controller Policy and enable the claim support
    on clients
.SYNOPSIS
    Enable claim support in the entire domain
.PARAMETER DomainDNSName
    The domain DNS Name where the claim support will be enabled
.OUTPUTS
    None
#>
function EnableClaimSupport {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $DomainDNSName
    )
    $DefaultDomainControllerPolicy = "6AC1786C-016F-11D2-945F-00C04FB984F9"
    $DefaultDomainPolicy = "31B2F340-016D-11D2-945F-00C04FB984F9"
    try {
        #Enable Claim Support on Domain Controllers. 
        #Write this setting to the default domain controller policy 
        $KDCEnableClaim = @{
            GUID = $DefaultDomainControllerPolicy
            Key = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters"
            ValueName = "EnableCbacAndArmor"
            Value = 1
            Type = 'DWORD'
        } 
        Set-GPRegistryValue @KDCEnableClaim -Server (Get-ADDomain -Server $domainDNSName).PDCEmulator
        #Enable client claim support for domain controllers
        #Write this setting to the default domain controller Policy
        $ClientClaimSupport = @{
            GUID = $DefaultDomainControllerPolicy
            Key = "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"
            ValueName = "EnableCbacAndArmor"
            Value = 1
            Type = 'DWORD'
        }
        Set-GPRegistryValue @ClientClaimSupport -Server (Get-ADDomain -Server $domainDNSName).PDCEmulator
    }
    catch {
        Write-Host "Failed to update Default Domain Policy Policy in $DomainDNSName" -ForegroundColor Red
        Write-Host "Set Administrative Templates\KDC\Enable Combound authentication to supported" -ForegroundColor Yellow
        Write-Host "set Administrative Templates\Kerberos\Enabel client support to Enable"
    }
    #Enable client claim support on any clients
    #Write this setting to the default domain policy
    $ClientClaimSupport = @{
        GUID = $DefaultDomainPolicy
        Key = "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"
        ValueName = "EnableCbacAndArmor"
        Value = 1
        Type = 'DWORD'
    }
    try{
    Set-GPRegistryValue @ClientClaimSupport -Server (Get-ADDomain -Server $domainDNSName).PDCEmulator
    }
    catch {
        Write-Host "Failed to update Default Policy in $DomainDNSName" -ForegroundColor Red
        Write-Host "Enable Administrative Templates\Kerberos\Enable Claim support to enable" -ForegroundColor Yellow
    }
}
#endregion
#########################################################################################################
# Main program start here
#########################################################################################################

#This script requires the Active Director and Group Policy Powershell Module. The script terminal if one
#of the module is missing
try{
    Import-Module ActiveDirectory
    Import-Module GroupPolicy  
} 
catch {
    Write-Host "Failed to load the neede Powerhsell module" -ForegroundColor Red
    Write-Host "validate the Active Directory and Group Policy Powershell modules are installed"
    exit
}
#region constantes
#This region contains the default values and constantes 
$CurrentDomainDNS = (Get-ADDomain).DNSRoot
$CurrentDomainDN  = (Get-ADDomain).DistinguishedName
$aryDomains = (Get-ADForest).Domains

$DescriptionT0ComputerGroup = "This group contains any Tier 0 computer. It will be used for Tier 0 Kerberos Authentication policy"
$DescriptionT0Users         = "This group contains any Tier 0 user"
$KerberosAuthenticationPolicyDescription = "This Kerberos Authentication policy used to restrict interactive logon from untrusted computers"

$T0OUDefault = "OU=Tier 0,OU=Admin"
$T0ComputerOUDefault = "OU=Computers"
$T0UserDefaultOU = "OU=Users"
$T0ServiceAccountDefaultOU = "OU=Service Accounts"
$T0GroupDefaultOU= "OU=Groups"
$T0GroupDefault  = "Tier 0 computers"
$T0UserGroupDefault = "Tier 0 Users"
$TGTLifeTime = 240
$DefaultGMSAName = "T0UserMgmt"
$DefaultKerbAuthPolName = "Tier 0 Restrictions"
$GPOName = "Tier 0 User Management"
$RegExOUPattern = "(OU=*[^,]+)*,OU=[^,]+"
#endregion


#region Parameter validation
#If the parameters are not set while calling the script. Use the interactive mode to set the parameters

#A group managed service account is only required in a mulit domain forest. If the -singleDomain parameter is 
#set, the script will also run in the system context. I this scenario the Tier0UserManagement script will not 
#be able to remove unexpected users for privileged groups
if (!$SingleDomain -and ((Get-ADForest).Domains.count -gt 1)){
    if ($GMSAName -eq ""){ 
        do {
            $GMSAName = Read-Host "Group Managed Service Accountname ($DefaultGMSAName)"
            if ($GMSAName -eq ""){
                $GMSAName = $DefaultGMSAName
            } else {
                if ($GMSAName.Length -gt 20){
                    Write-Host "Group managed service account name exceed the maximum length of 20 characters"
                    $GMSAName = ""
                }
            }
        }while ($GMSAName -eq "")
    }
}
#Validate the base OU path. It should be similar like OU=Tier 1,OU=Admin
#If the parameter is not set, ask the user to enter a path or use the default value
while ($Tier0OU -eq ""){
    $Tier0OU = Read-Host "Tier 0 OU ($T0OUDefault)"
    if ($Tier0OU -eq ""){
        #the user pressed return the default value will be used
        $Tier0OU = $T0OUDefault
    } else {
        if (![regex]::Match($Tier0OU,$RegExOUPattern).Success){
                Write-Host "invalid OU Path"
                $Tier0OU = ""
        }
    }
}

#Validate the computer OU. This is the OU below the base OU. 
while ($ComputerOUName -eq ""){
    $Tier0ComputerOUName = Read-Host "Tier 0 Computer OU ($T0ComputerOUDefault)"
    if ($Tier0ComputerOUName -eq ""){
        #The user pressed return, the default value will be used
        $ComputerOUName = $T0ComputerOUDefault
    } else {
        if (![regex]::Match($Tier0ComputerOUName, $RegExOUPattern).Success){
            Write-Host "Invalid Tier 0 computer OU"
            $Tier0ComputerOUName = ""
        }
    }
}

#Validate the User OU. This is the OU below the base OU. 
while ($UserOUName -eq ""){
    $Tier0UserOU = Read-Host "Tier 0 User OU ($T0UserDefaultOU)"
    if ($Tier0UserOU -eq ""){
        $UserOUName = $T0UserDefaultOU
    } else {
        if (![regex]::Match($Tier0UserOU).Success){
            Write-Host "Invalid OU user path"
            $UserOUName = ""
        }
    }
}
#Validate the service account OU. This is the OU below the base OU. 

while ($ServiceAccountOUName -eq "") {
    $Tier0ServiceAccountOU = Read-Host "Service account OU Name ($T0ServiceAccountDefaultOU)"
    if ($Tier0ServiceAccountOU -eq ""){
        $ServiceAccountOUName = $T0ServiceAccountDefaultOU
    } else {
        if (![regex]::Match($Tier0ServiceAccountOU,$RegExOUPattern).Success){
            Write-Host "Invalid Service account OU"
            $ServiceAccountOUName = ""
        }
    }
}

#Validate the group OU name. This is the OU below the base OU. 
while ($GroupOUName -eq "") {
    $GroupOUName = Read-Host "Tier 0 Group OU name ($T0GroupDefaultOU)"
    if ($GroupOUName -eq ""){
        $GroupOUName = $T0GroupDefaultOU
    } else {
        if (![regex]::Match($GroupOUName,$RegExOUPattern).Success){
            Write-Host "Invalid Group OU Path"
            $GroupOUName = ""
        }
    }
    
}

#Validate the computer group OU name. This is the of the group who contains any Tier 0 computer 
while ($ComputerGroupName -eq ""){
    $Tier0ComputerGroupName = Read-Host "Tier 0 computer group ($T0GroupDefault)"
    if ($Tier0ComputerGroupName -eq ""){
        $ComputerGroupName = $T0GroupDefault
    }
}
while ($UserGroupName -eq ""){
    $Tier0UserGroupName = Read-Host "Tier 0 user group($T0UserGroupDefault)"
    if ($Tier0UserGroupName -eq ""){
        $UserGroupName = $T0UserGroupDefault
    }
}

#Validate the name of the Tier 0 Kerberos Authentication Policy name
while ($KerberosAuthenticationPolicy -eq ""){
    $KerberosAuthenticationPolicy = Read-Host "Kerberos Authentication Policy Name ($DefaultKerbAuthPolName)"
    if ($KerberosAuthenticationPolicy -eq ""){
        $KerberosAuthenticationPolicy = $DefaultKerbAuthPolName
    } 
}
#endregion

#region building the OU structure in every domain in the forest or in the local domain if the -singleDomain parameter is set
Write-Host "**************************************************************************************" -ForegroundColor Green
Write-Host "* Build OU structure                                                                 *" -ForegroundColor Green
Write-Host "**************************************************************************************" -ForegroundColor Green
Foreach ($domain in $aryDomains){
    Write-Host "Validate or create $ComputerOUName,$Tier0OU in $domain" -ForegroundColor Green
    if (!(CreateOU -OUPath "$ComputerOUName,$Tier0OU" -DomainDNS $domain)){
        Write-Host "A error has occured while creating $ComputerOUName,$Tier0OU in $domain"
        ContinueOnError
    } else {
        #only continue if the base OU exists
        Write-Host "Validate or create $UserOUName,$Tier0OU in $domain" -ForegroundColor Green
        if (!(CreateOU -OUPath "$UserOUName,$Tier0OU" -DomainDNS $domain)){
            Write-Host "A error has occured while creating $UserOUName,$Tier0OU in $domain" -ForegroundColor Red
            ContinueOnError
        }
        Write-Host "Validate or create $ServiceAccountOUName,$Tier0OU in $Domain" -ForegroundColor Green
        if (!(CreateOU -OUPath "$ServiceAccountOUName,$Tier0OU" -DomainDNS $domain)){
            Write-Host "A error has occured while creating $ServiceAccountOUName,$Tier0OU in $domain" -ForegroundColor Red
            ContinueOnError
        }
        Write-Host "Validate or create $GroupOUName,$Tier0OU in $domain" -ForegroundColor Green
        if(!(CreateOU -OUPath "$GroupOUName,$Tier0OU" -DomainDNS $domain)){
            Write-Host "A error has occured while creating $GroupOUName,$Tier0OU in $domain" -ForegroundColor Red
            ContinueOnError
        }
    }
    Write-Host "Enable Claim support"
    EnableClaimSupport -DomainDNSName $domain
}
#endregion
#region AD groups
Write-Host "**************************************************************************************" -ForegroundColor Green
Write-Host "* Creating groups                                                                    *" -ForegroundColor Green
Write-Host "**************************************************************************************" -ForegroundColor Green
Write-Host "Validating or create $ComputerGroupName in $CurrentDomainDNS" -ForegroundColor Green
$ComputerGroup = Get-ADGroup -Filter "Name -eq '$ComputerGroupName'" -Server $CurrentDomainDNS -ErrorAction SilentlyContinue
if ($null -eq $ComputerGroup){
    #The group could not be found and need to be created
    try {
        New-ADGroup -Name $ComputerGroupName -Description $DescriptionT0ComputerGroup -GroupScope DomainLocal -GroupCategory Security -Path "$GroupOUName,$Tier0OU,$CurrentDomainDN" -ErrorAction Stop -Server $CurrentDomainDNS
    } 
    catch [System.UnauthorizedAccessException]{
        Write-Host "You don't have the rights to create $ComputerGroupName in $Tier0UserGroupOU,$CurrentDomainDN (access denied)" -ForegroundColor Red
        ContinueOnError
    }
    catch {
        Write-Host "A unexpected error has occured while creating $ComputerGroupName in $Domain script aborted"
        Write-Host $Error[0].Exception.GetType()
        exit
    }
} else {
    #The computer group should be a domain local group.
    if ($ComputerGroup.GroupScope -ne "DomainLocal"){
        Write-Host "The group $($ComputerGroup.Name) group scope is not domain local." -ForegroundColor Yellow
        ContinueOnError
    }
    if ($ComputerGroup.DistinguishedName -notlike "*,$GroupOUName,$Tier0OU,DC=*"){
        #If the computer is not in the the group OU name terminate the script 
        Write-Host "The group $($ComputerGroup.DistinguishedName) is not in the expected OU ($($ComputerGroup.DistinguishedName))" -ForegroundColor Red
        Write-Host "Move the group to '$tier0GroupOU,$CurrentDomainDN' and rerun the script" -ForegroundColor Red
        exit
    }
}
Write-Host "Validating or create $UserGroupName in $CurrentDomainDNS" -ForegroundColor Green
$UserGroup = Get-ADGroup -Filter "Name -eq '$UserGroupName'"
if ($null -eq $UserGroup){
    try {
        New-ADGroup -Name $UserGroupName -Description $DescriptionT0Users -GroupScope DomainLocal -GroupCategory Security -Path "$GroupOUName,$Tier0OU,$CurrentDomainDN" -Server $CurrentDomainDNS
    }
    catch [System.UnauthorizedAccessException]{
        Write-Host "You don't have the rights to create $UserGroupName in "$GroupOUName,$Tier0OU,$CurrentDomainDN" (access denied)" -ForegroundColor Red
        ContinueOnError
    }
    catch [Microsoft.ActiveDirectory.Management.ADException]{
        Write-Host "A unexpeted error has occured while create $userGroupName in $Domain" -ForegroundColor Red
        Write-Host $Error[0].Exception.Message -ForegroundColor red
        ContinueOnError
    }
    catch {
        Write-Host "A unexpected error has occured while creating $UserGroupName in $Domain script aborted" -ForegroundColor red
        Write-Host $Error[0].Exception.GetType() -ForegroundColor Red
        ContinueOnError
    }

} else {
    if ($UserGroup.DistinguishedName -notlike "*$Tier0UserOU,DC=*"){
        Write-Host "The group $($UserGroup.DistinguishedName) is not in the expected OU $($Tier0UserOU,$CurrentDomainDN)" -ForegroundColor Red
        Write-Host "Move the group to $Tier0UserOU,$CurrentDomainDN and rerun the script" -ForegroundColor Red
    }
}

#endregion
#Region Create Kerberos Authentication Policy
try {
    if ([bool](Get-ADAuthenticationPolicy -Filter "Name -eq '$KerberosAuthenticationPolicy'")){
        Write-Debug "Kerberos Authentication Policy $KerberosAuthenticationPolicy already exists"
    } else {
        #create a Kerberos authentication policy, wher assinged users can logon to members of enterprise domain controllers
        #or member of the Tier 0 computers group
        $T0GroupSID = (Get-ADGroup -Identity $ComputerGroupName -Properties ObjectSid -Server (Get-ADForest).RootDomain).ObjectSid.Value 
        $AllowToAutenticateFromSDDL = "O:SYG:SYD:(XA;OICI;CR;;;WD;((Member_of {SID(ED)})         || (Member_of {SID($T0GroupSID)})))"
        New-ADAuthenticationPolicy -Name $KerberosAuthenticationPolicy -Enforce `
                                   -RollingNTLMSecret Required `
                                   -UserTGTLifetimeMins $TGTLifeTime `
                                   -Description $KerberosAuthenticationPolicyDescription `
                                   -UserAllowedToAuthenticateFrom $AllowToAutenticateFromSDDL `
                                   -ProtectedFromAccidentalDeletion $true                             
    }
}
catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]{
    Write-Host "Can't find group $($Error[0].CategoryInfo.TargetName). Script aborted" -ForegroundColor Red 
    Write-Host "script aborted" -ForegroundColor Red
    exit
}
catch [System.UnauthorizedAccessException]{
    Write-Host "Enterprise Administrator Privileges required to create Kerberos Authentication Policy" -ForegroundColor Red
    Write-Host $($Error[0].Exception.Message) -ForegroundColor Red
    Write-Host "script aborted " -ForegroundColor Red
    exit
}
#endregion
#Region GMSA
if ($SingleDomain -or ((Get-ADForest).Domains.count -gt 1)){
    $NoGMSA = $false
    try {
        if (![bool](Get-KdsRootKey)){
            Write-Host "KDS Rootkey is missing." -ForegroundColor Red
            Write-Host "Creating KDS-Rootkey" -ForegroundColor Yellow
            Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10))
        }
        if (![bool](Get-ADServiceAccount -Filter "Name -eq '$GMSAName'")){
            $aryDCDN = @()
            foreach ($DC in (Get-ADDomainController -Filter *)){
                $aryDCDN += $DC.ComputerObjectDN
            }
            New-ADServiceAccount -Name $GMSAName -DNSHostName "$GmsaName.$((Get-ADDomain).DNSRoot)" -KerberosEncryptionType AES256 -PrincipalsAllowedToRetrieveManagedPassword $aryDCDN
        }
        $oEnterpriseAdmins = Get-ADGroup -Identity "$((Get-ADDomain).DomainSid)-519" -Properties Members
        $oGMSA = Get-ADServiceAccount -Identity $GMSAName -Properties Memberof
        if ($oEnterpriseAdmins.Members -notcontains $oGMSA.DistinguishedName){
            Add-ADGroupMember $oEnterpriseAdmins -Members $oGMSA
        }
    }
    catch [Microsoft.ActiveDirectory.Management.ADServerDownException]{
        Write-Host "Unable to access the Active Directory Web Service while creating the Group Managed Service Account" -ForegroundColor Red
        ContinueOnError
    }
    catch [Microsoft.ActiveDirectory.Management.ADException] {
        Write-Host "Access denied error occurs while creating a group managed service account. Validate you have the correct privileges" -ForegroundColor Red
        ContinueOnError
    }
    catch{
        Write-Host "a unexpected error has occured while creating the group managed service account" -ForegroundColor Red
        Write-Host $Error[0] -ForegroundColor Red
        Write-Host "create a GMSA manually and assing the GMSA to the Enterprise Admins" -ForegroundColor Yellow
    }
} else {
    $NoGMSA = $true
}
#endregion
#copy script files to SYSVOL\<DOMAIN>\scripts folder. While the script run high privileged, take care the folder is only writeable to Tier 0 users
try {
    $ScriptTarget = "\\$CurrentDomainDNS\SYSVOL\$CurrentDomainDNS\scripts"
    Copy-Item .\Tier0ComputerManagement.ps1 $ScriptTarget -ErrorAction Stop
    Copy-Item .\Tier0UserManagement.ps1 $ScriptTarget -ErrorAction Stop
} catch {
    Write-Host "A unexpected error has occured while copy the PowerShell script to $ScriptTarget" -ForegroundColor Red
    ContinueOnError
}

#region group policy
#read the schedule task template from the current directory
[string]$ScheduleTaskRaw = Get-Content ".\ScheduledTasksTemplate.xml" -ErrorAction SilentlyContinue
if ($null -eq $ScheduleTaskRaw ){
    Write-Host "Missing .\ScheduleTaskTemplate.xml file. Configuration of the schedule tasks terminated" -ForegroundColor Red
    exit
}
#Create new Group Policy if required
$oGPO = Get-GPO -Name $GPOName -ErrorAction SilentlyContinue
if ($null -eq $oGPO){
    $oGPO = New-gpo -Name $GPOName -Comment "Tier Level enforcement group policy. " -ErrorAction SilentlyContinue
}
#$oGPO = Get-GPO -Name $GPOName -ErrorAction SilentlyContinue
if ($null -eq $oGPO ){
    $GPPath = ".\ScheduledTasks.xml"
    Write-Host "A group policy for Tier 0 user management could not be created" -ForegroundColor Red
    Write-Host "=> Create a group policy" -ForegroundColor Yellow
    Write-Host "copy the file .\ScheduledTasks.xml to \\$CurrentDomainDNS\SYSVOL\$CurrentDomainDNS\Policies\<GroupPolicyGUID>\Machine\Preferences\ScheduledTasks" -ForegroundColor Yellow
} else {
    $GPPath = "\\$((Get-ADDomain).DNSRoot)\SYSVOL\$((Get-ADDomain).DNSRoot)\Policies\{$($oGPO.ID)}\Machine\Preferences\ScheduledTasks"
    if (!(Test-Path "$GPPath")){
        New-Item -ItemType Directory $GPPath | Out-Null
    }
#    $GPPath += "\Preferences\ScheduledTasks"
#    if (!(Test-Path $GPPath)){
#        New-Item -ItemType Directory "$GPPath\ScheduledTasks" | Out-Null
#    }
    $GPPath += "\ScheduledTasks.xml"
    $oGPO | New-GPLink -Target (Get-ADDomain).DomainControllersContainer -LinkEnabled No
    Write-Host "Tier 0 User Management Group Policy is linked to Domain Controllers OU but not activated" -ForegroundColor Yellow -BackgroundColor Blue
    Write-Host "Validate the group policy and enable" -ForegroundColor Yellow
}
if ($NoGMSA){
    $ScheduleTaskRaw = $ScheduleTaskRaw.Replace('$InstallTask', "")
} else {
    $UdpateGMSACommand = "`$principal = New-ScheduledTaskPrincipal -LogonType Password -UserId '$GmsaName`$';Set-ScheduledTask 'Tier 0 User Management' -Principal `$principal"
    $ScheduleTaskRaw = $ScheduleTaskRaw.Replace('$InstallTask', $UdpateGMSACommand)    
}
$ScheduleTaskRaw = $ScheduleTaskRaw.Replace('$DomainDNS', $CurrentDomainDNS)
$ScheduleTaskRaw = $ScheduleTaskRaw.Replace('$Tier0ComputerGroupName', "$ComputerGroupName")
$ScheduleTaskRaw = $ScheduleTaskRaw.Replace('$Tier0ComputerOU', "$ComputerOUName,$Tier0OU")
$ScheduleTaskRaw = $ScheduleTaskRaw.Replace('$DomainNetBIOS', ((Get-ADDomain).NetBIOSName))
$ScheduleTaskRaw = $ScheduleTaskRaw.Replace('$Tier0UserOUPath', "$UserOUName,$Tier0OU")
$ScheduleTaskRaw = $ScheduleTaskRaw.Replace('$Tier0ServiceAccountPath', "$ServiceAccountOUName,$Tier0OU")
$ScheduleTaskRaw = $ScheduleTaskRaw.Replace('$Tier0UserGroupName', "$UserGroupName")
$ScheduleTaskRaw = $ScheduleTaskRaw.Replace('$Tier0KerbAuthPol', $KerberosAuthenticationPolicy)
if ($NoGMSA){
    $ScheduleTaskRaw = $ScheduleTaskRaw.Replace('-EnableMulitDomainSupport', '')
}
[xml]$ScheduleTaskXML = $ScheduleTaskRaw
if ($NoGMSA){
    Foreach ($ChildNode in $ScheduleTaskXML.ScheduledTasks.TaskV2){
        if ($ChildNode.name -eq "Install Tier 0 User Management"){
            $ChildNode.ParentNode.RemoveChild($ChildNode) | Out-Null
        break
        }
    }
}
$ScheduleTaskXML.Save($GPPath)
#endregion        
