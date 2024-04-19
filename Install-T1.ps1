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
.OUTPUTS 
    None

#>
[CmdletBinding (SupportsShouldProcess)]
param(
    [Parameter (Mandatory = $false)]
    [string]$GMSAName,
    [Parameter (Mandatory = $false)]
    [string]$Tier1UserOU,
    [Parameter (Mandatory = $false)]
    [string]$Tier1ComputerOU,
    [Parameter (Mandatory = $false)]
    [string]$Tier1ComputerGroupName,
    [Parameter (Mandatory = $false)]
    [string]$Tier0ComputerOU,
    [Parameter (Mandatory = $false)]
    [string]$ServiceAccountOUName,
    [Parameter (Mandatory =$false)]
    [string]$GroupOUName,
    [Parameter(Mandatory = $false)]
    [string]$ComputerGroupName,
    [Parameter (Mandatory = $false)]
    [string]$KerberosAuthenticationPolicy,
    [switch]$SingleDomain
)


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
        Write-Debug "CreateOU called the $OUPath $DomainDNS"
        #load the OU path into array to create the entire path step by step
        $DomainDN = (Get-ADDomain -Server $DomainDNS).DistinguishedName
        #normalize OU remove 
        Write-Debug "Starting createOU $OUPath $DomainDNS"
        $OUPath = [regex]::Replace($OUPath,"\s?,\s?",",")
        if ($OUPath.Contains("DC=")){
            $OUPath = [regex]::Match($OUPath,"((CN|OU)=[^,]+,)+")
            $OUPath = $OUPath.Substring(0,$OUPath.Length-1)
        }
        Write-Debug "Normalized OUPath $OUPath"
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
function CreateGMSA {
    [cmdletBinding (SupportsShouldProcess)]
    param(
        [Parameter (Mandatory)]
        [string] $GMSAName,
        [Parameter (Mandatory=$false)]
        [string] $AllowTOLogon
    )
    try{
        #validate the KDS root key exists. If not create the KDS root key
        if (![bool](Get-KdsRootKey)){
            Write-Host "KDS Rootkey is missing." -ForegroundColor Red
            Write-Host "Creating KDS-Rootkey" -ForegroundColor Yellow
            Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10))
        }
        #Test the GMSA already exists. If the GMSA exists leaf the function with $true
        if ([bool](Get-ADServiceAccount -Filter "Name -eq '$GMSAName'")){
            return $true
        }
        #Provide the list of computers where the GMSA get the allow to logon privilege
        $aryAllowToLogon = @()
        if ($aryAllowToLogon -ne ""){
            #allow to logon to dedicated servers
            foreach ($srv in $AllowTOLogon.Split(";")){
                $oComputer = Get-ADComputer -Filter "name -eq '$srv'"
                $aryAllowToLogon += $oComputer.ComputerObjectDN
            } 
        } else {
            foreach ($srv in (Get-ADDomainController -Filter *)){
                $aryAllowToLogon += $srv.ComputerObjectDN
            }
        }
        #create the GMSA
        New-ADServiceAccount -Name $GMSAName -DNSHostName "$GmsaName.$((Get-ADDomain).DNSRoot)" -KerberosEncryptionType AES256 -PrincipalsAllowedToRetrieveManagedPassword $aryAllowToLogon
        $retval = $true
    }
    catch {
        Write-Host "A unexpected error has occured while creating the GMSA. $($error[0])"
        $retval = $false
    }
    Return $retval
}

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

$GlobalCatalog = "$((Get-ADDomainController -Discover -Service GlobalCatalog).HostName):3268"
$DescriptionT1ComputerGroup = "This group contains any Tier 0 computer. It will be used for Tier 0 Kerberos Authentication policy"
$KerberosAuthenticationPolicyDescription = "This Kerberos Authentication policy used to restrict interactive logon from untrusted computers"
$DefaultKerbAuthPolName = "Tier 1 Restrictions"

$T1UserOUDefault = "OU=Users,OU=Tier 1,OU=Admin"
$T1ComputerGroupNameDefault = "Tier 1 Computers"
$T1ComputerGroupNameDescription = "This group contains all Tier 1 member server and is used in Kerberos Authentication Policy"
$T1ComputerOUDefault = "OU=Computers,OU=Tier 1,OU=Admin"
$T0ComputerOUDefault = "OU=Computers,OU=Tier 0,OU=Admin"

$T1GroupDefaultOU= "OU=Groups"
$TGTLifeTime = 240
$DefaultGMSAName = "T1UserMgmt"

$GPOName = "Tier 1 User Management"
$RegExOUPattern = "(OU=*[^,]+)*,OU=[^,]+"
$iMaxGroupNameLength = 20
#endregion

$bAdding = $false #Global variable for adding another value. This parameter will be reused on interactive loops

#region Parameter validation
#region EnableForestMode
#A group managed service account is only required in a mulit domain forest. If the -singleDomain parameter is 
#set, the script will also run in the system context. I this scenario the Tier0UserManagement script will not 
#be able to remove unexpected users for privileged groups
if (!$SingleDomain -and ((Get-ADForest).Domains.count -gt 1)){
    Write-Host "Mulit domain forest mode activated" -ForegroundColor Green
    Write-Host "If you want to enable the Tier 1 user management only in the current domain, start the script with the switch -SingleDomain"
    $strContinue = Read-Host -Prompt "Do you want to continue?[Y]"
    if ($strContinue -like "n*"){
        Write-Host "script terminated" -ForegroundColor Red
    }
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
} else {
    Write-Host "Single domain mode activated" -ForegroundColor Green
}
#endregion
#region Tier 1 user OU
#Validate the base OU path. It should be similar like OU=Tier 1,OU=Admin
#If the parameter is not set, ask the user to enter a path or use the default value
if ($Tier1UserOU -eq ""){
    while (!$bAdding){
        Write-Host "Define the Tier 1 OU distinguished name for users without the domain name"
        $strTier1UserOU = Read-Host "Tier 1 user OU ($T1UserOUDefault)"
        if ($strTier1UserOU -eq ""){
            #the user pressed return the default value will be used
            $strTier1UserOU = $T1UserOUDefault
        } else {
            if (![regex]::Match($strTier1UserOU,$RegExOUPattern).Success){
                Write-Host "invalid OU Path" -ForegroundColor Red
                $strTier1UserOU = ""
            }
        }
        if ($Tier1UserOU -like "*$strTier1UserOU*"){
            Write-Host "OU $strTier1OU already added"
        } else {
            if ($Tier1UserOU -eq ""){
                $Tier1UserOU = $strTier1UserOU
            } else {
                $Tier1OU += ";$strTier1UserOU"
            }
        }
        if ((Read-Host -Prompt "Add another OU?[N]") -like "n*"){
            $bAdding = $true
        }
    }
}
#endregion
#region Tier 1 computer OU
$bAdding = $false
if ($Tier1ComputerOU -eq ""){
    while (!$bAdding){
        Write-Host "Define the relative OU distinguished name for computers without the domain name"        
        $strTier1ComputerOU = Read-Host "Tier 1 computer OU ($T1ComputerOUDefault)"
        if ($strTier1ComputerOU -eq ""){
            $strTier1ComputerOU = $T1ComputerOUDefault
        } else {
            if (![regex]::Match($strTier1ComputerOU,$RegExOUPattern).Success){
                Write-Host "Invalid OU path" -ForegroundColor Red
            }
        }
        if ($Tier1ComputerOU -like "*$strTier1ComputerOU"){
            Write-Host "OU $strTier1ComputerOU already added"
        } else {
            if ($Tier1ComputerOU = ""){
                $Tier1ComputerOU = $strTier1ComputerOU
            } else {
                $Tier1ComputerOU += ";$strTier1ComputerOU"
            }
        }
        if ((Read-Host -Prompt "Add another OU?[N]") -like "n*"){
            $bAdding = $true
        }
    }
}
#endregion
#region Tier 1 computer group name

if ($Tier1ComputerGroupName -eq ""){
    Write-Host "Name of the group who contains all Tier 1 computers"
    $strT1ComputerGroupName = Read-Host "Tier 0 computer group name"
    if ($strT1ComputerGroupName -eq ""){
        $Tier1ComputerGroupName = $T1ComputerGroupNameDefault
    } else {
        $Tier1ComputerGroupName = $strT1ComputerGroupName
    }
}
#endregion
#region Tier 0 computer OU
$bAdding = $false
if ($Tier0ComputerOU -eq ""){
    while (!$bAdding){
        Write-Host "Define the relative OU distinguished name from Tier 0 computer without the domain name"
        $strTier0ComputerOU = Read-Host "Tier 0 computer OU ($T0ComputerOUDefault)"
        if ($strTier0ComputerOU -eq ""){
            $strTier0ComputerOU  = $T0ComputerOUDefault
        } else {
            $Tier0ComputerOU = $strTier0ComputerOU
        }
        if ([adsi]::Exists("LDAP://$Tier0computerOU,$((Get-ADDomain).Distiguishedname)")){
                $bAdding = $true
        } else {
            Write-Host "The OU $Tier0ComputerOU doesn't exists in $domain"
        }
    }
}
#endregion
#region Tier 0 computerGroup
xxxxx validieren ob es diese Gruppe gibt
#endregion
#region KerberosAuthenticationPolicy
if ($KerberosAuthenticationPolicy -eq ""){
    $strKerbAuthName = Read-Host "Name of the Tier 1 Kerberos Authentication Policy Name"
    if ($strKerbAuthName -eq ""){
        $KerberosAuthenticationPolicy = $DefaultKerbAuthPolName
    }
}
#endregion
#endregion

#region OU Structure
#Create the required OUs in the all domains if the -SingleDomain switch is not set
#Tier 1 users can be located in different OUs
if ($SingleDomain){
    $aryDomains = @("$((Get-ADDomain).DNSRoot)")
} else {
    $aryDomains = (Get-ADForest).Domains
}
#On every domain in the array aryDomains
foreach ($domain in $aryDomains){
    if ($Tier1UserOU.Contains(";")){
        foreach ($strTier1UserOU in $Tier1UserOU.Split(";")){
            if (!(CreateOU -OUPath $Tier1UserOU -DomainDNS $domain)){
                Write-Host "$strTier1UserOU doesn't exists and cannot be created in $domain" -ForegroundColor Red
            }
        }
    } else {
        if(!(CreateOU -OUPath $Tier1UserOU -DomainDNS $domain)){
            Write-Host "$strTier1UserOU doesn't exists and cannot be created in $domain" -ForegroundColor Red
        }
    }
}
#endregion

#Create Tier 1 computer group if it doesn't exists
if ($null -eq (Get-ADObject -Filter "name -eq '$Tier1ComputerGroupName'")){
    #create the Tier 1 computer group
    Write-Host "the Tier 1 computer group doesn't exists and will be created."
    Write-Host "Don't forget to move the group into the correct OU" -ForegroundColor Yellow
    New-ADGroup -Name $Tier1ComputerGroupName -Description $T1ComputerGroupNameDescription -GroupScope Universal 
}

#region Kerberos Authentication Policy
if ($null -eq (Get-ADObject -LDAPFilter "(&(objectclass=msDS-AuthNPolicy)(name=$KerberosAuthenticationPolicy))" -SearchBase (GET-ADRootDSE).configurationNamingContext)){
    try {
        $T0GroupSID = (Get-ADGroup -Identity $Tier0ComputerGroupName -Properties ObjectSid).ObjectSid.Value
        $T1GroupSID = (Get-ADGroup -Identity $Tier1ComputerGroupName -Properties ObjectSid).ObjectSid.Value
        #Claim changed from Member of each to Member of any
        $AllowToAutenticateFromSDDL = "O:SYG:SYD:(XA;OICI;CR;;;WD;((Member_of_any {SID($T0GroupSID)})|| (Member_of_any {SID($T1GroupSID)})))"
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
} else {
    Write-Host "Kerberos Authentication policy $KerberosAuthenticationPolicy already exists"
}
#endregion

#region create a GroupManagedService Account if needed
if (!$SingleDomain){
    #in singleDomainMode a GMSA is not needed, because the schedule task will run in the system context and all Tier 1
    #users can ge managed by the SYSTEM account. In multi domain mode the schedule task must modify the users in all domains
    CreateGMSA -GMSAName $GMSAName
}
#region script copy
#copy script files to SYSVOL\<DOMAIN>\scripts folder. While the script run high privileged, take care the folder is only writeable to Tier 0 users
try {
    $ScriptTarget = "\\$CurrentDomainDNS\SYSVOL\$CurrentDomainDNS\scripts"
    Copy-Item .\Tier0ComputerManagement.ps1 $ScriptTarget -ErrorAction Stop
    Copy-Item .\Tier0UserManagement.ps1 $ScriptTarget -ErrorAction Stop
} catch {
    Write-Host "A unexpected error has occured while copy the PowerShell script to $ScriptTarget" -ForegroundColor Red
    Write-Host "copy the required Tier1MemberServerManagement.ps1 and Tier1userManagement.ps1 to \\$currentDomainDNS\SYSVOL\$CurrentDomainDNS\scripts"
    ContinueOnError
}
#endregion

#region group policy
#read the schedule task template from the current directory
[string]$ScheduleTaskRaw = Get-Content ".\ScheduledTasksTier1Template.xml" -ErrorAction SilentlyContinue
if ($null -eq $ScheduleTaskRaw ){
    Write-Host "Missing .\ScheduleTaskTier1Template.xml file. Configuration of the schedule tasks terminated" -ForegroundColor Red
    exit
}
#Create new Group Policy if required
$oGPO = Get-GPO -Name $GPOName -ErrorAction SilentlyContinue
if ($null -eq $oGPO){
    $oGPO = New-gpo -Name $GPOName -Comment "Tier Level enforcement group policy. " -ErrorAction SilentlyContinue
    $CSEGuid = "[{00000000-0000-0000-0000-000000000000}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}][{AADCED64-746C-4633-A97C-D61349046527}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}]"
    Set-ADObject -Identity "CN={$($oGPO.Id.Guid)},CN=Policies,CN=System,$((Get-ADDomain).DistinguishedName)" -Add @{'gPCMachineExtensionNames' = $CSEGuid}
}
#the Group Policy doesn't exists and is not created terminate the script
if ($null -eq $oGPO ){
    Write-Host "A group policy for Tier 0 user management could not be created" -ForegroundColor Red
    Write-Host "=> Create a group policy" -ForegroundColor Yellow
    Write-Host "configure the schedule tasks manually" -ForegroundColor Yellow
    exit
}
#$GPPPath contains the group policy path to the group policy preferences
$GPPath = "\\$((Get-ADDomain).DNSRoot)\SYSVOL\$((Get-ADDomain).DNSRoot)\Policies\{$($oGPO.ID)}\Machine\Preferences\ScheduledTasks"
#If a new group policy is created, the directory doesn't exists. We will create the directory
if (!(Test-Path "$GPPath")){
    New-Item -ItemType Directory $GPPath | Out-Null
}
#$GPPPath contains the full qualified path
$GPPath += "\ScheduledTasks.xml"
$oGPO | New-GPLink -Target (Get-ADDomain).DomainControllersContainer -LinkEnabled No
Write-Host "Tier 1 User Management Group Policy is linked to Domain Controllers OU but not activated" -ForegroundColor Yellow -BackgroundColor Blue
Write-Host "Validate the group policy and enable" -ForegroundColor Yellow
#region Configure the group policy schedule task
# in single domain mode the script will run in the system context. In mulit domain mode the Tier1UserManagement task must run in the context to the GMSA
# the group policy schedule task preferences doesn't allow to use GMSA. To enable the GMSA an seperate taks is required to change the context of the
#Tier1UserManagement Task to GMSA
if ($SingleDomain -or ((Get-ADForest).Domains.count -eq 1)){
    $ScheduleTaskRaw = $ScheduleTaskRaw.Replace('$InstallTask', "")
} else {
    $UdpateGMSACommand = "`$principal = New-ScheduledTaskPrincipal -LogonType Password -UserId '$GmsaName`$';Set-ScheduledTask 'Tier 1 User Management' -Principal `$principal"
    $ScheduleTaskRaw = $ScheduleTaskRaw.Replace('$InstallTask', $UdpateGMSACommand)    
}
$ScheduleTaskRaw = $ScheduleTaskRaw.Replace('$DomainDNS', $CurrentDomainDNS)
$ScheduleTaskRaw = $ScheduleTaskRaw.Replace('$Tier1ComputerGroupName', $Tier1ComputerGroupName)
$ScheduleTaskRaw = $ScheduleTaskRaw.Replace('$Tier1ComputerOU', $Tier1ComputerOU)
if ($SingleDomain){
    $ScheduleTaskRaw = $ScheduleTaskRaw.Replace('$EnableMulitDomainSupport','')
} else {
    $ScheduleTaskRaw = $ScheduleTaskRaw.Replace('$EnableMulitDomainSupport','-EnableMulitDomainSupport')
}
$ScheduleTaskRaw = $ScheduleTaskRaw.Replace('$AnyComputerType','')
$ScheduleTaskRaw = $ScheduleTaskRaw.Replace('$KerberosAuthenticationPolicyName',$KerberosAuthenticationPolicy)
$ScheduleTaskRaw = $ScheduleTaskRaw.Replace('$Tier1UserOU', $Tier1UserOU)

[xml]$ScheduleTaskXML = $ScheduleTaskRaw
if ($SingleDomain){
    $GMSAChangeNode  = $ScheduleTaskXML.SelectSingleNode("//TaskV2[@name='Change Tier 1 User Management']")
    $ScheduleTaskXML.ScheduledTasks.RemoveChild($GMSAChangeNode) 
}
$ScheduleTaskXML.Save($GPPath)
 
#endregion