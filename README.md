# Introduction
Kerberos Authentication Policies are a common way to isolate Tier 0 accounts in Active Directory. Tier 0 accounts are those that have the highest level of privilege and access to the most sensitive resources, such as domain controllers, schema administrators, and enterprise administrators. Isolating Tier 0 accounts can help prevent credential theft, lateral movement, and privilege escalation attacks.
The huge benefit of Kerberos Authentication Policy is that it is independent of the client. The isolation is handled on the Key Distribution Center (KDC), which is the service that issues Kerberos tickets, and not on the client. This means that the policy can be enforced regardless of the device or application that the Tier 0 account uses to authenticate.
The downside is that the Kerberos Authentication Policy must be added to each Tier 0 account manually. The purpose of these scripts is to automate the manual task and make it easier to manage the Kerberos Authentication Policy for Tier 0 accounts.
Kerberos Authentication Policies can be used to restrict interactive logon to Tier 0 and Tier 1

# Enforcing Kerberos Authentication Policy for Tier 0 and Tier 1
This solution provides both options to restrict interactive logon. 

# Tier 0 User Management Version 0.1
This solution provides automated prozesses to manage Tier 0 users.
# Version 1.0.20240206
User objects outside of the Tier 0 users OU can be defined during the setup. Multiple users can be added
Fix on schedule task management

## Key Features
* Automatically assignment of Kerberos Authentication Policy on Tier 0 user accounts
* Automatically deactivation of user accounts which are outside of the Tier 0 OU Structure 
* Automatically adding Tier 0 member server to the Kerberos Authentication Policy Claim (group)

The solution is based on PowerShell scripts triggered by schedule tasks. If the script runs in a mulit domain forest, a group managed service account is needed to run the Tier 0 User Management script. In a single domain mode, the script will run in the system context of a domain controller. 

# Installation
To install the solution download the Powershell script and run Install-T0.ps1. The installation script must run as a enterprise admin. After the installation script is finished validate Kerberos amoring is functional. If Kerberos amoring is enabled on every DC, move any Tier 0 user to the Tier 0 user OU and any Tier 0 member server to the Tier 0 computers OU.
On the last step enable the Tier 0 Management group policy on the Domain controller OU 

## The installation in a nutshell
## Tier 0
To install Tier 0 protection run the install-t0.ps1. This script will
### create the required Tier 0 OUs on every domain in the forest
It will create the required OU structure for protected Tier 0 isolation. The names of the OU can be changed. The default names are
{Domain}\
         Admin\                 Is the global administration OU for any Tier level
                Tier 0\                 contains any non-builtin Tier 0 related User, Group and Computer objects
                    Computers           contains any Tier 0 related computer object. Any computer in this OU will be added to the Tier 0 claim.
                    Groups              Contains any Tier 0 groups special the Tier 0 computer groups
                    Service Acocunts    contains any Tier 0 related use object who will used to run a service. 
                    Users               contains any Tier 0 users
                    
### create the Tier 0 computers group
the Tier 0 computers group will be located in [domain]/Admin/Tier 0/Groups as universal group. If the group already exists in the wrong OU a warning will be presented and the group must be moved manually to the correct OU.
### enable Kerberos amoring on the forest
Kerberos amroing will be enabled on the domain controllers and any client in the forest. On the Default Domain Policy the Administrative Template SYSTEM\Kerberos\Enable claim support will be enabled. On the Default Domain Controller Policy the Administrative Template SYSTEM\KDC\Support Kerberos amoring will be change to the supported state
### copy the required scripts to the SYSVOL scripts folder
The installation script will copy the required scrips to \\{Forest-Root}\SYSVOL\{Forest-Root}\Scripts to make the scripts available to any domain controller in the root domain. Please take care this Folder is only writeable to domain admins
### create a group policy for schedule tasks
A new group policy "Tier 0 Management" will be created and linked as disabled to the forest-root domain controller OU. 

## Tier 1
### create the required Tier 1 OUs in the current domain
...
### copy the required scripts to the SYSVOL scripts folder
The installation script will copy the required scrips to \\{Forest-Root}\SYSVOL\{Forest-Root}\Scripts to make the scripts available to any domain controller in the root domain. Please take care this Folder is only writeable to domain admins
### create a group policy for schedule tasks
A new group policy "Tier 1 management" will be created and linked as disabled to the forest-root domain controller OU

# Powershell  scripts in details 
The solution is based on three PowerShell scripts that can be downloaded from the following URL: https://github.com/Kili69/Tier0-User-Management
##	Tier0ComputerManagement.ps1: 
This script creates and manages a security group that contains all the Tier 0 computers in the domain. 
##	Tier0UserManagement.ps1: 
This script creates and manages a security group that contains all the Tier 0 users in the domain. The script also apply the Kerberos Authentication Policy to any user who is located in the Tier 0 user OU, which will restrict the Tier 0 users to only request Kerberos tickets from the Tier 0 computers. This will prevent the Tier 0 users from logging on to other devices that are not in the Tier 0 scope.
## Install-T0.ps1: 
This script installs and configures the Tier 0 scripts on a designated management computer. The will provide a Group Policy to schedule the Tier 0 scripts to run periodically, which will ensure that the Tier 0 security groups and Kerberos Authentication Policy are updated regularly.

## CreatekerberosAuthenticationPolicy.ps1
(This script is deprecated)
This script create Kerberos Authentication policies for Tier 0 or Tier 1 isolation. 
### Parameters 

-PolicyName  is the name of the Kerberos Authentication Policy (Default value is "Tier 0 Restrictions)"

-Tier0ComputerGroup is the name of the AD group who contains any Tier 0 member server (Default value is "Tier 0 Computers")

-TGTLifeTime is the user TGT life time (Default vlue is 240 minutes)

-Tier1KerberosAuthenticationPolicy use this switch if you creating a Kerberos Authentication Policy for Tier 1 users


## Tier0ComputerManagement.ps1

This script add all computers in the Tier 0 computer OU to a single group. This group can be used in the Claim of the Kerberos Authentication Policy
### Parameters 

-Tier0ComputerGroupName   this parameter is the name of the AD group where all the T0 computer objects are added

-Tier0ComputerOU          this parameter is the relative distinguished name of the OU where all the Tier 0 computer objects exits. Relative distinguished name means the DN with out the domain component e.g. OU=Tier0,OU=Admin

-MulitDomainForest        this parameter enable the mulit domain forest mode. In this mode all Tier 0 computer object from any domain it the AD forest will be added to this group

### Example

.\Tier0computerManagement.ps1  -Tier0ComputerOU 'Tier 0 computers' -Tier0ComputerOU 'OU=Tier 0,OU=Admin'

## Tier0UserManagement.ps1

This script assign the Kerberos Authentication Policy to any user account in the Tier 0 OU and disable user account who are member of privileged groups who are located in a different OU then the Tier 0 user OU
### Parameters 

-RemoveUserFromPrivilegedGroups    if this parameter is $true the script will disable all non Tier 0 user accounts, if they are not located in the Tier 0 user OU

-PrivilegedOUPath                  this parameter is the relative distinguishedname to the Tier 0 user OU

-PrivilegedServiceAccountOUPath    this parameter ignores the assignment of Kerberos Authenticiation Polices to users ojects in this OU. Relative DistinguishedName means the DN without the domain component

-Tier0UserGroupName                is a optional parameter to add any to on the PrivilegedOUPath to a AD user group

-KerberosPolicyName                is the name of the Kerberos Authentication Policy

-ExcludeUser                       is a list of users they not be disabled event they are in a privileged Tier 0 group

-EnableMulitDomainSupport          if this switch is available the script will assing all users in the PrivilegedOUPath from any domain to the Tier 0 users group

### Example

.\Tier0UserManagement.ps1 -PrivilegedOUPAth 'OU=Users,OU=Tier 0,OU=Admin' - PrivilegedServiceAccountOUPath 'OU=Service Account,OU=Tier 0,OU=Admin' -Tier0UserGroup 'T0-Users' -KerberosPolicyName 'Tier 0 Isolation' -EnableMutiDomainSupport

## Install-T1.ps
This script create the required Kerberos Authentication Policy, OUs and Group Policy to protect Tier 1 accounts.

## Tier1MemberServerManagement.ps1
This script adds Tier 1 computers to the Tier 1 computer group.
### Parameters 
-Tier1ComputerGroupName              is a mandatory string with the name fo the AD group where all Tier 1 computer object will be added
-Tier1ComputerOU                     is a mandatory string ofthe relavtive OUs of Tier 1 computers. If there is mulitple OUs available, separate them with a ";". The OU path contains all sub OUs
-Tier0ComputerOU                     is mandatory and contains the relative path of Tier 0 computers OUs. All SUB OUs will be automatically included
-EnableMulitDomainSupport            if this switch is available, the script will add Tier 1 computers from any domain in Tier 1 computer group
-AnyComputerType                     if this switch is available, the script will and any object of object class computer to the Tier 1 computer group. if the switch is not available, the script will only add computer object who has the word "server" in the operating system string
### Example 
    .\Tier0ComputerManagement.ps1 -Tier0ComputerGroupName "Tier0Server" -Tier0ComputerGroupName "OU=Tier 0,OU=Admin"
        The script will search for any computer in the OU=Tier 0,OU=Admin and subfolder on any domain in the forest 
    .\Tier0ComputerManagement.ps1 -Tier0ComputerGroupName "Tier0Server" -Tier0ComputerGroupName "OU=Tier 0,OU=Admin" -MulitDomainForest $False
        The script will search for any computer in the OU=Tier 0,OU=Admin and subfolder in the current domain
	.\Tier0ComputerManagement.ps1 -Tier0ComputerGroupName "Tier0Server" -Tier0ComputerGroupName "OU=Tier 0,OU=Admin,DC=Contoso,DC=com"
        The script will search for any computer in the OU=Tier 0,OU=Admin and subfolder on any domain in the forest. The domain name in the Distiguishedname will be ignored
    .\Tier0ComputerManagement.ps1 -Tier0ComputerGroupName "Tier0Server" -Tier0ComputerGroupName "OU=Tier 0,OU=Admin;OU=2ndOU"
        The script will search for any computer in OU=Tier 0,OU=Admin and OU=2ndOU in all domains in the forest
    
## Tier1UserManagement.ps
This script will assing the Kerberos Authentication policy to Tier 1 administrators.
### Parameters 
-KerberosAuthenticationPolicyName    is the name ob the Tier 1 Kerberos Authentication policy. This parameter is mandatory
-Tier1UserOU                         is the relative OU path for Tier 1 administrators. If the Tier 1 administrators are located in different OUs, you can seperate the OUs with a ";"
-EnableMulitDomainSupport            if this switch is available, the Kerberos Authentication Policy will be added to any user in the Forest
### Example
    .\Tier1UserManagement.ps1 -KerberosAuthenticationPolicyName "Tier 1 Isolation" -Tier1UserOU "OU=Users,OU=Tier 1,OU=Admin"
        Applies the "Tier 1 Isolation" Kerberos policy to any user located in the OU=Users,OU=Tier 1,OU=Admin,DC=<domain>
    .\Tier1UserManagement.ps1 -KerberosAuthenticationPolicyName "Tier 1 Isolation" -Tier1UserOU "OU=Users,OU=Tier 1,OU=Admin" -EnableMulitdomainSupport
        Applies the "Tier 1 Isolation" Kerberos policy to any user located in the OU=Users,OU=Tier 1,OU=Admin in every domain of the forest
    .\Tier1UserManagement.ps1 -KerberosAuthenticationPolicyName "Tier 1 Isolation" -Tier1UserOU "OU=Users,OU=Tier 1,OU=Admin;OU=Org1,OU=Admins"
        Applies the "Tier 1 Isolation" Kerberos policy to any user located in the OU=Users,OU=Tier 1,OU=Admin,DC=<domain> and "OU=Org1,OU=Admins"

## Prerequisites 

* Microsoft Powershell 5.0 or higher
* Active Directory Remote Administration Powershell Modules (Windows Server 2016 or higher)

# Contributors
Many thanks to 
Dagmar Heidecker
Andreas Luy


# Support
This sample script is not supported under any support program or service. 
The sample script is provided AS IS without warranty of any kind. If you repo

# You may also like...

- Just-In-Time Administration https://github.com/Kili69/T1JIT
- Enumaration of local administrators https://github.com/Kili69/LocalAdministrators



---


