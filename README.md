# Introduction
Kerberos Authentication Policies are a common way to isolate Tier 0 accounts in Active Directory. Tier 0 accounts are those that have the highest level of privilege and access to the most sensitive resources, such as domain controllers, schema administrators, and enterprise administrators. Isolating Tier 0 accounts can help prevent credential theft, lateral movement, and privilege escalation attacks.
The huge benefit of Kerberos Authentication Policy is that it is independent of the client. The isolation is handled on the Key Distribution Center (KDC), which is the service that issues Kerberos tickets, and not on the client. This means that the policy can be enforced regardless of the device or application that the Tier 0 account uses to authenticate.
The downside is that the Kerberos Authentication Policy must be added to each Tier 0 account manually. This can be a tedious and error-prone task, especially if there are many Tier 0 accounts in the domain. The purpose of these scripts is to automate the manual task and make it easier to manage the Kerberos Authentication Policy for Tier 0 accounts.

## Solution Version 0.1.20231223

## The scripts 
The solution is based on three PowerShell scripts that can be downloaded from the following URL: https://github.com/Kili69/Tier0-User-Management
###	Tier0ComputerManagement.ps1: 
This script creates and manages a security group that contains all the Tier 0 computers in the domain. 
###	Tier0UserManagement.ps1: 
This script creates and manages a security group that contains all the Tier 0 users in the domain. The script also apply the Kerberos Authentication Policy to any user who is located in the Tier 0 user OU, which will restrict the Tier 0 users to only request Kerberos tickets from the Tier 0 computers. This will prevent the Tier 0 users from logging on to other devices that are not in the Tier 0 scope.
### Install-T0.ps1: 
This script installs and configures the Tier 0 scripts on a designated management computer. The will provide a Group Policy to schedule the Tier 0 scripts to run periodically, which will ensure that the Tier 0 security groups and Kerberos Authentication Policy are updated regularly.

# Key Features
* Automatically assignment of Kerberos Authentication Policy on Tier 0 user accounts
* Automatically deactivation of user accounts which are outside of the Tier 0 OU Structure 
* Automatically adding Tier 0 member server to the Kerberos Authentication Policy Claim (group)

## How To Use
Run the Install-T0.ps1 script to install the solution. The installation script will copy the Tier0UserManagement.ps1 and Tier0ComputerManagement.ps1 required scripts to \\ForestRootDomain\SYSVOl\ForestRootDomain\scripts, it will create the Kerberos Authentication Policy and a Group Policy linked to the Domain Controller OU in the Forest Root. This Group Policy contains the Schedule tasks to run the scripts regularly on very domain controller. 
** The created group policy requires to open a schedule task in preferences/control panel and click on OK. Otherwise the schedule task will not shown up in the group policy **
** The created group policy is linked to the domain controller OU but not enabled, validate the Group Policy and enable**

### Install-T0.ps1
This script install the solution in the current AD Forest. 
This script creates the required
- OU structure for Tier 0 computers, T0 Users, T0 Groups and T0 service accounts. 
- "Tier 0 computer" and "Tier 0 users" in the Tier 0 groups organizaional unit
- Kerberos Authenticatin Policy
- Group Policy to run the scripts as a schedule task
 

### CreatekerberosAuthenticationPolicy.ps1
(This script is deprecated)
This script create Kerberos Authentication policies for Tier 0 or Tier 1 isolation. 
the script supports the following parameters:

-PolicyName  is the name of the Kerberos Authentication Policy (Default value is "Tier 0 Restrictions)"

-Tier0ComputerGroup is the name of the AD group who contains any Tier 0 member server (Default value is "Tier 0 Computers")

-TGTLifeTime is the user TGT life time (Default vlue is 240 minutes)

-Tier1KerberosAuthenticationPolicy use this switch if you creating a Kerberos Authentication Policy for Tier 1 users


## Tier0ComputerManagement.ps1

This script add all computers in the Tier 0 computer OU to a single group. This group can be used in the Claim of the Kerberos Authentication Policy
The script supports the following parameters:

-Tier0ComputerGroupName   this parameter is the name of the AD group where all the T0 computer objects are added

-Tier0ComputerOU          this parameter is the relative distinguished name of the OU where all the Tier 0 computer objects exits. Relative distinguished name means the DN with out the domain component e.g. OU=Tier0,OU=Admin

-MulitDomainForest        this parameter enable the mulit domain forest mode. In this mode all Tier 0 computer object from any domain it the AD forest will be added to this group

### Example

.\Tier0computerManagement.ps1  -Tier0ComputerOU 'Tier 0 computers' -Tier0ComputerOU 'OU=Tier 0,OU=Admin'

Tier0UserManagement.ps1

This script assign the Kerberos Authentication Policy to any user account in the Tier 0 OU and disable user account who are member of privileged groups who are located in a different OU then the Tier 0 user OU
The script supports the following parameters:

-RemoveUserFromPrivilegedGroups    if this parameter is $true the script will disable all non Tier 0 user accounts, if they are not located in the Tier 0 user OU

-PrivilegedOUPath                  this parameter is the relative distinguishedname to the Tier 0 user OU

-PrivilegedServiceAccountOUPath    this parameter ignores the assignment of Kerberos Authenticiation Polices to users ojects in this OU. Relative DistinguishedName means the DN without the domain component

-Tier0UserGroupName                is a optional parameter to add any to on the PrivilegedOUPath to a AD user group

-KerberosPolicyName                is the name of the Kerberos Authentication Policy

-ExcludeUser                       is a list of users they not be disabled event they are in a privileged Tier 0 group

-EnableMulitDomainSupport          if this switch is available the script will assing all users in the PrivilegedOUPath from any domain to the Tier 0 users group

### Example

.\Tier0UserManagement.ps1 -PrivilegedOUPAth 'OU=Users,OU=Tier 0,OU=Admin' - PrivilegedServiceAccountOUPath 'OU=Service Account,OU=Tier 0,OU=Admin' -Tier0UserGroup 'T0-Users' -KerberosPolicyName 'Tier 0 Isolation' -EnableMutiDomainSupport

##Prerequisites 

Microsoft Powershell 5.0 or higher
Active Directory Remote Administration Powershell Modules (Windows Server 2016 or higher)


# Credits


# Support


# You may also like...

- Just-In-Time Administration https://github.com/Kili69/T1JIT
- Enumaration of local administrators https://github.com/Kili69/LocalAdministrators

# License

BSD

---


