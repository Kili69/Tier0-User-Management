Kerberos Authentication Policies are a common way to isolate Tier 0 in Active Directory. The huge benefit of Kerberos Authentication Policy is that it is independent of the client. The isolation is handled on the KDC and not on the client. 
The downside is that the Kerberos Authentication Policy must be added to each Tier 0 account manually. The purpose of these scripts is to automate the manual task.


## Key Features
* Automatically assignment of Kerberos Authentication Policy on Tier 0 user accounts
* Automatically deactivation of user accounts which are outside of the Tier 0 OU Structure 
* Automatically adding Tier 0 member server to the Kerberos Authentication Policy Claim (group)

## How To Use

Run the scripts as a schedule task on every DC in the context of the system every 10 - 30 minutes. 

## CreatekerberosAuthenticatinPolicy
This script create Kerberos Authentication policies for Tier 0 or Tier 1 isolation. 
the script supports the following parameters:

-PolicyName  is the name of the Kerberos Authentication Policy (Default value is "Tier 0 Restrictions"

-Tier0ComputerGroup is the name of the AD group who contains any Tier 0 member server (Default value is "Tier 0 Computers")

-TGTLifeTime is the user TGT life time (Default vlue is 240 minutes)

-Tier1KerberosAuthenticationPolicy use this switch if you creating a Kerberos Authentication Policy for Tier 1 users


## Tier0ComputerManagement.ps1

This script add all computers in the Tier 0 computer OU to a single group. This group can be used in the Claim of the Kerberos Authentication Policy
The script supports the following parameters:

-Tier0ComputerGroupName   this parameter is the name of the AD group where all the T0 computer objects are added

-Tier0ComputerOU          this parameter is the relative distinguished name of the OU where all the Tier 0 computer objects exits. Relative distinguished name means the DN with out the domain component e.g. OU=Tier0,OU=Admin

-MulitDomainForest        this parameter enable the mulit domain forest mode. In this mode all Tier 0 computer object from any domain it the AD forest will be added to this group

#Example

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

Example

.\Tier0UserManagement.ps1 -PrivilegedOUPAth 'OU=Users,OU=Tier 0,OU=Admin' - PrivilegedServiceAccountOUPath 'OU=Service Account,OU=Tier 0,OU=Admin' -Tier0UserGroup 'T0-Users' -KerberosPolicyName 'Tier 0 Isolation' -EnableMutiDomainSupport

##Prerequisites 

Microsoft Powershell 5.0 or higher
Active Directory Remote Administration Powershell Modules (Windows Server 2016 or higher)


## Credits


## Support


## You may also like...

- Just-In-Time Administration https://github.com/Kili69/T1JIT
- Enumaration of local administrators https://github.com/Kili69/LocalAdministrators

## License

BSD

---


