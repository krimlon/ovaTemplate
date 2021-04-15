
[string]$ADServer1NetBIOSName = "AD1"
[string]$ADServer2NetBIOSName = "AD2"
[string]$ADServer1PrivateIP = (Get-EC2Instance -Filter @{Name = "tag:test:ce:windows-domain"; Value = "test.beta.net" }, @{Name = "tag:test:ml:tech-stack"; Value = "adds_primary" } | Select-object -ExpandProperty Instances -first 1 | select-object PrivateIPAddress).privateipaddress
[string]$ADServer2PrivateIP = (Get-EC2Instance -Filter @{Name = "tag:test:ce:windows-domain"; Value = "test.beta.net" }, @{Name = "tag:test:ml:tech-stack"; Value = "adds_backup" } | Select-object -ExpandProperty Instances -first 1 | select-object PrivateIPAddress).privateipaddress
[string]$DomainDNSName = "test.beta.net"

$ADAdminPassword = New-Object -TypeName psobject
$ADAdminPassword | Add-Member -MemberType NoteProperty -Name username -Value "administrator"
$ADAdminPassword | Add-Member -MemberType NoteProperty -Name password -Value ([string]$((Get-SSMParameterValue -Name testbetaDAadminPassword -WithDecryption $True).Parameters[0].Value))

# PowerShell DSC Configuration Block to config DNS Settings on DC1 and DC2


Configuration DnsConfig {

    # Importing DSC Modules needed for Configuration
    Import-Module -Name PSDesiredStateConfiguration
    Import-Module -Name NetworkingDsc
    Import-Module -Name ComputerManagementDsc

    # Importing All DSC Resources needed for Configuration
    Import-DscResource -Module PSDesiredStateConfiguration
    Import-DscResource -Module NetworkingDsc
    Import-DscResource -Module ComputerManagementDsc

    # DNS Settings for First Domain Controller
    Node $ADServer1 {

        DnsServerAddress DnsServerAddress {
            Address        = $ADServer2PrivateIP, $ADServer1PrivateIP
            InterfaceAlias = 'Primary'
            AddressFamily  = 'IPv4'
        }
    }

    # DNS Settings for Second Domain Controller
    Node $ADServer2 {

        DnsServerAddress DnsServerAddress {
            Address        = $ADServer1PrivateIP, $ADServer2PrivateIP
            InterfaceAlias = 'Primary'
            AddressFamily  = 'IPv4'
        }
    }
}

# Formatting Computer names as FQDN
$ADServer1 = $ADServer1NetBIOSName + "." + $DomainDNSName
$ADServer2 = $ADServer2NetBIOSName + "." + $DomainDNSName

# Creating Credential Object
$Credentials = (New-Object PSCredential($ADAdminPassword.UserName,(ConvertTo-SecureString $ADAdminPassword.Password -AsPlainText -Force)))

# Setting Cim Sessions for Each Host
$VMSession1 = New-CimSession -Credential $Credentials -ComputerName $ADServer1 -Verbose
$VMSession2 = New-CimSession -Credential $Credentials -ComputerName $ADServer2 -Verbose

# Generating MOF File
DnsConfig -OutputPath 'C:\config\DnsConfig'

# No Reboot Needed, Processing Configuration from Script utilizing pre-created Cim Sessions
Start-DscConfiguration -Path 'C:\config\DnsConfig' -CimSession $VMSession1 -Wait -Verbose -Force
Start-DscConfiguration -Path 'C:\config\DnsConfig' -CimSession $VMSession2 -wait -Verbose -Force
