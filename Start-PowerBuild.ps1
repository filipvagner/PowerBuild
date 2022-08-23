###########################################################
# AUTHOR  : Filip Vagner
# EMAIL   : filip.vagner@hotmail.com
# DATE    : 05-06-2020
# COMMENT : This Powershell script performs deployment of virtual machine in vCenter.
#           It uses VM templates.
#           It uses pre-defined OS Customization templates.
# TODO Implement logic to exclude esx host from vm deployment (if VLAN or datastore is not connected) instead of exiting script
# FIXME How to implement to whom send email (possible fix email group or email as parameter)
###########################################################

# Script's parameters
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateNotNull()]
    [ValidatePattern('^[a-zA-Z]{2,3}-([vV][wW]|[vV][wW][lL])\d{4}$')]
    [String]
    $NewServerName
)

# Loading functions
. $env:ProgramData\PowerBuild\Write-PowerBuildLogToDb.ps1
. $env:ProgramData\PowerBuild\Get-PowerBuildLogFromDb.ps1
. $env:ProgramData\PowerBuild\Write-PowerBuildDataToDb.ps1
. $env:ProgramData\PowerBuild\Test-AdComputerLocation.ps1
. $env:ProgramData\PowerBuild\Get-NewServerOSlicense.ps1
. $env:ProgramData\PowerBuild\Set-NewServerDisk.ps1

#TODO Check if JSON file exist
#TODO Check if conneciton to DB is available
#TODO Parameter email address (if empty, set default address)

## Loading server's properties to variables
$serverJson = Get-Content -Path "$env:ProgramData\PowerBuild\JsonTemplate\$NewServerName.json"
$serverObject = $serverJson | ConvertFrom-Json

$serverName = $serverObject.servername
$requestNumber = $serverObject.requestnumber
$requester = $serverObject.requester
$country = $serverObject.country
$datacenter = $serverObject.datacenter
$environment = $serverObject.environment
$domain = $serverObject.domain
$serverTier = $serverObject.tier
$appName = $serverObject.appname
$appOwner = $serverObject.appowner
$appAdmin = $serverObject.appadmin
$cyberarkRequired = $serverObject.cyberarkrequiered
$backupRequired = $serverObject.backuprequired
$patchWave = $serverObject.patchwave
$os = $serverObject.os
$cpu = $serverObject.cpu
$memory = $serverObject.memory
$diskOne = $serverObject.diskone
$diskTwo = $serverObject.disktwo
$diskThree = $serverObject.diskthree
$diskFour = $serverObject.diskfour
$diskFive = $serverObject.diskfive
$diskSix = $serverObject.disksix
$ipAddress = $serverObject.ipaddress
$ipMask = $serverObject.ipmask
$ipGateway = $serverObject.ipgateway
$ipDnsOne = $serverObject.ipdnsone
$ipDnsTwo = $serverObject.ipdnstwo
$ipVlan = $serverObject.ipvlan

# Variables
## VMware check
$vcAvailable = 0
$vmDuplicate = 1
$nwAvailable = 0
$dsAvailable = 0
$tpAvailable = 0
$ocAvailable = 0
## Active Directory check
$adAvailable = 0
$caDuplicate = 1
$ouAvailable = 0
## Other check
$ipDuplicate = 1
## Active Directory build
$caExist = 0
$caLocation
$adController
## VMware build
$vmCluster
$vmHost
$vmHostStatus = 0
$vmRp
$vmFolder
$dsCluster
$vmDatastore
$vmDatastoreStatus = 0
$vmTemplate
$vmTemplateStatus = 0
$vmOc
$vmOcCopy
$vmOcCopyStatus = 0
$vmExist = 0
$vmVlanName
## OS Checks
$imgStatePassed = 0
$fwPassed = 0
$osLicPassed = 0
$osLicProductKey
$osLicServer
## OS Configuration
$disksSet = 0
$patchingSet = 0
$pwGroup
$adminSet = 0
## Software installation
$installFilesCopied = 0
$knaInstalled = 0
$kavInstalled = 0
$spnInstalled = 0
$ucmInstalled = 0
$emcInstalled = 0
## Process status
$pchkPassed = 0
$buildPassed = 0
$buildStatus = "Ready"
$canDeploy = 0
$scopeStatus = "Ready"
$oschkPassed = 0
$osConfigPassed = 0
$swInstallPassed = 0

## Help variables
$pbStartDate = Get-Date -Format yyyy-MM-dd
$pbStartTime = Get-Date -Format HH:mm:ss
$dsListAccessible = New-Object -TypeName "System.Collections.ArrayList"
[int[]]$vmDiskList = $diskOne, $diskTwo, $diskThree, $diskFour, $diskFive, $diskSix
[string[]] $dnsServerList = $ipDnsOne, $ipDnsTwo
$dnsListCounter = 1

## Email notification
$pbSendMailPassed = @{
    From = "powerbuild@domain.cz"
    To = "filip.vagner@domain.cz"
    Subject = "PowerBuild - $requestNumber completed"
    SMTPServer = "<server domain name>"
    Body = "Deployment of server $serverName successfully completed"
}

$pbSendMailFailed = @{
    From = "powerbuild@domain.cz"
    To = "filip.vagner@domain.cz"
    Subject = "PowerBuild - $requestNumber failed"
    SMTPServer = "<server domain name>"
    Body = "Deployment of server $serverName failed"
}

## Loading server's properties to database
$sqlServerInfo = "<server name>"
$sqlInstanceInfo = Get-SqlInstance -Path "SQLSERVER:\SQL\<server name>\DEFAULT"
$sqlDatabaseInfo = "PowerBuild"

$serverNameProperties = "
INSERT INTO builds (
	server_name,
	request_number,
	requester,
	country,
	datacenter,
	environment,
    domain,
    server_tier,
	app_name,
	app_owner,
	app_admin,
	cyberark_required,
	backup_required,
	patch_wave,
	os,
	cpu,
	memory,
	disk_one,
	disk_two,
	disk_three,
	disk_four,
	disk_five,
	disk_six ,
	ip_address,
	ip_mask,
	ip_gateway,
	ip_dns_one,
	ip_dns_two,
	ip_vlan
) VALUES (
    '$serverName',
    '$requestNumber',
    '$requester',
    '$country',
    '$datacenter',
    '$environment',
    '$domain',
    '$serverTier',
    '$appName',
    '$appOwner',
    '$appAdmin',
    '$cyberarkRequired',
    '$backupRequired',
    '$patchWave',
    '$os',
    '$cpu',
    '$memory',
    '$diskOne',
    '$diskTwo',
    '$diskThree',
    '$diskFour',
    '$diskFive',
    '$diskSix',
    '$ipAddress',
    '$ipMask',
    '$ipGateway',
    '$ipDnsOne',
    '$ipDnsTwo',
    '$ipVlan'
);
"
Invoke-Sqlcmd -HostName $sqlServerInfo -ServerInstance $sqlInstanceInfo -Database $sqlDatabaseInfo -Query $serverNameProperties

Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - PowerBuild process started"
Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Build of $serverName started"
# VMware Checks
## vCenter availablity
Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Check vCenter availablity"
switch ($country) {
    '<country code>' { 
        if ($datacenter -like 'pdc') { 
            $vCenterServer = "<server name>"
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Variable vCenterServer set to $vCenterServer"
            $vmCluster = "<cluster name>"
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Variable vmCluster set to $vmCluster"
            $dsCluster = "<cluster name>"
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Variable dsCluster set to $dsCluster"
            $pchkPassed = 1
            $buildStatus = "Running"
            $canDeploy = 1
            break
        } elseif ($datacenter -like 'drc') {
            $vCenterServer = "<server name>"
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Variable vCenterServer set to $vCenterServer"
            $vmCluster = "<cluster name>"
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Variable vmCluster set to $vmCluster"
            $dsCluster = "<cluster name>"
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Variable dsCluster set to $dsCluster"
            $pchkPassed = 1
            $buildStatus = "Running"
            $canDeploy = 1
            break
        } else {
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - Variable vCenterServer has not been set"
            $pchkPassed = 0
            $buildStatus = "Failed"
            $canDeploy = 0
            break
        }
    }

    '<country code>' { 
        if ($datacenter -like 'pdc') { 
            $vCenterServer = "<server name>"
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Variable vCenterServer set to $vCenterServer"
            $vmCluster = "<cluster name>"
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Variable vmCluster set to $vmCluster"
            $dsCluster = "<cluster name>"
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Variable dsCluster set to $dsCluster"
            $pchkPassed = 1
            $buildStatus = "Running"
            $canDeploy = 1
            break
        } elseif ($datacenter -like 'drc') {
            $vCenterServer = "<server name>"
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Variable vCenterServer set to $vCenterServer"
            $vmCluster = "<cluster name>"
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Variable vmCluster set to $vmCluster"
            $dsCluster = ""
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Variable dsCluster set to $dsCluster"
            $pchkPassed = 1
            $buildStatus = "Running"
            $canDeploy = 1
            break
        } else {
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - Variable vCenterServer has not been set"
            $pchkPassed = 0
            $buildStatus = "Failed"
            $canDeploy = 0
            break
        }
    }

    '<country code>' { 
        if ($datacenter -like 'pdc') { 
            $vCenterServer = "<server name>"
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Variable vCenterServer set to $vCenterServer"
            $vmCluster = "<cluster name>"
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Variable vmCluster set to $vmCluster"
            $dsCluster = "<cluster name>"
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Variable dsCluster set to $dsCluster"
            $pchkPassed = 1
            $buildStatus = "Running"
            $canDeploy = 1
            break
        } elseif ($datacenter -like 'drc') {
            $vCenterServer = "<server name>"
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Variable vCenterServer set to $vCenterServer"
            $vmCluster = "<cluster name>"
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Variable vmCluster set to $vmCluster"
            $dsCluster = ""
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Variable dsCluster set to $dsCluster"
            $pchkPassed = 1
            $buildStatus = "Running"
            $canDeploy = 1
            break
        } else {
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - Variable vCenterServer has not been set"
            $pchkPassed = 0
            $buildStatus = "Failed"
            $canDeploy = 0
            break
        }
    }

    '<country code>' { 
        if ($datacenter -like 'pdc') { 
            $vCenterServer = "<server name>"
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Variable vCenterServer set to $vCenterServer"
            $vmCluster = "<cluster name>"
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Variable vmCluster set to $vmCluster"
            $dsCluster = "<cluster name>"
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Variable dsCluster set to $dsCluster"
            $pchkPassed = 1
            $buildStatus = "Running"
            $canDeploy = 1
            break
        } else {
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - Variable vCenterServer has not been set"
            $pchkPassed = 0
            $buildStatus = "Failed"
            $canDeploy = 0
            break
        }
    }

    '<country code>' { 
        if ($datacenter -like 'pdc') { 
            $vCenterServer = "<server name>"
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Variable vCenterServer set to $vCenterServer"
            $vmCluster = "<cluster name>"
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Variable vmCluster set to $vmCluster"
            $dsCluster = "<cluster name>"
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Variable dsCluster set to $dsCluster"
            $pchkPassed = 1
            $buildStatus = "Running"
            $canDeploy = 1
            break
        } elseif ($datacenter -like 'drc') {
            $vCenterServer = "<server name>"
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Variable vCenterServer set to $vCenterServer"
            $vmCluster = "<cluster name>"
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Variable vmCluster set to $vmCluster"
            $dsCluster = "<cluster name>"
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Variable dsCluster set to $dsCluster"
            $pchkPassed = 1
            $buildStatus = "Running"
            $canDeploy = 1
            break
        } else {
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - Variable vCenterServer has not been set"
            $pchkPassed = 0
            $buildStatus = "Failed"
            $canDeploy = 0
            break
        }
    }

    '<country code>' { 
        if ($datacenter -like 'pdc') { 
            $vCenterServer = "<server name>"
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Variable vCenterServer set to $vCenterServer"
            $vmCluster = "<cluster name>"
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Variable vmCluster set to $vmCluster"
            $dsCluster = "<cluster name>"
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Variable dsCluster set to $dsCluster"
            $pchkPassed = 1
            $buildStatus = "Running"
            $canDeploy = 1
            break
        } elseif ($datacenter -like 'drc') {
            $vCenterServer = "<server name>"
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Variable vCenterServer set to $vCenterServer"
            $vmCluster = "<cluster name>"
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Variable vmCluster set to $vmCluster"
            $dsCluster = "<cluster name>"
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Variable dsCluster set to $dsCluster"
            $pchkPassed = 1
            $buildStatus = "Running"
            $canDeploy = 1
            break
        } else {
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - Variable vCenterServer has not been set"
            $pchkPassed = 0
            $buildStatus = "Failed"
            $canDeploy = 0
            break
        }
    }

    '<country code>' { 
        if ($datacenter -like 'pdc') { 
            $vCenterServer = "<server name>"
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Variable vCenterServer set to $vCenterServer"
            $vmCluster = "<cluster name>"
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Variable vmCluster set to $vmCluster"
            $dsCluster = "<cluster name>"
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Variable dsCluster set to $dsCluster"
            $pchkPassed = 1
            $buildStatus = "Running"
            $canDeploy = 1
            break
        } elseif ($datacenter -like 'drc') {
            $vCenterServer = "<server name>"
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Variable vCenterServer set to $vCenterServer"
            $vmCluster = "<cluster name>"
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Variable vmCluster set to $vmCluster"
            $dsCluster = "searchWin"
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Variable dsCluster set to $dsCluster"
            $pchkPassed = 1
            $buildStatus = "Running"
            $canDeploy = 1
            break
        } else {
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - Variable vCenterServer has not been set"
            $pchkPassed = 0
            $buildStatus = "Failed"
            $canDeploy = 0
            break
        }
    }

    '<country code>' { 
        if ($datacenter -like 'pdc') { 
            $vCenterServer = "<server name>"
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Variable vCenterServer set to $vCenterServer"
            $vmCluster = "<cluster name>"
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Variable vmCluster set to $vmCluster"
            $dsCluster = "<cluster name>"
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Variable dsCluster set to $dsCluster"
            $pchkPassed = 1
            $buildStatus = "Running"
            $canDeploy = 1
            break
        } elseif ($datacenter -like 'drc') {
            $vCenterServer = "<server name>"
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Variable vCenterServer set to $vCenterServer"
            $vmCluster = "<cluster name>"
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Variable vmCluster set to $vmCluster"
            $dsCluster = "<cluster name>"
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Variable dsCluster set to $dsCluster"
            $pchkPassed = 1
            $buildStatus = "Running"
            $canDeploy = 1
            break
        } else {
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - Variable vCenterServer has not been set"
            $pchkPassed = 0
            $buildStatus = "Failed"
            $canDeploy = 0
            break
        }
    }

    '<country code>' { 
        if ($datacenter -like 'pdc') { 
            $vCenterServer = "<server name>"
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Variable vCenterServer set to $vCenterServer"
            $vmCluster = "<cluster name>"
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Variable vmCluster set to $vmCluster"
            $dsCluster = "searchWin"
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Variable dsCluster set to $dsCluster"
            $pchkPassed = 1
            $buildStatus = "Running"
            $canDeploy = 1
            break
        } elseif ($datacenter -like 'drc') {
            $vCenterServer = "<server name>"
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Variable vCenterServer set to $vCenterServer"
            $vmCluster = "<cluster name>"
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Variable vmCluster set to $vmCluster"
            $dsCluster = ""
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Variable dsCluster set to $dsCluster"
            $pchkPassed = 1
            $buildStatus = "Running"
            $canDeploy = 1
            break
        } else {
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - Variable vCenterServer has not been set"
            $pchkPassed = 0
            $buildStatus = "Failed"
            $canDeploy = 0
            break
        }
    }

    '<country code>' { 
        if ($datacenter -like 'pdc') { 
            $vCenterServer = "<server name>"
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Variable vCenterServer set to $vCenterServer"
            $vmCluster = "<cluster name>"
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Variable vmCluster set to $vmCluster"
            $dsCluster = "<cluster name>"
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Variable dsCluster set to $dsCluster"
            $pchkPassed = 1
            $buildStatus = "Running"
            $canDeploy = 1
            break
        } elseif ($datacenter -like 'drc') {
            $vCenterServer = "<server name>"
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Variable vCenterServer set to $vCenterServer"
            $vmCluster = "<cluster name>"
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Variable vmCluster set to $vmCluster"
            $dsCluster = "<cluster name>"
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Variable dsCluster set to $dsCluster"
            $pchkPassed = 1
            $buildStatus = "Running"
            $canDeploy = 1
            break
        } else {
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - Variable vCenterServer has not been set"
            $pchkPassed = 0
            $buildStatus = "Failed"
            $canDeploy = 0
            break
        }
    }

    Default {
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - Variable vCenterServer has not been set"
        $pchkPassed = 0
        $buildStatus = "Failed"
        $canDeploy = 0
        break
    }
}

Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Connecting to vCenter server $vCenterServer"
if ((Test-NetConnection -ComputerName $vCenterServer -Port 443).TcpTestSucceeded -eq $true) {
    $EncryptedPasswordToAccessVcenter = Get-Content -Path "$env:ProgramData\PowerBuild\eid.txt" | ConvertTo-SecureString
    $UserNameToAccessVcenter = '<user name>@<domain name>'
    if ($vCenterServer -like "<server name>") {
        $UserNameToAccessVcenter = '<user name>@<other domain name>'
    }
    $CredentialsToAccessVcenter = New-Object -TypeName System.Management.Automation.PSCredential($UserNameToAccessVcenter, $EncryptedPasswordToAccessVcenter)
    Connect-VIServer -Server $vCenterServer -Credential $CredentialsToAccessVcenter

    if ($global:DefaultVIServers.Length -eq 0) {
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - Connection to vCenter server $vCenterServer failed"
        $pchkPassed = 0
        $buildStatus = "Failed"
        $canDeploy = 0
        $vcAvailable = 0
    } else {
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Connection to vCenter server $vCenterServer succeeded"
        $pchkPassed = 1
        $buildStatus = "Running"
        $canDeploy = 1
        $vcAvailable = 1
    }
} else {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - Connection to vCenter server $vCenterServer failed"
    $pchkPassed = 0
    $buildStatus = "Failed"
    $canDeploy = 0
    $vcAvailable = 0
}

if (($pchkPassed -eq 0) -or ($buildStatus -like "Failed") -or ($canDeploy -eq 0) -or ($vcAvailable -eq 0)) {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - Check vCenter availablity did not meet conditions to continue"
    Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "precheck_passed", "build_status", "can_deploy", "vc_available" -NewValue $pchkPassed, $buildStatus, $canDeploy, $vcAvailable
    Get-PowerBuildLogFromDb -RequestNumber $requestNumber -StartDate $pbStartDate -StartTime $pbStartTime | Out-File -FilePath "$env:ProgramData\PowerBuild\Log\LogFromDb\$requestNumber-log_message.txt"
    Send-MailMessage @pbSendMailFailed -Attachments "$env:ProgramData\PowerBuild\Log\LogFromDb\$requestNumber-log_message.txt"
    exit
} else {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Check vCenter availablity meet conditions to continue"
    Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "precheck_passed", "build_status", "can_deploy", "vc_available" -NewValue $pchkPassed, $buildStatus, $canDeploy, $vcAvailable
}

## Check Virtual machine duplicity
Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Check Virtual machine duplicity"
if (Get-VM -Name $serverName -ErrorAction SilentlyContinue) {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - Virtual machine $serverName already exist"
    $pchkPassed = 0
    $buildStatus = "Failed"
    $canDeploy = 0
    $vmDuplicate = 1
} else {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - No virtual machine duplicity found"
    $pchkPassed = 1
    $buildStatus = "Running"
    $canDeploy = 1
    $vmDuplicate = 0
}

if (($pchkPassed -eq 0) -or ($buildStatus -like 'Failed') -or ($canDeploy -eq 0) -or ($vmDuplicate -eq 1)) {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber LogMessage "ERROR - Check Virtual machine duplicity did not meet conditions to continue"
    Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "precheck_passed", "build_status", "can_deploy", "vm_duplicate" -NewValue $pchkPassed, $buildStatus, $canDeploy, $vmDuplicate
    Disconnect-VIServer -Server $vCenterServer -Confirm:$false
    Get-PowerBuildLogFromDb -RequestNumber $requestNumber -StartDate $pbStartDate -StartTime $pbStartTime | Out-File -FilePath "$env:ProgramData\PowerBuild\Log\LogFromDb\$requestNumber-log_message.txt"
    Send-MailMessage @pbSendMailFailed -Attachments "$env:ProgramData\PowerBuild\Log\LogFromDb\$requestNumber-log_message.txt"
    exit
} else {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Check Virtual machine duplicity meet conditions to continue"
    Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "precheck_passed", "build_status", "can_deploy", "vm_duplicate" -NewValue $pchkPassed, $buildStatus, $canDeploy, $vmDuplicate
}

## Check VLAN availability
Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Check VLAN availability"
Get-Cluster -Name $vmCluster | Get-VMHost | ForEach-Object {
    if (Get-VMHost -Name $_.Name | Get-VDSwitch) {
        $vmHost = $_.Name
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Host $vmHost connected to distributed switch"
        if (Get-VMHost -Name $_.Name | Get-VDSwitch | Get-VDPortgroup | Where-Object {$PSItem.VlanConfiguration -like "VLAN $ipVlan"}) {
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Host $vmHost connected to vlan $ipVlan"
            $pchkPassed = 1
            $buildStatus = "Running"
            $canDeploy = 1
            $nwAvailable = 1
        } else {
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - Host $vmHost is not connected to vlan $ipVlan"
            $pchkPassed = 0
            $buildStatus = "Failed"
            $canDeploy = 0
            $nwAvailable = 0
        }
    } elseif (Get-VMHost -Name $_.Name | Get-VirtualSwitch) {
        $vmHost = $_.Name
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Host $vmHost connected to virtual switch"
        if (Get-VMHost -Name $_.Name | Get-VirtualSwitch | Get-VirtualPortgroup | Where-Object {$PSItem.VlanId -like $ipVlan}) {
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Host $vmHost connected to vlan $ipVlan"
            $pchkPassed = 1
            $buildStatus = "Running"
            $canDeploy = 1
            $nwAvailable = 1
        } else {
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - Host $vmHost is not connected to vlan $ipVlan"
            $pchkPassed = 0
            $buildStatus = "Failed"
            $canDeploy = 0
            $nwAvailable = 0
        }
    } else {
        $vmHost = $_.Name
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - Host $vmHost is not connected to any switch"
        $pchkPassed = 0
        $buildStatus = "Failed"
        $canDeploy = 0
        $nwAvailable = 0
    }
}

if (($pchkPassed -eq 0) -or ($buildStatus -like 'Failed') -or ($canDeploy -eq 0) -or ($nwAvailable -eq 0)) {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - Check VLAN availability did not meet conditions to continue"
    Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "precheck_passed", "build_status", "can_deploy", "nw_available" -NewValue $pchkPassed, $buildStatus, $canDeploy, $nwAvailable
    Disconnect-VIServer -Server $vCenterServer -Confirm:$false
    Get-PowerBuildLogFromDb -RequestNumber $requestNumber -StartDate $pbStartDate -StartTime $pbStartTime | Out-File -FilePath "$env:ProgramData\PowerBuild\Log\LogFromDb\$requestNumber-log_message.txt"
    Send-MailMessage @pbSendMailFailed -Attachments "$env:ProgramData\PowerBuild\Log\LogFromDb\$requestNumber-log_message.txt"
    exit
} else {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Check VLAN availability meet conditions to continue"
    Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "precheck_passed", "build_status", "can_deploy", "nw_available" -NewValue $pchkPassed, $buildStatus, $canDeploy, $nwAvailable
}

## Check Datastore availability
Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Check datastore availability"
$pchkPassed = 1
$buildStatus = "Running"
$canDeploy = 1
$dsAvailable = 0
$vmTotalDiskSize = 66 + $diskOne + $diskTwo + $diskThree + $diskFour + $diskFive + $diskSix
if ($dsCluster -like "") {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - No datastore found to deploy virtual machine"
    $pchkPassed = 0
    $buildStatus = "Failed"
    $canDeploy = 0
    $dsAvailable = 0
} elseif ($dsCluster -like 'searchWin') {
    $dsAvailable = 1
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "WARNING - No datastore cluster found to deploy virtual machine"
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Searching for datastore"
    $dsList = Get-Datastore | Where-Object {($_.Name -like "*WIN*") -and ($_.State -like 'Available') -and ($_.Accessible -eq $true) -and ((((($_.CapacityGB)-($_.FreespaceGB - $vmTotalDiskSize))*100)/$_.CapacityGB) -lt 85)} | Select-Object Name
    Get-Cluster -Name $vmCluster | Get-VMHost | ForEach-Object {
        $dsHostList = (Get-VMHost -Name $_ | Get-Datastore | Where-Object {$_.Name -like "*WIN*"}).Name
        foreach ($singleDs in $dsList) {
            $vmHost = $_.Name
            if ($dsHostList -contains $singleDs) {
                Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Host $vmHost connected to datastore $singleDs"
                $dsListAccessible.Add($singleDs)
            } else {
                Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - Host $vmHost is not connected to datastore $singleDs"
                $pchkPassed = 0
                $buildStatus = "Failed"
                $canDeploy = 0
                $dsAvailable = 0
            }   
        }
    }
} elseif (($dsCluster -notlike "") -and ($dsCluster -notlike 'searchWin')) {
    $dsAvailable = 1
    Get-Cluster -Name $vmCluster | Get-VMHost | ForEach-Object {
        $dsHostList = (Get-VMHost -Name $_.Name | Get-Datastore | Where-Object {$_.Name -like "*WIN*"}).Name
        foreach ($singleDs in $dsHostList) {
            $vmHost = $_.Name
            if (Get-DatastoreCluster -Name $dsCluster | Get-Datastore -Name $singleDs) {
                Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Host $vmHost connected to datastore $singleDs"
                if ($dsListAccessible -notcontains $singleDs) {
                    $dsListAccessible.Add($singleDs)
                }
            } else {
                Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "WARNING - Datastore $singleDs is not connected to datastore cluster $dsCluster"
            }   
        }
    }
} else {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - Search for datastore failed"
    $pchkPassed = 0
    $buildStatus = "Failed"
    $canDeploy = 0
    $dsAvailable = 0
}

if (($pchkPassed -eq 0) -or ($buildStatus -like 'Failed') -or ($canDeploy -eq 0) -or ($dsAvailable -eq 0)) {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - Check Datastore availability did not meet conditions to continue"
    Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "precheck_passed", "build_status", "can_deploy", "ds_available" -NewValue $pchkPassed, $buildStatus, $canDeploy, $dsAvailable
    Disconnect-VIServer -Server $vCenterServer -Confirm:$false
    Get-PowerBuildLogFromDb -RequestNumber $requestNumber -StartDate $pbStartDate -StartTime $pbStartTime | Out-File -FilePath "$env:ProgramData\PowerBuild\Log\LogFromDb\$requestNumber-log_message.txt"
    Send-MailMessage @pbSendMailFailed -Attachments "$env:ProgramData\PowerBuild\Log\LogFromDb\$requestNumber-log_message.txt"
    exit
} else {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Check Datastore availability meet conditions to continue"
    Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "precheck_passed", "build_status", "can_deploy", "ds_available" -NewValue $pchkPassed, $buildStatus, $canDeploy, $dsAvailable
}

## Check Template availability
Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Check template availability"
if ($os -like 'win2k12r2std') {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Searching for Windows Server 2012 R2 Standard template"
    if (Get-Template -Name '<template name>') {
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Template for Windows Server 2012 R2 Standard found"
        $vmTemplate = "<template name>"
        $pchkPassed = 1
        $buildStatus = "Running"
        $canDeploy = 1
        $tpAvailable = 1
    } else {
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - Template for Windows Server 2012 R2 Standard not found"
        $pchkPassed = 0
        $buildStatus = "Failed"
        $canDeploy = 0
        $tpAvailable = 0
    }
} elseif ($os -like 'win2k16std') {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Searching for Windows Server 2016 Standard template"
    if (Get-Template -Name '<template name>') {
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Template for Windows Server 2016 Standard found"
        $vmTemplate = "<template name>"
        $pchkPassed = 1
        $buildStatus = "Running"
        $canDeploy = 1
        $tpAvailable = 1
    } else {
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - Template for Windows Server 2016 Standard not found"
        $pchkPassed = 0
        $buildStatus = "Failed"
        $canDeploy = 0
        $tpAvailable = 0
    }
} else {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - Search for tempalte failed"
    $pchkPassed = 0
    $buildStatus = "Failed"
    $canDeploy = 0
    $tpAvailable = 0
}

if (($pchkPassed -eq 0) -or ($buildStatus -like 'Failed') -or ($canDeploy -eq 0) -or ($tpAvailable -eq 0)) {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - Check Template availability did not meet conditions to continue"
    Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "precheck_passed", "build_status", "can_deploy", "tp_available" -NewValue $pchkPassed, $buildStatus, $canDeploy, $tpAvailable
    Disconnect-VIServer -Server $vCenterServer -Confirm:$false
    Get-PowerBuildLogFromDb -RequestNumber $requestNumber -StartDate $pbStartDate -StartTime $pbStartTime | Out-File -FilePath "$env:ProgramData\PowerBuild\Log\LogFromDb\$requestNumber-log_message.txt"
    Send-MailMessage @pbSendMailFailed -Attachments "$env:ProgramData\PowerBuild\Log\LogFromDb\$requestNumber-log_message.txt"
    exit
} else {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Check Template availability meet conditions to continue"
    Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "precheck_passed", "build_status", "can_deploy", "tp_available" -NewValue $pchkPassed, $buildStatus, $canDeploy, $tpAvailable
}

## Check Customization availability
Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Check customization availability"
if ($os -like 'win2k12r2std') {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Searching for Windows Server 2012 R2 Standard customization"
    if (($domain -like 'domain') -and (Get-OSCustomizationSpec -Name '<customization name>')) {
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Domain customization for Windows Server 2012 R2 Standard found"
        $vmOc = "<customization name>"
        $pchkPassed = 1
        $buildStatus = "Running"
        $canDeploy = 1
        $ocAvailable = 1
    } elseif (($domain -like 'workgroup') -and (Get-OSCustomizationSpec -Name '<customization name>')) {
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Workgroup customization for Windows Server 2012 R2 Standard found"
        $vmOc = "<customization name>"
        $pchkPassed = 1
        $buildStatus = "Running"
        $canDeploy = 1
        $ocAvailable = 1
    }else {
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - Customization for Windows Server 2012 R2 Standard not found"
        $pchkPassed = 0
        $buildStatus = "Failed"
        $canDeploy = 0
        $ocAvailable = 0
    }
} elseif ($os -like 'win2k16std') {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Searching for Windows Server 2016 Standard customization"
    if (($domain -like 'domain') -and (Get-OSCustomizationSpec -Name '<customization name>')) {
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Domain customization for Windows Server 2016 Standard found"
        $vmOc = "<customization name>"
        $pchkPassed = 1
        $buildStatus = "Running"
        $canDeploy = 1
        $ocAvailable = 1
    } elseif (($domain -like 'workgroup') -and (Get-OSCustomizationSpec -Name '<customization name>')) {
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Workgroup customization for Windows Server 2016 Standard found"
        $vmOc = "<customization name>"
        $pchkPassed = 1
        $buildStatus = "Running"
        $canDeploy = 1
        $ocAvailable = 1
    }else {
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - Customization for Windows Server 2016 Standard not found"
        $pchkPassed = 0
        $buildStatus = "Failed"
        $canDeploy = 0
        $ocAvailable = 0
    }
} else {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - Search for customization failed"
    $pchkPassed = 0
    $buildStatus = "Failed"
    $canDeploy = 0
    $ocAvailable = 0
}

if (($pchkPassed -eq 0) -or ($buildStatus -like 'Failed') -or ($canDeploy -eq 0) -or ($ocAvailable -eq 0)) {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - Check Customization availability did not meet conditions to continue"
    Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "precheck_passed", "build_status", "can_deploy", "oc_available" -NewValue $pchkPassed, $buildStatus, $canDeploy, $ocAvailable
    Disconnect-VIServer -Server $vCenterServer -Confirm:$false
    Get-PowerBuildLogFromDb -RequestNumber $requestNumber -StartDate $pbStartDate -StartTime $pbStartTime | Out-File -FilePath "$env:ProgramData\PowerBuild\Log\LogFromDb\$requestNumber-log_message.txt"
    Send-MailMessage @pbSendMailFailed -Attachments "$env:ProgramData\PowerBuild\Log\LogFromDb\$requestNumber-log_message.txt"
    exit
} else {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Check Customization availability meet conditions to continue"
    Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "precheck_passed", "build_status", "can_deploy", "oc_available" -NewValue $pchkPassed, $buildStatus, $canDeploy, $ocAvailable
}

# Active Directory Checks
## Check Domain Controller availability
Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Check domain controller availability"
if ($domain -like 'domain') {
    foreach ($dnsServerIp in $dnsServerList) {
        if (Resolve-DnsName -Name $dnsServerIp -ErrorAction SilentlyContinue) {
            $dnsServer = (Resolve-DnsName -Name $dnsServerIp).NameHost
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Testing connection to $dnsServer"
            if (-not (Test-NetConnection -ComputerName $dnsServer -Port 9389 -ErrorAction SilentlyContinue).TcpTestSucceeded) {
                Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "WARNING - Connection to $dnsServer on port 9389 failed"
                $pchkPassed = 0
                $buildStatus = "Failed"
                $canDeploy = 0
                $adAvailable = 0
    
                if ($dnsListCounter -eq $dnsServerList.Length) {
                    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - No DNS server found"
                    $pchkPassed = 0
                    $buildStatus = "Failed"
                    $canDeploy = 0
                    $adAvailable = 0
                    break
                }
            } elseif ((Test-NetConnection -ComputerName $dnsServer -Port 9389 -ErrorAction SilentlyContinue).TcpTestSucceeded) {
                Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Connection to $dnsServer on port 9389 succeeded"
                $pchkPassed = 1
                $buildStatus = "Running"
                $canDeploy = 1
                $adAvailable = 1
                $adController = $dnsServer
                break
            } elseif ($dnsListCounter -eq $dnsServerList.Length) {
                Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - No DNS server found"
                $pchkPassed = 0
                $buildStatus = "Failed"
                $canDeploy = 0
                $adAvailable = 0
                break
            }
    
            $dnsListCounter++
        } else {
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "WARNING - DNS server $dnsServerIp not available"
            if ($dnsListCounter -eq $dnsServerList.Length) {
                Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - No DNS server found"
                $pchkPassed = 0
                $buildStatus = "Failed"
                $canDeploy = 0
                $adAvailable = 0
                break
            }
            
            $dnsListCounter++
        }
    }
} elseif ($domain -like 'workgroup') {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Server will be deployed as Workgroup"
    $pchkPassed = 1
    $buildStatus = "Running"
    $canDeploy = 1
    $adAvailable = 1
} else {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - Variable domain has unknown value $domain"
    $pchkPassed = 0
    $buildStatus = "Failed"
    $canDeploy = 0
    $adAvailable = 0
}

if (($pchkPassed -eq 0) -or ($buildStatus -like 'Failed') -or ($canDeploy -eq 0) -or ($adAvailable -eq 0)) {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - Check Domain Controller availability did not meet conditions to continue"
    Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "precheck_passed", "build_status", "can_deploy", "ad_available" -NewValue $pchkPassed, $buildStatus, $canDeploy, $adAvailable
    Disconnect-VIServer -Server $vCenterServer -Confirm:$false
    Get-PowerBuildLogFromDb -RequestNumber $requestNumber -StartDate $pbStartDate -StartTime $pbStartTime | Out-File -FilePath "$env:ProgramData\PowerBuild\Log\LogFromDb\$requestNumber-log_message.txt"
    Send-MailMessage @pbSendMailFailed -Attachments "$env:ProgramData\PowerBuild\Log\LogFromDb\$requestNumber-log_message.txt"
    exit
} else {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Check Domain Controller availability meet conditions to continue"
    Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "precheck_passed", "build_status", "can_deploy", "ad_available" -NewValue $pchkPassed, $buildStatus, $canDeploy, $adAvailable
}

## Check Computer object duplicity
Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Check computer account duplicity"
if ($serverName | Get-ADComputer -ErrorAction SilentlyContinue) {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - Computer account duplicity for $serverName found"
    $pchkPassed = 0
    $buildStatus = "Failed"
    $canDeploy = 0
    $caDuplicate = 1
} else {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Computer account duplicity for $serverName not found"
    $pchkPassed = 1
    $buildStatus = "Running"
    $canDeploy = 1
    $caDuplicate = 0
}

if (($pchkPassed -eq 0) -or ($buildStatus -like 'Failed') -or ($canDeploy -eq 0) -or ($caDuplicate -eq 1)) {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - Check Computer account duplicity did not meet conditions to continue"
    Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "precheck_passed", "build_status", "can_deploy", "ca_duplicate" -NewValue $pchkPassed, $buildStatus, $canDeploy, $caDuplicate
    Disconnect-VIServer -Server $vCenterServer -Confirm:$false
    Get-PowerBuildLogFromDb -RequestNumber $requestNumber -StartDate $pbStartDate -StartTime $pbStartTime | Out-File -FilePath "$env:ProgramData\PowerBuild\Log\LogFromDb\$requestNumber-log_message.txt"
    Send-MailMessage @pbSendMailFailed -Attachments "$env:ProgramData\PowerBuild\Log\LogFromDb\$requestNumber-log_message.txt"
    exit
} else {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Check Computer account duplicity meet conditions to continue"
    Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "precheck_passed", "build_status", "can_deploy", "ca_duplicate" -NewValue $pchkPassed, $buildStatus, $canDeploy, $caDuplicate
}

## Check Organization unit availability
#TODO missing check

# Other Checks
## Check IP duplicity
Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Check IP address duplicity"
if (Test-Connection -ComputerName $ipAddress -ErrorAction SilentlyContinue) {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - IP address $ipAddress responds to PING"
    $pchkPassed = 0
    $buildStatus = "Failed"
    $canDeploy = 0
    $ipDuplicate = 1
} else {
    $pchkPassed = 1
    $buildStatus = "Running"
    $canDeploy = 1
    $ipDuplicate = 0
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - IP address $ipAddress is available"
}

if (($pchkPassed -eq 0) -or ($buildStatus -like 'Failed') -or ($canDeploy -eq 0) -or ($ipDuplicate -eq 1)) {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - Check IP duplicity did not meet conditions to continue"
    Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "precheck_passed", "build_status", "can_deploy", "ip_duplicate" -NewValue $pchkPassed, $buildStatus, $canDeploy, $ipDuplicate
    Disconnect-VIServer -Server $vCenterServer -Confirm:$false
    Get-PowerBuildLogFromDb -RequestNumber $requestNumber -StartDate $pbStartDate -StartTime $pbStartTime | Out-File -FilePath "$env:ProgramData\PowerBuild\Log\LogFromDb\$requestNumber-log_message.txt"
    Send-MailMessage @pbSendMailFailed -Attachments "$env:ProgramData\PowerBuild\Log\LogFromDb\$requestNumber-log_message.txt"
    exit
} else {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Check IP duplicity meet conditions to continue"
    Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "precheck_passed", "build_status", "can_deploy", "ip_duplicate" -NewValue $pchkPassed, $buildStatus, $canDeploy, $ipDuplicate
}

# All checks passed
if (($pchkPassed -eq 0) -or ($buildStatus -like 'Failed') -or ($canDeploy -eq 0)) {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - All checks did not meet conditions to continue"
    Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "precheck_passed", "build_status", "can_deploy" -NewValue $pchkPassed, $buildStatus, $canDeploy
    Disconnect-VIServer -Server $vCenterServer -Confirm:$false
    Get-PowerBuildLogFromDb -RequestNumber $requestNumber -StartDate $pbStartDate -StartTime $pbStartTime | Out-File -FilePath "$env:ProgramData\PowerBuild\Log\LogFromDb\$requestNumber-log_message.txt"
    Send-MailMessage @pbSendMailFailed -Attachments "$env:ProgramData\PowerBuild\Log\LogFromDb\$requestNumber-log_message.txt"
    exit
} else {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - All checks meet conditions to continue"
    $pchkPassed = 1
    $buildStatus = "Ready"
    $canDeploy = 1
    Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "precheck_passed", "build_status", "can_deploy" -NewValue $pchkPassed, $buildStatus, $canDeploy
}


# Build
## Active Directory Build
if ($domain -like 'domain') {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Creating computer account in Active Directory"
    $userNameAdSa = '<domain>\<user name>'
    $encryptedPasswordToCreateComputerObj = Get-Content -Path "$env:ProgramData\PowerBuild\adsa.txt" | ConvertTo-SecureString
    $credentialsToAd = New-Object -TypeName System.Management.Automation.PSCredential($userNameAdSa, $encryptedPasswordToCreateComputerObj)
    New-ADComputer -Name $serverName.ToUpper() -SAMAccountName $serverName -Description $requestNumber -Credential $credentialsToAd -Path "OU=$serverTier,OU=$country,DC=<domain>,DC=<domain>,DC=<domain>" -Server $adController
    Start-Sleep -Seconds 5

    if ($serverName | Get-ADComputer -Server $adController -ErrorAction SilentlyContinue) {
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Computer account $serverName created"
        $pchkPassed = 1
        $buildStatus = "Running"
        $canDeploy = 1
        $caExist = 1

        $caLocation = (Test-AdComputerLocation -ComputerName $serverName -DomainController $adController).Location
        Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "ca_location" -NewValue $caLocation
    } else {
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - Computer account $serverName not created"
        $pchkPassed = 1
        $buildStatus = "Failed"
        $canDeploy = 0
        $caExist = 0
    }

} elseif ($domain -like 'workgroup') {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Server $serverName will be deployed as Workgroup"
    $pchkPassed = 1
    $buildStatus = "Running"
    $canDeploy = 1
    $caExist = 1
} else {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - Variable domain has unknown value $domain"
    $pchkPassed = 1
    $buildStatus = "Failed"
    $canDeploy = 0
    $caExist = 0
}

if (($pchkPassed -eq 0) -or ($buildStatus -like 'Failed') -or ($canDeploy -eq 0) -or ($caExist -eq 0)) {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - Active Directory build did not meet conditions to continue"
    Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "precheck_passed", "build_status", "can_deploy", "ca_exist" -NewValue $pchkPassed, $buildStatus, $canDeploy, $caExist
    Disconnect-VIServer -Server $vCenterServer -Confirm:$false
    Get-PowerBuildLogFromDb -RequestNumber $requestNumber -StartDate $pbStartDate -StartTime $pbStartTime | Out-File -FilePath "$env:ProgramData\PowerBuild\Log\LogFromDb\$requestNumber-log_message.txt"
    Send-MailMessage @pbSendMailFailed -Attachments "$env:ProgramData\PowerBuild\Log\LogFromDb\$requestNumber-log_message.txt"
    exit
} else {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Active Directory build meet conditions to continue"
    $pchkPassed = 1
    $buildStatus = "Ready"
    $canDeploy = 1
    Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "precheck_passed", "build_status", "can_deploy" -NewValue $pchkPassed, $buildStatus, $canDeploy
}

## Vmware Build
Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Getting ESXi host for deployment"
$vmHost = $null
$vmHost = Get-Cluster -Name $vmCluster | Get-VMHost | Where-Object {($_.ConnectionState -like 'Connected') -and ($_.PowerState -like 'PoweredOn')} | Sort-Object -Property MemoryUsageMB -Descending | Select-Object -First 1
if ($vmHost -eq 0) {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - No ESXi host for deployment found"
    $pchkPassed = 1
    $buildStatus = "Failed"
    $canDeploy = 0
    $vmHostStatus = 0
    Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "vm_host" -NewValue "n/a"
} else {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Selected ESXi host $vmHost"
    $pchkPassed = 1
    $buildStatus = "Running"
    $canDeploy = 1
    $vmHostStatus = 1
    Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "vm_host" -NewValue $vmHost
}

Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Getting datastore for deployment"
$vmDatastore = $null
$vmDatastore = Get-Datastore -Name $dsListAccessible | Sort-Object -Descending -Property FreeSpaceGB | Select-Object -First 1
if ($vmDatastore -eq 0) {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - No datastore for deployment found"
    $pchkPassed = 1
    $buildStatus = "Failed"
    $canDeploy = 0
    $vmDatastoreStatus = 0
    Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "vm_datastore" -NewValue "n/a"
} else {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Selected datastore $vmDatastore"
    $pchkPassed = 1
    $buildStatus = "Running"
    $canDeploy = 1
    $vmDatastoreStatus = 1
    Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "vm_datastore" -NewValue $vmDatastore
}

Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Setting virtual machine folder"
if ($environment -like "prod") {
    if (Get-Folder -Name "win-prod") {
        $vmFolder = "win-prod"
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Virtual machine folder set to $vmFolder"
        Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "vm_folder" -NewValue $vmFolder
    } else {
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "WARNING - Could not find virtual machine folder $vmFolder"
        $vmFolder = "Discovered virtual machine"
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Virtual machine folder set to $vmFolder"
        Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "vm_folder" -NewValue $vmFolder
    }
} elseif ($environment -like "non-prod") {
    if (Get-Folder -Name "win-nonprod") {
        $vmFolder = "win-nonprod"
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Virtual machine folder set to $vmFolder"
        Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "vm_folder" -NewValue $vmFolder
    } else {
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "WARNING - Could not find virtual machine folder $vmFolder"
        $vmFolder = "Discovered virtual machine"
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Virtual machine folder set to $vmFolder"
        Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "vm_folder" -NewValue $vmFolder
    }
} else {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - Variable environment has unknown value $environment"
    $vmFolder = "Discovered virtual machine"
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "WARNING - Virtual machine folder set to $vmFolder"
    Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "vm_folder" -NewValue $vmFolder
}

Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Getting virtual machine template for deployment"
if ($vmTemplate -eq 0) {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - No virtual machine template for deployment found"
    $pchkPassed = 1
    $buildStatus = "Failed"
    $canDeploy = 0
    $vmTemplateStatus = 0
    Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "vm_template" -NewValue "n/a"
} else {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Selected VM template $vmTemplate"
    $pchkPassed = 1
    $buildStatus = "Running"
    $canDeploy = 1
    $vmTemplateStatus = 1
    Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "vm_template" -NewValue $vmTemplate
}

Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Creating OS Customization copy for deployment"
$vmOcCopy = Get-OSCustomizationSpec -Name $vmOc | New-OSCustomizationSpec -Name "$vmOc-$serverName"
if ($vmOcCopy -eq 0) {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - OS Customization has not been created"
    $pchkPassed = 1
    $buildStatus = "Failed"
    $canDeploy = 0
    $vmOcCopyStatus = 0
    Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "vm_oc_copy" -NewValue "n/a"
} else {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - OS Customization $vmOcCopy copy has been created"
    $pchkPassed = 1
    $buildStatus = "Running"
    $canDeploy = 1
    $vmOcCopyStatus = 1
    Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "vm_oc_copy" -NewValue $vmOcCopy
}

Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Setting OS customization network properties"
Get-OSCustomizationSpec $vmOcCopy | Get-OSCustomizationNicMapping | Set-OSCustomizationNicMapping -IpMode UseStaticIP -IpAddress $ipAddress -SubnetMask $ipMask -DefaultGateway $ipGateway -Dns $ipDnsOne, $ipDnsTwo
if (((Get-OSCustomizationNicMapping -OSCustomizationSpec $vmOcCopy).IPAddress -like $ipAddress) -and `
    ((Get-OSCustomizationNicMapping -OSCustomizationSpec $vmOcCopy).SubnetMask -like $ipMask) -and `
    ((Get-OSCustomizationNicMapping -OSCustomizationSpec $vmOcCopy).DefaultGateway -like $ipGateway) -and `
    ((Get-OSCustomizationNicMapping -OSCustomizationSpec $vmOcCopy).dns[0] -like $ipDnsOne) -and `
    ((Get-OSCustomizationNicMapping -OSCustomizationSpec $vmOcCopy).dns[1] -like $ipDnsTwo) -and `
    ((Get-OSCustomizationNicMapping -OSCustomizationSpec $vmOcCopy).IPMode -like 'UseStaticIP')) {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - OS customization network properties are set"
    $pchkPassed = 1
    $buildStatus = "Running"
    $canDeploy = 1
    $vmOcNwstatus = 1
} else {
    $pchkPassed = 1
    $buildStatus = "Failed"
    $canDeploy = 0
    $vmOcNwstatus = 0
}

if (($pchkPassed -eq 0) -or ($buildStatus -like 'Failed') -or ($canDeploy -eq 0) -or ($vmHostStatus -eq 0) -or ($vmDatastoreStatus -eq 0) -or ($vmTemplateStatus -eq 0) -or ($vmOcCopyStatus -eq 0) -or ($vmOcNwstatus -eq 0)) {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - Vmware build did not meet conditions to continue"
    Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "precheck_passed", "build_status", "can_deploy", "vm_host_status", "vm_datastore_status", "vm_template_status", "vm_oc_copy_status", "vm_oc_nw_status" -NewValue $pchkPassed, $buildStatus, $canDeploy, $vmHostStatus, $vmDatastoreStatus, $vmTemplateStatus, $vmOcCopyStatus, $vmOcCopyStatus 
    
    Get-OSCustomizationSpec -Name $vmOcCopy | Remove-OSCustomizationSpec -Confirm:$false
    if(Get-OSCustomizationSpec -Name $vmOcCopy -ErrorAction SilentlyContinue) {
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - OS Customization $vmOcCopy copy has not been deleted"
    } else {
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - OS Customization $vmOcCopy copy has been deleted"
    }
    Disconnect-VIServer -Server $vCenterServer -Confirm:$false

    if ($domain -like 'domain') {
        Remove-ADComputer -Identity $serverName -Credential $credentialsToAd -Server $adController -Confirm:$false
        if ($serverName | Get-ADComputer -Server $adController -ErrorAction SilentlyContinue) {
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - Active Directory account $serverName has not been deleted"
        } else {
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Active Directory account $serverName has been deleted"
        }
    }    

    Get-PowerBuildLogFromDb -RequestNumber $requestNumber -StartDate $pbStartDate -StartTime $pbStartTime | Out-File -FilePath "$env:ProgramData\PowerBuild\Log\LogFromDb\$requestNumber-log_message.txt"
    Send-MailMessage @pbSendMailFailed -Attachments "$env:ProgramData\PowerBuild\Log\LogFromDb\$requestNumber-log_message.txt"
    exit
} else {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Vmware build meet conditions to continue"
    $pchkPassed = 1
    $buildStatus = "Ready"
    $canDeploy = 1
    Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "precheck_passed", "build_status", "can_deploy", "vm_host_status", "vm_datastore_status", "vm_template_status", "vm_oc_copy_status", "vm_oc_nw_status" -NewValue $pchkPassed, $buildStatus, $canDeploy, $vmHostStatus, $vmDatastoreStatus, $vmTemplateStatus, $vmOcCopyStatus, $vmOcCopyStatus
}

## Deploying virtual machine
Start-Sleep -Seconds 15
Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Deploying virtual machine"
New-VM -Name $serverName -Template $vmTemplate -ResourcePool $vmHost -Location $vmFolder -Datastore $vmDatastore -DiskStorageFormat EagerZeroedThick -OSCustomizationSpec $vmOcCopy

$deploymentCounter = 0
do {
    $pchkPassed = 1
    $buildStatus = "Running"
    Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "build_status" -NewValue $buildStatus
    $canDeploy = 1
    $buildPassed = 1
    $vmExist = 1

    Start-Sleep -Seconds 30

    if ($deploymentCounter -eq 10) {
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - Virtual machine deployment counter exceeded limit"
        $pchkPassed = 1
        $buildStatus = "Failed"
        $canDeploy = 0
        $buildPassed = 0
        $vmExist = 0
        break
    }

    $deploymentCounter++
} until (Get-VM -Name $serverName -ErrorAction SilentlyContinue)

if (($pchkPassed -eq 0) -or ($buildStatus -like 'Failed') -or ($canDeploy -eq 0) -or ($buildPassed -eq 0) -or ($vmExist -eq 0)) {
    Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "precheck_passed", "build_status", "can_deploy", "build_passed", "vm_exist" -NewValue $pchkPassed, $buildStatus, $canDeploy, $buildPassed,$vmExist
    
    Get-OSCustomizationSpec -Name $vmOcCopy | Remove-OSCustomizationSpec -Confirm:$false
    if(Get-OSCustomizationSpec -Name $vmOcCopy -ErrorAction SilentlyContinue) {
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - OS Customization $vmOcCopy copy has not been deleted"
    } else {
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - OS Customization $vmOcCopy copy has been deleted"
    }
    Disconnect-VIServer -Server $vCenterServer -Confirm:$false

    if ($domain -like 'domain') {
        Remove-ADComputer -Identity $serverName -Credential $credentialsToAd -Server $adController -Confirm:$false
        if ($serverName | Get-ADComputer -Server $adController -ErrorAction SilentlyContinue) {
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - Active Directory account $serverName has not been deleted"
        } else {
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Active Directory account $serverName has been deleted"
        }
    }

    Get-PowerBuildLogFromDb -RequestNumber $requestNumber -StartDate $pbStartDate -StartTime $pbStartTime | Out-File -FilePath "$env:ProgramData\PowerBuild\Log\LogFromDb\$requestNumber-log_message.txt"
    Send-MailMessage @pbSendMailFailed -Attachments "$env:ProgramData\PowerBuild\Log\LogFromDb\$requestNumber-log_message.txt"
    exit
} else {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Virtual machine deployment meet conditions to continue"
    $pchkPassed = 1
    $buildStatus = "Ready"
    $canDeploy = 1
    $buildPassed = 1
    Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "precheck_passed", "build_status", "can_deploy", "build_passed", "vm_exist" -NewValue $pchkPassed, $buildStatus, $canDeploy, $buildPassed, $vmExist
}

## Configuring virtual machine
Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Configuring virtual machine"
switch ($cpu) {
    1 {
        Get-VM -Name $serverName | Set-VM -NumCpu 1 -CoresPerSocket 1 -Confirm:$false
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Number of CPUs set to $cpu"
        break
    }
    2 {
        Get-VM -Name $serverName | Set-VM -NumCpu 2 -CoresPerSocket 2 -Confirm:$false
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Number of CPUs set to $cpu"
        break
    }
    3 {
        Get-VM -Name $serverName | Set-VM -NumCpu 3 -CoresPerSocket 3 -Confirm:$false
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Number of CPUs set to $cpu"
        break
    }
    4 {
        Get-VM -Name $serverName | Set-VM -NumCpu 4 -CoresPerSocket 4 -Confirm:$false
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Number of CPUs set to $cpu"
        break
    }
    5 {
        Get-VM -Name $serverName | Set-VM -NumCpu 5 -CoresPerSocket 5 -Confirm:$false
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Number of CPUs set to $cpu"
        break
    }
    6 {
        Get-VM -Name $serverName | Set-VM -NumCpu 6 -CoresPerSocket 6 -Confirm:$false
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Number of CPUs set to $cpu"
        break
    }
    7 {
        Get-VM -Name $serverName | Set-VM -NumCpu 7 -CoresPerSocket 7 -Confirm:$false
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Number of CPUs set to $cpu"
        break
    }
    8 {
        Get-VM -Name $serverName | Set-VM -NumCpu 8 -CoresPerSocket 8 -Confirm:$false
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Number of CPUs set to $cpu"
        break
    }
    9 {
        Get-VM -Name $serverName | Set-VM -NumCpu 9 -CoresPerSocket 9 -Confirm:$false
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Number of CPUs set to $cpu"
        break
    }
    10 {
        Get-VM -Name $serverName | Set-VM -NumCpu 10 -CoresPerSocket 10 -Confirm:$false
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Number of CPUs set to $cpu"
        break
    }
    11 {
        Get-VM -Name $serverName | Set-VM -NumCpu 10 -CoresPerSocket 10 -Confirm:$false
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "WARNING - $cpu CPUs cannot be set, CPUs set to 10"
        break
    }
    12 {
        Get-VM -Name $serverName | Set-VM -NumCpu 12 -CoresPerSocket 6 -Confirm:$false
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Number of CPUs set to $cpu"
        break
    }
    13 {
        Get-VM -Name $serverName | Set-VM -NumCpu 12 -CoresPerSocket 6 -Confirm:$false
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "WARNING - $cpu CPUs cannot be set, CPUs set to 12"
        break
    }
    14 {
        Get-VM -Name $serverName | Set-VM -NumCpu 14 -CoresPerSocket 7 -Confirm:$false
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Number of CPUs set to $cpu"
        break
    }
    15 {
        Get-VM -Name $serverName | Set-VM -NumCpu 14 -CoresPerSocket 7 -Confirm:$false
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "WARNING - $cpu CPUs cannot be set, CPUs set to 14"
        break
    }
    16 {
        Get-VM -Name $serverName | Set-VM -NumCpu 16 -CoresPerSocket 8 -Confirm:$false
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Number of CPUs set to $cpu"
        break
    }
    17 {
        Get-VM -Name $serverName | Set-VM -NumCpu 16 -CoresPerSocket 8 -Confirm:$false
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "WARNING - $cpu CPUs cannot be set, CPUs set to 16"
        break
    }
    18 {
        Get-VM -Name $serverName | Set-VM -NumCpu 18 -CoresPerSocket 9 -Confirm:$false
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Number of CPUs set to $cpu"
        break
    }
    19 {
        Get-VM -Name $serverName | Set-VM -NumCpu 18 -CoresPerSocket 9 -Confirm:$false
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "WARNING - $cpu CPUs cannot be set, CPUs set to 18"
        break
    }
    20 {
        Get-VM -Name $serverName | Set-VM -NumCpu 20 -CoresPerSocket 10 -Confirm:$false
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Number of CPUs set to $cpu"
        break
    }
    { $NewVMNumCPU -gt 20 } {
        Get-VM -Name $serverName | Set-VM -NumCpu 4 -CoresPerSocket 4 -Confirm:$false
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "WARNING - Number of CPUs cannot be more than 20, setting to default 4"
        break
    }
    Default {
        Get-VM -Name $serverName | Set-VM -NumCpu 4 -CoresPerSocket 4 -Confirm:$false
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "WARNING - Unknown number of CPUs, setting to default 4"
        break
    }
}

Get-VM -Name $serverName | Set-VM -MemoryGB $memory -Confirm:$false
Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Memory set to $memory GB"

$diskNumber = 1
for ($i = 0; $i -lt $vmDiskList.Count; $i++) {
    if ($vmDiskList[$i] -eq 0) {
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Disk $diskNumber size is 0 GB, disk will not be configured"
    } elseif ($vmDiskList[$i] -lt 1) {
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "WARNING - Disk $diskNumber size is less than 1 GB, disk will not be configured"
    } elseif ($vmDiskList[$i] -gt 500) {
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "WARNING - Disk $diskNumber size is more than 500 GB, disk will not be configured"
    } elseif (($vmDiskList[$i] -ge 1) -and ($vmDiskList[$i] -le 500)) {
        $vmDisk = $vmDiskList[$i]
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Disk $diskNumber size is $vmDisk GB, configuring disk"
        Get-VM -Name $serverName | New-HardDisk -Persistence Persistent -DiskType Flat -CapacityGB $vmDisk -StorageFormat EagerZeroedThick
    }
    $diskNumber++
}

if (Get-VM -Name $serverName | Get-VMHost | Get-VDSwitch | Get-VDPortgroup | Where-Object {$PSItem.VlanConfiguration -like "VLAN $ipVlan"}) {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Connecting virtual machine to distributed switch"
    $vmVlanName = Get-VM -Name $serverName | Get-VMHost | Get-VDSwitch | Get-VDPortgroup | Where-Object {$PSItem.VlanConfiguration -like "VLAN $ipVlan"} | Select-Object -ExpandProperty Name
    Get-VM -Name $serverName | Get-NetworkAdapter | Set-NetworkAdapter -Portgroup $vmVlanName -Confirm:$false
    Get-VM -Name $serverName | Get-NetworkAdapter | Set-NetworkAdapter -StartConnected:$true -Confirm:$false
    Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "vm_vlan_name" -NewValue $vmVlanName
    $pchkPassed = 1
    $buildStatus = "Running"
    $canDeploy = 1
    $buildPassed = 1
} elseif (Get-VM -Name $serverName | Get-VMHost | Get-VirtualSwitch | Get-VirtualPortgroup | Where-Object {$PSItem.VlanId -like $ipVlan}) {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Connecting virtual machine to vSwitch"
    $vmVlanName =  Get-VM -Name $serverName | Get-VMHost | Get-VirtualSwitch | Get-VirtualPortgroup | Where-Object {$PSItem.VlanId -like $ipVlan} | Select-Object -ExpandProperty Name
    Get-VM -Name $serverName | Get-NetworkAdapter | Set-NetworkAdapter -NetworkName $vmVlanName -StartConnected $true -Confirm:$false
    Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "vm_vlan_name" -NewValue $vmVlanName
    $pchkPassed = 1
    $buildStatus = "Running"
    $canDeploy = 1
    $buildPassed = 1
}else {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - Host $vmHost does not have any switch configured"
    $pchkPassed = 1
    $buildStatus = "Failed"
    $canDeploy = 0
    $buildPassed = 0
}

Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Setting virtual machine notes"
$vmNotes = "Name: $serverName `nSupport request: $requestNumber `nPurpose: $appName"
Set-VM -VM $serverName -Notes $vmNotes -Confirm:$false

Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Powering on virtual machine"
Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Virtual machine customization in progress"
$buildStatus = "Waiting"
Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "build_status" -NewValue $buildStatus
Get-VM -Name $serverName | Start-VM
$customizationCounter = 0
do {
    $serverNameCustomizationStatus = $null
    $serverNameGuestState = $null
    # $serverNameVMToolsStatus = $null
    $serverNameHeartBeatStatus = $null
    $serverNameOverallStatus = $null
    
    $pchkPassed = 1
    $buildStatus = "Running"
    Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "build_status" -NewValue $buildStatus
    $canDeploy = 1
    $buildPassed = 1

    Start-Sleep -Seconds 30
    
    $serverNameCustomizationStatus = (Get-VM -Name $serverName | Get-VIEvent | Where-Object {$_.FullFormattedMessage -match 'succeeded'})
    $serverNameGuestState = (Get-VM -Name $serverName | Get-View).Guest.GuestState
    # $serverNameVMToolsStatus = (Get-VM -Name $serverName | Get-View).Guest.ToolsStatus
    $serverNameHeartBeatStatus = (Get-VM -Name $serverName | Get-View).GuestHeartbeatStatus
    $serverNameOverallStatus = (Get-VM -Name $serverName | Get-View).OverallStatus
    if ($customizationCounter -eq 10) {
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - Virtual machine customization counter exceeded limit"
        $pchkPassed = 1
        $buildStatus = "Failed"
        $canDeploy = 1
        $buildPassed = 0
        break
    }

    $customizationCounter++
} until (($serverNameCustomizationStatus -match 'succeeded') -and `
        ($serverNameGuestState -like 'running') -and `
        ($serverNameHeartBeatStatus -like 'green') -and `
        ($serverNameOverallStatus -like 'green'))


if (($pchkPassed -eq 0) -or ($buildStatus -like 'Failed') -or ($canDeploy -eq 0) -or ($buildPassed -eq 0)) {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERORR - Virtual machine deployement failed"
    Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "precheck_passed", "build_status", "can_deploy", "build_passed" -NewValue $pchkPassed, $buildStatus, $canDeploy, $buildPassed
    
    Get-OSCustomizationSpec -Name $vmOcCopy | Remove-OSCustomizationSpec -Confirm:$false
    if(Get-OSCustomizationSpec -Name $vmOcCopy -ErrorAction SilentlyContinue) {
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - OS Customization $vmOcCopy copy has not been deleted"
    } else {
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - OS Customization $vmOcCopy copy has been deleted"
    }

    $powerOffCounter = 0
    Get-VM -Name $serverName | Stop-VM -Confirm:$false
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Powering off $serverName in progress"
    do {
        Start-Sleep -Seconds 5

        if ($powerOffCounter -eq 12) {
            break
        }
        
        $powerOffCounter++
    } until ((Get-VM -Name $serverName).PowerState -like 'PoweredOff')

    if ($powerOffCounter -eq 12) {
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - Power off $serverName operation failed"
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "WARNING - Remove virtual machine $serverName manualy"
    } else {
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Power off $serverName operation completed"
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Removing virtual machine $serverName"
        Remove-VM -VM $serverName -DeletePermanently -Confirm:$false
        if (Get-VM -Name $serverName -ErrorAction SilentlyContinue) {
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - Remove virtual machine $serverName operation failed"
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "WARNING - Remove virtual machine $serverName manualy"
        } else {
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Virtual machine $serverName has been removed"
        }
    }
    Disconnect-VIServer -Server $vCenterServer -Confirm:$false

    if ($domain -like 'domain') {
        Remove-ADComputer -Identity $serverName -Credential $credentialsToAd -Server $adController -Confirm:$false
        if ($serverName | Get-ADComputer -Server $adController -ErrorAction SilentlyContinue) {
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - Active Directory account $serverName has not been deleted"
        } else {
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Active Directory account $serverName has been deleted"
        }
    }

    Get-PowerBuildLogFromDb -RequestNumber $requestNumber -StartDate $pbStartDate -StartTime $pbStartTime | Out-File -FilePath "$env:ProgramData\PowerBuild\Log\LogFromDb\$requestNumber-log_message.txt"
    Send-MailMessage @pbSendMailFailed -Attachments "$env:ProgramData\PowerBuild\Log\LogFromDb\$requestNumber-log_message.txt"
    exit
} else {
    Get-OSCustomizationSpec -Name $vmOcCopy | Remove-OSCustomizationSpec -Confirm:$false
    if(Get-OSCustomizationSpec -Name $vmOcCopy -ErrorAction SilentlyContinue) {
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "WARNING - OS Customization $vmOcCopy copy has not been deleted"
    } else {
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - OS Customization $vmOcCopy copy has been deleted"
    }

    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Disconnecting from vCenter server $vCenterServer"
    Disconnect-VIServer -Server $vCenterServer -Confirm:$false
    $buildStatus = "Completed"
    Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "build_status" -NewValue $buildStatus
}

# Scope process start
#TODO Add check if port 445 is available
if ($domain -like 'domain') {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Scope of $serverName started"
    
    $pingCounter = 0
    do {
        Start-Sleep -Seconds 30

        if ($pingCounter -eq 10) {
            break
        }
        $pingCounter++
    } until ((Test-NetConnection -ComputerName $serverName).PingSucceeded -eq $true)
    
    if ((Test-NetConnection -ComputerName $serverName -Port 5985).TcpTestSucceeded -eq $true) {
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - WinRM accessible"
        $scopeStatus = "Ready"
        $canDeploy = 1
        Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "scope_status", "can_deploy" -NewValue $scopeStatus, $canDeploy
    } else {
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - WinRM is not accessible"
        $scopeStatus = "Failed"
        $canDeploy = 0
        Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "scope_status", "can_deploy" -NewValue $scopeStatus, $canDeploy
        Get-PowerBuildLogFromDb -RequestNumber $requestNumber -StartDate $pbStartDate -StartTime $pbStartTime | Out-File -FilePath "$env:ProgramData\PowerBuild\Log\LogFromDb\$requestNumber-log_message.txt"
        Send-MailMessage @pbSendMailFailed -Attachments "$env:ProgramData\PowerBuild\Log\LogFromDb\$requestNumber-log_message.txt"
        exit
    }

} elseif ($domain -like 'workgroup') {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Server $serverName deployed as workgroup"
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Virtual machine deployment successfully completed"
    $scopeStatus = "Completed"
    $canDeploy = 1
    Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "scope_status", "can_deploy" -NewValue $scopeStatus, $canDeploy

    Move-Item -Path "$env:ProgramData\PowerBuild\JsonTemplate\$NewServerName.json" -Destination "$env:ProgramData\PowerBuild\JsonTemplate\Archive"
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Server JSON template has been moved to Archive folder"
    Get-PowerBuildLogFromDb -RequestNumber $requestNumber -StartDate $pbStartDate -StartTime $pbStartTime | Out-File -FilePath "$env:ProgramData\PowerBuild\Log\LogFromDb\$requestNumber-log_message.txt"
    Send-MailMessage @pbSendMailPassed -Attachments "$env:ProgramData\PowerBuild\Log\LogFromDb\$requestNumber-log_message.txt"
    exit
} else {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "WARNING - Variable domain has unknown value $domain"
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Virtual machine deployment successfully completed"
    $scopeStatus = "Completed"
    $canDeploy = 1
    Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "scope_status", "can_deploy" -NewValue $scopeStatus, $canDeploy

    Move-Item -Path "$env:ProgramData\PowerBuild\JsonTemplate\$NewServerName.json" -Destination "$env:ProgramData\PowerBuild\JsonTemplate\Archive"
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Server JSON template has been moved to Archive folder"
    Get-PowerBuildLogFromDb -RequestNumber $requestNumber -StartDate $pbStartDate -StartTime $pbStartTime | Out-File -FilePath "$env:ProgramData\PowerBuild\Log\LogFromDb\$requestNumber-log_message.txt"
    Send-MailMessage @pbSendMailPassed -Attachments "$env:ProgramData\PowerBuild\Log\LogFromDb\$requestNumber-log_message.txt"
    exit
}

# OS Checks
## Check image state
Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Checking image state"
$imgState = Invoke-Command -ComputerName $serverName -ScriptBlock {Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\State\} | Select-Object -ExpandProperty ImageState
if ($imgState -notlike 'IMAGE_STATE_COMPLETE') {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - Image state value $imgState of $serverName is not correct"
    $imgStatePassed = 0
    $oschkPassed = 0
    $scopeStatus = "Failed"
    $canDeploy = 0
    Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "img_state_passed", "scope_status", "oscheck_passed", "can_deploy" -NewValue $imgStatePassed, $scopeStatus, $oschkPassed, $canDeploy
} else {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Image state value $imgState of $serverName is correct"
    $imgStatePassed = 1
    $scopeStatus = "Running"
    $oschkPassed = 1
    $canDeploy = 1
    Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "img_state_passed", "scope_status", "oscheck_passed", "can_deploy" -NewValue $imgStatePassed, $scopeStatus, $oschkPassed, $canDeploy
}

## Check Windows Firewall
$fwState = Invoke-Command -ComputerName $serverName -ScriptBlock {Get-NetFirewallProfile}
if ((($fwState | Where-Object {$_.Name -like 'Domain'}).Enabled -eq $true) -and (($fwState | Where-Object {$_.Name -like 'Domain'}).DefaultInboundAction -like 'Allow') -and (($fwState | Where-Object {$_.Name -like 'Domain'}).DefaultOutboundAction -like 'Allow') -and `
    (($fwState | Where-Object {$_.Name -like 'Private'}).Enabled -eq $true) -and (($fwState | Where-Object {$_.Name -like 'Private'}).DefaultInboundAction -like 'Allow') -and (($fwState | Where-Object {$_.Name -like 'Private'}).DefaultOutboundAction -like 'Allow') -and `
    (($fwState | Where-Object {$_.Name -like 'Public'}).Enabled -eq $true) -and (($fwState | Where-Object {$_.Name -like 'Public'}).DefaultInboundAction -like 'Allow') -and (($fwState | Where-Object {$_.Name -like 'Public'}).DefaultOutboundAction -like 'Allow')
) {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Windows Firewall is set"
    $fwPassed = 1
    $scopeStatus = "Running"
    $oschkPassed = 1
    $canDeploy = 1
    Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "fw_passed", "scope_status", "oscheck_passed", "can_deploy" -NewValue $fwPassed, $scopeStatus, $oschkPassed, $canDeploy
}   elseif (
    (($fwState | Where-Object {$_.Name -like 'Domain'}).Enabled -eq $false) -or (($fwState | Where-Object {$_.Name -like 'Domain'}).DefaultInboundAction -notlike 'Allow') -and (($fwState | Where-Object {$_.Name -like 'Domain'}).DefaultOutboundAction -notlike 'Allow') -and `
    (($fwState | Where-Object {$_.Name -like 'Private'}).Enabled -eq $true) -and (($fwState | Where-Object {$_.Name -like 'Private'}).DefaultInboundAction -like 'Allow') -and (($fwState | Where-Object {$_.Name -like 'Private'}).DefaultOutboundAction -like 'Allow') -and `
    (($fwState | Where-Object {$_.Name -like 'Public'}).Enabled -eq $true) -and (($fwState | Where-Object {$_.Name -like 'Public'}).DefaultInboundAction -like 'Allow') -and (($fwState | Where-Object {$_.Name -like 'Public'}).DefaultOutboundAction -like 'Allow')
) {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "WARNING - Windows Firewall Domain profile is not set correctly"
    $fwPassed = 0
    $scopeStatus = "Running"
    $oschkPassed = 1
    $canDeploy = 1
    Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "fw_passed", "scope_status", "oscheck_passed", "can_deploy" -NewValue $fwPassed, $scopeStatus, $oschkPassed, $canDeploy
} elseif (
    (($fwState | Where-Object {$_.Name -like 'Domain'}).Enabled -eq $true) -and (($fwState | Where-Object {$_.Name -like 'Domain'}).DefaultInboundAction -like 'Allow') -and (($fwState | Where-Object {$_.Name -like 'Domain'}).DefaultOutboundAction -like 'Allow') -and `
    (($fwState | Where-Object {$_.Name -like 'Private'}).Enabled -eq $false) -and (($fwState | Where-Object {$_.Name -like 'Private'}).DefaultInboundAction -notlike 'Allow') -and (($fwState | Where-Object {$_.Name -like 'Private'}).DefaultOutboundAction -notlike 'Allow') -and `
    (($fwState | Where-Object {$_.Name -like 'Public'}).Enabled -eq $true) -and (($fwState | Where-Object {$_.Name -like 'Public'}).DefaultInboundAction -like 'Allow') -and (($fwState | Where-Object {$_.Name -like 'Public'}).DefaultOutboundAction -like 'Allow')
) {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "WARNING - Windows Firewall Private profile is not set correctly"
    $fwPassed = 0
    $scopeStatus = "Running"
    $oschkPassed = 1
    $canDeploy = 1
    Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "fw_passed", "scope_status", "oscheck_passed", "can_deploy" -NewValue $fwPassed, $scopeStatus, $oschkPassed, $canDeploy
} elseif (
    (($fwState | Where-Object {$_.Name -like 'Domain'}).Enabled -eq $true) -and (($fwState | Where-Object {$_.Name -like 'Domain'}).DefaultInboundAction -like 'Allow') -and (($fwState | Where-Object {$_.Name -like 'Domain'}).DefaultOutboundAction -like 'Allow') -and `
    (($fwState | Where-Object {$_.Name -like 'Private'}).Enabled -eq $true) -and (($fwState | Where-Object {$_.Name -like 'Private'}).DefaultInboundAction -like 'Allow') -and (($fwState | Where-Object {$_.Name -like 'Private'}).DefaultOutboundAction -like 'Allow') -and `
    (($fwState | Where-Object {$_.Name -like 'Public'}).Enabled -eq $false) -and (($fwState | Where-Object {$_.Name -like 'Public'}).DefaultInboundAction -notlike 'Allow') -and (($fwState | Where-Object {$_.Name -like 'Public'}).DefaultOutboundAction -notlike 'Allow')
) {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "WARNING - Windows Firewall Public profile is not set correctly"
    $fwPassed = 0
    $scopeStatus = "Running"
    $oschkPassed = 1
    $canDeploy = 1
    Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "fw_passed", "scope_status", "oscheck_passed", "can_deploy" -NewValue $fwPassed, $scopeStatus, $oschkPassed, $canDeploy
} else {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "WARNING - Windows Firewall is not set correctly"
    $fwPassed = 0
    $scopeStatus = "Running"
    $oschkPassed = 1
    $canDeploy = 1
    Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "fw_passed", "scope_status", "oscheck_passed", "can_deploy" -NewValue $fwPassed, $scopeStatus, $oschkPassed, $canDeploy
}

## Check OS license
$osLicenseInfo = Get-NewServerOSlicense -ComputerName $serverName
$osLicProductKey = $osLicenseInfo.ProductChannel
$osLicServer = $osLicenseInfo.LicenseServer
if ($osLicProductKey -like '*GVLK') {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - OS is licensed on KMS server"
    Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "os_lic_product_key", "os_lic_server" -NewValue $osLicProductKey, $osLicServer
    $osLicPassed = 1
    $scopeStatus = "Running"
    $oschkPassed = 1
    $canDeploy = 1
    Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "os_lic_passed", "scope_status", "oscheck_passed", "can_deploy" -NewValue $osLicPassed, $scopeStatus, $oschkPassed, $canDeploy
} elseif ($osLicProductKey -like '*MAK') {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "WARNING - OS is using MAK key"
    Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "os_lic_product_key", "os_lic_server" -NewValue $osLicProductKey, $osLicServer
    $osLicPassed = 0
    $scopeStatus = "Running"
    $oschkPassed = 1
    $canDeploy = 1
    Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "os_lic_passed", "scope_status", "oscheck_passed", "can_deploy" -NewValue $osLicPassed, $scopeStatus, $oschkPassed, $canDeploy
} elseif ($osLicProductKey -like 'NotLicensed') {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - OS is not activated"
    Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "os_lic_product_key", "os_lic_server" -NewValue $osLicProductKey, $osLicServer
    $osLicPassed = 0
    $scopeStatus = "Running"
    $oschkPassed = 1
    $canDeploy = 1
    Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "os_lic_passed", "scope_status", "oscheck_passed", "can_deploy" -NewValue $osLicPassed, $scopeStatus, $oschkPassed, $canDeploy
} else {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - OS is not activated"
    Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "os_lic_product_key", "os_lic_server" -NewValue $osLicProductKey, $osLicServer
    $osLicPassed = 0
    $scopeStatus = "Running"
    $oschkPassed = 1
    $canDeploy = 1
    Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "os_lic_passed", "scope_status", "oscheck_passed", "can_deploy" -NewValue $osLicPassed, $scopeStatus, $oschkPassed, $canDeploy
}

if (($imgStatePassed -eq 0) -or ($scopeStatus -like 'Failed') -or ($oschkPassed -eq 0) -or ($canDeploy -eq 0)) {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - Operating system check did not meet conditions to continue"
    $scopeStatus = "Failed"
    Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "scope_status" -NewValue $scopeStatus
    Get-PowerBuildLogFromDb -RequestNumber $requestNumber -StartDate $pbStartDate -StartTime $pbStartTime | Out-File -FilePath "$env:ProgramData\PowerBuild\Log\LogFromDb\$requestNumber-log_message.txt"
    Send-MailMessage @pbSendMailFailed -Attachments "$env:ProgramData\PowerBuild\Log\LogFromDb\$requestNumber-log_message.txt"
    exit
} else {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Operating system check meet conditions to continue"
    $scopeStatus = "Ready"
    Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "scope_status" -NewValue $scopeStatus
}

# OS Configuration
## Configure all disks
Set-NewServerDisk -ComputerName $serverName
Start-Sleep -Seconds 15
$serverNameSessionDisk = New-CimSession -ComputerName $serverName -Name SetDisk
if (((Get-Disk -CimSession $serverNameSessionDisk).OperationalStatus -eq 'Offline' -and (Get-Disk -CimSession $serverNameSessionDisk).PartitionStyle -eq 'RAW') -or `
    ((Get-Disk -CimSession $serverNameSessionDisk).OperationalStatus -eq 'Online' -and (Get-Disk -CimSession $serverNameSessionDisk).PartitionStyle -eq 'RAW') -or `
    ((Get-Disk -CimSession $serverNameSessionDisk).PartitionStyle -eq 'RAW')
) {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "WARNING - Some disks are not configured"
    Remove-CimSession -Name SetDisk
    $disksSet = 0
    $scopeStatus = "Running"
    $osConfigPassed = 1
    $canDeploy = 1
    Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "disks_set", "scope_status", "os_config_passed", "can_deploy" -NewValue $disksSet, $scopeStatus, $oschkPassed, $canDeploy
} else {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Disks are configured"
    Remove-CimSession -Name SetDisk
    $disksSet = 1
    $scopeStatus = "Running"
    $osConfigPassed = 1
    $canDeploy = 1
    Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "disks_set", "scope_status", "os_config_passed", "can_deploy" -NewValue $disksSet, $scopeStatus, $oschkPassed, $canDeploy
}

## Configure patching
switch ($patchWave) {
    'pw0' {
        $pwGroup = "$country.WSUS.SERVERS.WAVE.0"
        Add-ADGroupMember -Identity $pwGroup -Members (Get-ADComputer -Identity $serverName) -Server $adController
        break
    }
    'pw1' {
        $pwGroup = "$country.WSUS.SERVERS.WAVE.1"
        Add-ADGroupMember -Identity $pwGroup -Members (Get-ADComputer -Identity $serverName) -Server $adController
        break
    }
    'pw2' {
        $pwGroup = "$country.WSUS.SERVERS.WAVE.2"
        Add-ADGroupMember -Identity $pwGroup -Members (Get-ADComputer -Identity $serverName) -Server $adController
        break
    }
    'pw3' {
        $pwGroup = "$country.WSUS.SERVERS.WAVE.3"
        Add-ADGroupMember -Identity $pwGroup -Members (Get-ADComputer -Identity $serverName) -Server $adController
        break
    }
    Default {
        $pwGroup = 'N/A'
        Write-Host "No patch wave group selected" -ForegroundColor Red
        break
    }
}

if ((Get-ADComputer -Identity $serverName -Properties memberof -Server $adController  | Select-Object -ExpandProperty Memberof | Get-ADGroup | Where-Object {$_.Name -match 'WSUS'} | Select-Object -ExpandProperty Name) -like $pwGroup) {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Server added to $pwGroup"
    Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "pw_group" -NewValue $pwGroup
    $patchingSet = 1
    $scopeStatus = "Running"
    $osConfigPassed = 1
    $canDeploy = 1
    Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "patching_set", "scope_status", "os_config_passed", "can_deploy" -NewValue $patchingSet, $scopeStatus, $oschkPassed, $canDeploy
} else {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "WARNING - Server is not added to correct patch wave group"
    Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "pw_group" -NewValue $pwGroup
    $patchingSet = 0
    $scopeStatus = "Running"
    $osConfigPassed = 1
    $canDeploy = 1
    Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "patching_set", "scope_status", "os_config_passed", "can_deploy" -NewValue $patchingSet, $scopeStatus, $oschkPassed, $canDeploy
}

## Configure administrators
if (($appAdmin -like $null) -or ($appAdmin -eq $null) -or (($appAdmin | Get-ADUser -ErrorAction SilentlyContinue) -eq $null)) {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "WARNING - variable $appAdmin is empty or account does not exist"
    $adminSet = 0
    $scopeStatus = "Running"
    $osConfigPassed = 1
    $canDeploy = 1
    Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "admin_set", "scope_status", "os_config_passed", "can_deploy" -NewValue $adminSet, $scopeStatus, $oschkPassed, $canDeploy
} else {
    $appAdmin = '<domain>\' + $appAdmin
    Invoke-Command -ComputerName $serverName -ScriptBlock {Add-LocalGroupMember -Group 'Administrators' -Member $using:appAdmin}
    Start-Sleep -Seconds 5
    if (Invoke-Command -ComputerName $serverName -ScriptBlock {Get-LocalGroupMember -Group 'Administrators' -Member $using:appAdmin}) {
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Account $appAdmin added to server as administrator"
        $adminSet = 1
        $scopeStatus = "Running"
        $osConfigPassed = 1
        $canDeploy = 1
        Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "admin_set", "scope_status", "os_config_passed", "can_deploy" -NewValue $adminSet, $scopeStatus, $oschkPassed, $canDeploy
    } else {
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - Account $appAdmin was not added to server as administrator"
        $adminSet = 0
        $scopeStatus = "Running"
        $osConfigPassed = 1
        $canDeploy = 1
        Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "admin_set", "scope_status", "os_config_passed", "can_deploy" -NewValue $adminSet, $scopeStatus, $oschkPassed, $canDeploy
    }
}

#TODO Create Rcovery User

if (($scopeStatus -like 'Failed') -or ($osConfigPassed -eq 0) -or ($canDeploy -eq 0) -or ($patchingSet -eq 0) -or ($adminSet -eq 0) -or ($disksSet -eq 0)) {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - Operating system configuration did not pass"
} else {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Operating system configuration passed"
    $scopeStatus = "Ready"
    Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "scope_status" -NewValue $scopeStatus
}

## Software installation
$foldersToCopy = Get-ChildItem -Path "D:\SoftwareInstallationFiles\" -Exclude 'emc' | Select-Object -ExpandProperty Name
foreach ($folderToCopy in $foldersToCopy) {
    Copy-Item -Path "D:\SoftwareInstallationFiles\$folderToCopy" -Destination "\\$serverName\c$\ITISOperatingSystems" -Recurse
}
#FIXME Implement better installation files copy verification
if (((Invoke-Command -ComputerName $serverName -ScriptBlock {Get-ChildItem -Path "C:\ITISOperatingSystems"}).Count) -lt $foldersToCopy.Count) {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - Installation files are missing"
    $installFilesCopied = 0
    $scopeStatus = "Running"
    $swInstallPassed = 0
    $canDeploy = 1
    Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "install_files_copied", "scope_status", "sw_install_passed", "can_deploy" -NewValue $installFilesCopied, $scopeStatus, $swInstallPassed, $canDeploy
} else {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Installation files has been copied"
    $installFilesCopied = 1
    $scopeStatus = "Running"
    $swInstallPassed = 1
    $canDeploy = 1
    Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "install_files_copied", "scope_status", "sw_install_passed", "can_deploy" -NewValue $installFilesCopied, $scopeStatus, $swInstallPassed, $canDeploy
}

if ($installFilesCopied -eq 1) {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Software installation process has started"

    #Install Kaspersky Agent
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Kaspersky Network Agent for Windows Server installation process has started"
    Invoke-Command -ComputerName $serverName -ScriptBlock {& C:\ITISOperatingSystems\na4w\install_na4w.bat}
    $knaCounter = 0
    do {

        Start-Sleep -Seconds 30

        if ($knaCounter -eq 10) {
            $knaInstalled = 0
            break
        }
        $knaInstalled = 1
        $knaCounter++
    } until (
        ((Invoke-Command -ComputerName $serverName -ScriptBlock {Test-Path -Path 'C:\Program Files (x86)\Kaspersky Lab\NetworkAgent\klnagent.exe'}) -and `
        ((Get-CimInstance -ClassName 'Win32_InstalledWin32Program' -ComputerName $serverName).Name -contains "Kaspersky Security Center 11 Network Agent") -and `
        (Get-Service -Name 'klnagent' -ComputerName $serverName))
    )
    
    if ($knaInstalled -eq 1) {
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Kaspersky Network Agent for Windows Server installation succeed"
        Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "kna_installed" -NewValue $knaInstalled
    } else {
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - Kaspersky Network Agent for Windows Server installation failed"
        Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "kna_installed" -NewValue $knaInstalled
    }

    #Install Kaspersky Antivirus
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Kaspersky Security for Windows Server installation process has started"
    Invoke-Command -ComputerName $serverName -ScriptBlock {& C:\ITISOperatingSystems\ks4ws\install_ks4ws.bat}
    $kavCounter = 0
    do {

        Start-Sleep -Seconds 30

        if ($kavCounter -eq 10) {
            $kavInstalled = 0
            break
        }
        $kavInstalled = 1
        $kavCounter++
    } until (((Invoke-Command -ComputerName $serverName -ScriptBlock {Test-Path -Path 'C:\Program Files (x86)\Kaspersky Lab\Kaspersky Security for Windows Server\kavfs.exe'}) -and `
        ((Get-CimInstance -ClassName 'Win32_InstalledWin32Program' -ComputerName $serverName).Name -contains "Kaspersky Security 10.1.2 for Windows Server") -and `
        (Get-Service -Name 'kavfs' -ComputerName $serverName))
    )
    
    if ($kavInstalled -eq 1) {
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Kaspersky Security for Windows Server installation succeed"
        Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "kav_installed" -NewValue $kavInstalled
    } else {
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - Kaspersky Security for Windows Server installation failed"
        Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "kav_installed" -NewValue $kavInstalled
    }
      
    #Install Splunk
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Splunk Universal Forwarder installation process has started"
    Invoke-Command -ComputerName $serverName -ScriptBlock {& C:\ITISOperatingSystems\splunk\install_splunk.bat}
    $spnCounter = 0
    do {

        Start-Sleep -Seconds 30

        if ($spnCounter -eq 10) {
            $spnInstalled = 0
            break
        }
        $spnInstalled = 1
        $spnCounter++
    } until (((Invoke-Command -ComputerName $serverName -ScriptBlock {Test-Path -Path 'C:\Program Files\SplunkUniversalForwarder\bin\splunk.exe'}) -and `
        ((Get-CimInstance -ClassName 'Win32_InstalledWin32Program' -ComputerName $serverName).Name -contains "UniversalForwarder") -and `
        (Get-Service -Name 'SplunkForwarder' -ComputerName $serverName))
    )
    
    if ($spnInstalled -eq 1) {
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Splunk Universal Forwarder installation succeed"
        Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "spn_installed" -NewValue $spnInstalled
    } else {
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - Splunk Universal Forwarder installation failed"
        Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "spn_installed" -NewValue $spnInstalled
    }

    #Install uCMDB
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - uCMDB Agent installation process has started"
    Invoke-Command -ComputerName $serverName -ScriptBlock {& C:\ITISOperatingSystems\ucmdb\install_ucmdb.bat}
    $ucmCounter = 0
    do {

        Start-Sleep -Seconds 30

        if ($ucmCounter -eq 10) {
            $ucmInstalled = 0
            break
        }
        $ucmInstalled = 1
        $ucmCounter++
    } until (((Invoke-Command -ComputerName $serverName -ScriptBlock {Test-Path -Path 'C:\Program Files (x86)\Micro Focus\Discovery Agent\bin32\discagnt.exe'}) -and `
        ((Get-CimInstance -ClassName 'Win32_InstalledWin32Program' -ComputerName $serverName).Name -contains "Universal Discovery Agent (x86)") -and `
        (Get-Service -Name 'DiscAgent' -ComputerName $serverName))
    )
    
    if ($ucmInstalled -eq 1) {
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - uCMDB Agent installation succeed"
        Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "ucm_installed" -NewValue $ucmInstalled
    } else {
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - uCMDB Agent installation failed"
        Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "ucm_installed" -NewValue $ucmInstalled
    }

} else {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - Software installation process is skiped"
}

#Install EMC
if ($backupRequired -eq 1) {
    $emcRequired = 0

    switch ($country) {
        '<country code>' { 
            if ($environment -like 'prod') { 
                Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Automatic backup for production virtual machines"
                $emcRequired = 0
                break
            } elseif ($environment -like 'non-prod') {
                Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "WARNING - Request backup for non-production virtual machines"
                $emcRequired = 0
                break
            } else {
                Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - Variable environment has unknown value $environment"
                $emcRequired = 0
                break
            }
        }

        '<country code>' { 
            if ($environment -like 'prod') { 
                Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Installation of EMC Networker required"
                $emcRequired = 1
                break
            } elseif ($environment -like 'non-prod') {
                Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Installation of EMC Networker required"
                $emcRequired = 1
                break
            } else {
                Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - Variable environment has unknown value $environment"
                $emcRequired = 0
                break
            }
        }
        
        '<country code>' { 
            if ($environment -like 'prod') { 
                Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Installation of EMC Networker required"
                $emcRequired = 1
                break
            } elseif ($environment -like 'non-prod') {
                Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Installation of EMC Networker required"
                $emcRequired = 1
                break
            } else {
                Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - Variable environment has unknown value $environment"
                $emcRequired = 0
                break
            }
        }
        
        '<country code>' { 
            if ($environment -like 'prod') { 
                Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Installation of EMC Networker required"
                $emcRequired = 1
                break
            } elseif ($environment -like 'non-prod') {
                Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Installation of EMC Networker required"
                $emcRequired = 1
                break
            } else {
                Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - Variable environment has unknown value $environment"
                $emcRequired = 0
                break
            }
        }
        
        '<country code>' { 
            if ($environment -like 'prod') { 
                Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Installation of EMC Networker required"
                $emcRequired = 1
                break
            } elseif ($environment -like 'non-prod') {
                Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Installation of EMC Networker required"
                $emcRequired = 1
                break
            } else {
                Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - Variable environment has unknown value $environment"
                $emcRequired = 0
                break
            }
        }

        '<country code>' { 
            if ($environment -like 'prod') { 
                Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Automatic backup for production virtual machines"
                $emcRequired = 0
                break
            } elseif ($environment -like 'non-prod') {
                Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Automatic backup for non-production virtual machines"
                $emcRequired = 0
                break
            } else {
                Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - Variable environment has unknown value $environment"
                $emcRequired = 0
                break
            }
        }

        '<country code>' { 
            if ($environment -like 'prod') { 
                Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Automatic backup for production virtual machines"
                $emcRequired = 0
                break
            } elseif ($environment -like 'non-prod') {
                Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Automatic backup for non-production virtual machines"
                $emcRequired = 0
                break
            } else {
                Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - Variable environment has unknown value $environment"
                $emcRequired = 0
                break
            }
        }
        
        '<country code>' { 
            if ($environment -like 'prod') { 
                Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Installation of EMC Networker required"
                $emcRequired = 1
                break
            } elseif ($environment -like 'non-prod') {
                Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Installation of EMC Networker required"
                $emcRequired = 1
                break
            } else {
                Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - Variable environment has unknown value $environment"
                $emcRequired = 0
                break
            }
        }
        
        '<country code>' { 
            if ($environment -like 'prod') { 
                Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Installation of EMC Networker required"
                $emcRequired = 1
                break
            } elseif ($environment -like 'non-prod') {
                Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Installation of EMC Networker required"
                $emcRequired = 1
                break
            } else {
                Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - Variable environment has unknown value $environment"
                $emcRequired = 0
                break
            }
        }

        '<country code>' { 
            if ($environment -like 'prod') { 
                Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Installation of EMC Networker required"
                $emcRequired = 1
                break
            } elseif ($environment -like 'non-prod') {
                Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Installation of EMC Networker required"
                $emcRequired = 1
                break
            } else {
                Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - Variable environment has unknown value $environment"
                $emcRequired = 0
                break
            }
        }

        Default {
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - Variable country has unknown value $country"
            $emcRequired = 0
            break
        }
    }
} else {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Server backup not required"
    $emcRequired = 0
}

if ($emcRequired -eq 1) {
    Copy-Item -Path "D:\SoftwareInstallationFiles\emc" -Destination "\\$serverName\c$\ITISOperatingSystems" -Recurse

    if (!((Invoke-Command -ComputerName $serverName -ScriptBlock {Get-ChildItem -Path "C:\ITISOperatingSystems\emc"}).Count) -eq 4) {
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - EMC Networker installation files are missing"
        $installFilesCopied = 0
        Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "install_files_copied" -NewValue $installFilesCopied
    } else {
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - EMC Networker installation files has been copied"
        $installFilesCopied = 1
        Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "install_files_copied" -NewValue $installFilesCopied
    }

    if ($installFilesCopied = 1) {
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - EMC Networker installation process has started"
        Invoke-Command -ComputerName $NewServerName -ScriptBlock {& C:\ITISOperatingSystems\emc\install_emc.bat}

        $emcCounter = 0
        do {
            Start-Sleep -Seconds 30

            if ($emcCounter -eq 10) {
                $emcInstalled = 0
                break
            }
            $emcInstalled = 1
            $emcCounter++
        } until (
            (Invoke-Command -ComputerName $serverName -ScriptBlock {Test-Path -Path 'C:\Program Files\EMC NetWorker\nsr\bin\nsrexecd.exe'}) -and `
            ((Get-CimInstance -ClassName 'Win32_InstalledWin32Program' -ComputerName $serverName).Name -contains "NetWorker") -and `
            (Get-Service -Name 'nsrexecd' -ComputerName $serverName)
        )
    
        if ($emcInstalled -eq 1) {
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - EMC Networker installation succeed"
            
            Invoke-Command -ComputerName $serverName -ScriptBlock {& 'C:\Program Files\EMC NetWorker\nsr\bin\nsrports.exe' -S 7937-8000}
            $emcPortsSet = Invoke-Command -ComputerName $serverName -ScriptBlock{& 'C:\Program Files\EMC NetWorker\nsr\bin\nsrports.exe'}
            if (($emcPortsSet[0].Trim()) -like "*7937-8000") {
                Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - EMC Networker ports configured"
            } else {
                Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "WARNING - EMC Networker ports are not configured"
            }

            Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "emc_installed" -NewValue $emcInstalled
        } else {
            Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - EMC Networker installation failed"
            Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "emc_installed" -NewValue $emcInstalled
        }
    } else {
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - EMC Networker installation process is skiped"
    }
}

if (($installFilesCopied -eq 0) -or ($knaInstalled -eq 0) -or ($kavInstalled -eq 0) -or ($spnInstalled -eq 0) -or ($ucmInstalled -eq 0) -or (($emcInstalled -eq 0) -and ($backupRequired -eq 1)) -or ($swInstallPassed -eq 0)) {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "ERROR - Software installation did not pass"
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "WARNING - Software installation files not removed"
    $scopeStatus = "Ready"
    Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "scope_status" -NewValue $scopeStatus
} else {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Software installation passed"
    $scopeStatus = "Ready"
    Write-PowerBuildDataToDb -ServerName $serverName -ColumnName "scope_status" -NewValue $scopeStatus
    $foldersToRemove = Invoke-Command -ComputerName $serverName -ScriptBlock {Get-ChildItem -Path "C:\ITISOperatingSystems\"}
    $installFilesRemoved = 1
    foreach ($folderToRemove in $foldersToRemove) {
        Remove-Item -Path "\\$serverName\c$\ITISOperatingSystems\$folderToRemove" -Recurse -Confirm:$false
        if (Test-Path -Path "\\$serverName\c$\ITISOperatingSystems\$folderToRemove") {
            $installFilesRemoved = 0
        }
    }
    if ($installFilesRemoved -eq 1) {
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Software installation files removed"
    } else {
        Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "WARNING - Software installation files not removed"
    }
}

if ($scopeStatus -like 'Ready') {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Deployment of $serverName successfully completed"
    Move-Item -Path "$env:ProgramData\PowerBuild\JsonTemplate\$NewServerName.json" -Destination "$env:ProgramData\PowerBuild\JsonTemplate\Archive"
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Server JSON template has been moved to Archive folder"
    Get-PowerBuildLogFromDb -RequestNumber $requestNumber -StartDate $pbStartDate -StartTime $pbStartTime | Out-File -FilePath "$env:ProgramData\PowerBuild\Log\LogFromDb\$requestNumber-log_message.txt"
    Send-MailMessage @pbSendMailPassed -Attachments "$env:ProgramData\PowerBuild\Log\LogFromDb\$requestNumber-log_message.txt"
    exit
} else {
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "WARNING - Variable scopeStatus has unknown value $scopeStatus"
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Deployment of $serverName successfully completed"
    Move-Item -Path "$env:ProgramData\PowerBuild\JsonTemplate\$NewServerName.json" -Destination "$env:ProgramData\PowerBuild\JsonTemplate\Archive"
    Write-PowerBuildLogToDb -RequestNumber $requestNumber -LogMessage "INFORMATION - Server JSON template has been moved to Archive folder"
    Get-PowerBuildLogFromDb -RequestNumber $requestNumber -StartDate $pbStartDate -StartTime $pbStartTime | Out-File -FilePath "$env:ProgramData\PowerBuild\Log\LogFromDb\$requestNumber-log_message.txt"
    Send-MailMessage @pbSendMailPassed -Attachments "$env:ProgramData\PowerBuild\Log\LogFromDb\$requestNumber-log_message.txt"
    exit
}
# End of script