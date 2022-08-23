function Set-NewServerDisk {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )
    
    begin {
        $SessionSetDisk = New-CimSession -ComputerName $ComputerName -Name SetDisk
    }
    
    process {
        if ((Get-Disk -CimSession $SessionSetDisk).OperationalStatus -eq 'Offline' -and (Get-Disk -CimSession $SessionSetDisk).PartitionStyle -eq 'RAW') {
            $DiskNumber = (Get-Disk -CimSession $SessionSetDisk | Where-Object {$_.OperationalStatus -eq 'Offline' -and $_.PartitionStyle -eq 'RAW'}).Number
            Set-Disk -CimSession $SessionSetDisk -IsOffline $false -Number $DiskNumber
            Set-Disk -CimSession $SessionSetDisk -IsReadOnly $false -Number $DiskNumber
            Initialize-Disk -CimSession $SessionSetDisk -Number $DiskNumber -PartitionStyle GPT
            New-Partition -CimSession $SessionSetDisk -DiskNumber $DiskNumber -UseMaximumSize -AssignDriveLetter
            $DriveLetter = (Get-Partition -CimSession $SessionSetDisk -DiskNumber $DiskNumber | Where-Object {$_.Size -gt 1024MB}).DriveLetter
            Format-Volume -CimSession $SessionSetDisk -DriveLetter $DriveLetter -FileSystem NTFS -Confirm:$false
        } elseif ((Get-Disk -CimSession $SessionSetDisk).OperationalStatus -eq 'Online' -and (Get-Disk -CimSession $SessionSetDisk).PartitionStyle -eq 'RAW') {
            $DiskNumber = (Get-Disk -CimSession $SessionSetDisk | Where-Object {$_.OperationalStatus -eq 'Online' -and $_.PartitionStyle -eq 'RAW'}).Number
            Set-Disk -CimSession $SessionSetDisk -IsReadOnly $false -Number $DiskNumber
            Initialize-Disk -CimSession $SessionSetDisk -Number $DiskNumber -PartitionStyle GPT
            New-Partition -CimSession $SessionSetDisk -DiskNumber $DiskNumber -UseMaximumSize -AssignDriveLetter
            $DriveLetter = (Get-Partition -CimSession $SessionSetDisk -DiskNumber $DiskNumber | Where-Object {$_.Size -gt 1024MB}).DriveLetter
            Format-Volume -CimSession $SessionSetDisk -DriveLetter $DriveLetter -FileSystem NTFS -Confirm:$false
        } elseif ((Get-Disk -CimSession $SessionSetDisk).PartitionStyle -eq 'RAW') {
            $DiskNumber = (Get-Disk -CimSession $SessionSetDisk | Where-Object {$_.PartitionStyle -eq 'RAW'}).Number
            Set-Disk -CimSession $SessionSetDisk -IsOffline $false -Number $DiskNumber
            Set-Disk -CimSession $SessionSetDisk -IsReadOnly $false -Number $DiskNumber
            Initialize-Disk -CimSession $SessionSetDisk -Number $DiskNumber -PartitionStyle GPT
            New-Partition -CimSession $SessionSetDisk -DiskNumber $DiskNumber -UseMaximumSize -AssignDriveLetter
            $DriveLetter = (Get-Partition -CimSession $SessionSetDisk -DiskNumber $DiskNumber | Where-Object {$_.Size -gt 1024MB}).DriveLetter
            Format-Volume -CimSession $SessionSetDisk -DriveLetter $DriveLetter -FileSystem NTFS -Confirm:$false
        }
    }
    
    end {
        Remove-CimSession -Name SetDisk
    }
}