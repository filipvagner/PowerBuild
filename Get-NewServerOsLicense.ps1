function Get-NewServerOSlicense {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )
    
    begin {
        $SessionOSLicCheck = New-CimSession -ComputerName $ComputerName -Name OSLicCheck
        $LicenseStatus = Get-CimInstance -CimSession $SessionOSLicCheck -ClassName SoftwareLicensingProduct | Where-Object {$_.LicenseStatus -eq 1}
    }
    
    process {
        if ($LicenseStatus.ProductKeyChannel -match 'GVLK') {
            $LicenseInfo = [PSCustomObject]@{
                ProductChannel = $LicenseStatus.ProductKeyChannel
                LicenseServer = $LicenseStatus.DiscoveredKeyManagementServiceMachineName
            }
        } elseif ($LicenseStatus.ProductKeyChannel -match 'MAK') {
            $LicenseInfo = [PSCustomObject]@{
                ProductChannel = $LicenseStatus.ProductKeyChannel
                LicenseServer = "Unknown"
            }
        } else {
            $LicenseInfo = [PSCustomObject]@{
                ProductChannel = "NotLicensed"
                LicenseServer = "Unknown"
            }
        }
    }
    
    end {
        Remove-CimSession -Name OSLicCheck
        return $LicenseInfo
    }
}