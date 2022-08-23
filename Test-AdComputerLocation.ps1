function Test-AdComputerLocation {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName,
        [Parameter(Mandatory=$true)]
        [string]$DomainController
    )
    
    begin {
        $ADLocationSplit = (Get-ADComputer -Identity "$ComputerName" -Server $DomainController).DistinguishedName.Split(',')
        [string]$ADLocationFinalString
    }
    
    process {
        for ($i = 0; $i -lt $ADLocationSplit.Count; $i++) {
            if (($i -eq 0)) {
            
            } else {
                $ADLocationItemRegex = $ADLocationSplit[$i] -replace '..=', ''
                $ADLocationFinalString = $ADLocationFinalString + "/" + $ADLocationItemRegex
            }
        }    
    }
    
    end {
        $CustomADInfo = [ordered]@{
            ComputerName = $ComputerName
            Location = $ADLocationFinalString
        }

        $CustomADInfo
    }
}