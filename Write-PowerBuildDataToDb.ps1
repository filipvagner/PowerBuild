function Write-PowerBuildDataToDb {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $ServerName,
        [Parameter(Mandatory=$true)]
        [string[]]
        $ColumnName,
        [Parameter(Mandatory=$true)]
        [string[]]
        $NewValue
    )
    
    begin {
        $sqlServerInfo = "<server name>"
        $sqlInstanceInfo = Get-SqlInstance -Path "SQLSERVER:\SQL\<server name>\DEFAULT"
        $sqlDatabaseInfo = "PowerBuild"
        $j = 0
    }
    
    process {
        for ($i = 0; $i -lt $ColumnName.Count; $i++) {
            $currentColumn = $ColumnName[$i]
            for ($j; $j -le $NewValue.Count; $j++) {
                $currentValue = $NewValue[$j]
                $messageQuery = "UPDATE builds SET $currentColumn = '$currentValue' WHERE server_name = '$ServerName';"
                Invoke-Sqlcmd -HostName $sqlServerInfo -ServerInstance $sqlInstanceInfo -Database $sqlDatabaseInfo -Query $messageQuery
                $j++
                break
            }
        }
    }

    end {

    }
}