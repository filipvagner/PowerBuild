function Write-PowerBuildLogToDb {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        # [ValidatePattern('^([sS][rR]|[rR][fF][cC])-\d\d\d\d\d\d$')]
        $RequestNumber,
        [string]
        $LogMessage
    )
    
    begin {
        $sqlServerInfo = "<server name>"
        $sqlInstanceInfo = Get-SqlInstance -Path "SQLSERVER:\SQL\<server name>\DEFAULT"
        $sqlDatabaseInfo = "PowerBuild"
        $logDate = Get-Date -Format yyyy-MM-dd
        $logTime = Get-Date -Format HH:mm:ss
        [int]$dashCounter = 0
        [int]$dashPosition = 0
    }
    
    process {
        $logLevel = $logMessage.Split('-')[0].Trim()
        for ($i = 0; $i -lt $logMessage.Length; $i++) {
            if ($logMessage[$i] -eq '-') {
                $dashCounter++
                if ($dashCounter -eq 1) {
                    $dashPosition = $i
                    break
                }
            }
        }
        $logMessageModified = $logMessage.Substring($dashPosition + 2, $logMessage.Length - ($dashPosition + 2))
    }

    end {
        $messageQuery = "
        INSERT INTO builds_log (
            request_number,
            log_date,
            log_time,
            log_level,
            log_message
        ) VALUES (
            '$requestNumber',
            '$logDate',
            '$logTime',
            '$logLevel',
            '$logMessageModified'
        );
        "

        Invoke-Sqlcmd -HostName $sqlServerInfo -ServerInstance $sqlInstanceInfo -Database $sqlDatabaseInfo -Query $messageQuery
    }
}