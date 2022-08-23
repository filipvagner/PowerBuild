function Get-PowerBuildLogFromDb {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        # [ValidatePattern('^([sS][rR]|[rR][fF][cC])-\d\d\d\d\d\d$')]
        $RequestNumber,
        [Parameter(Mandatory=$true)]
        [string]
        $StartDate,
        [Parameter(Mandatory=$true)]
        [string]
        $StartTime
    )
    
    begin {
        $sqlServerInfo = "<server name>"
        $sqlInstanceInfo = Get-SqlInstance -Path "SQLSERVER:\SQL\<server name>\DEFAULT"
        $sqlDatabaseInfo = "PowerBuild"
    }
    
    process {
        $getBuildError = "
        USE PowerBuild;

        DECLARE @srNumber VARCHAR(9);
        DECLARE @logDate DATE;
        DECLARE @logTime TIME;

        SET @srNumber = '$RequestNumber';
        SET @logDate = '$StartDate';
        SET @logTime = '$StartTime';

        SELECT CONCAT_WS(' - ',log_level, log_message) AS 'LogMessage'
        FROM dbo.builds_log
        WHERE (request_number = @srNumber) AND ((log_date >= @logDate) AND (log_date <= (SELECT CONVERT(varchar(10), GETDATE(),23)))) AND ((log_time >= @logTime) AND (log_time <= (SELECT CONVERT(varchar(8), GETDATE(),24)))) AND ((log_level LIKE 'WARNING') OR (log_level LIKE 'ERROR'))
        ORDER BY log_time;
        "
        $buildErrorMessages = Invoke-Sqlcmd -HostName $sqlServerInfo -ServerInstance $sqlInstanceInfo -Database $sqlDatabaseInfo -Query $getBuildError # | Select-Object -ExpandProperty 'LogMessage'
    }

    end {
        return $buildErrorMessages
    }
}