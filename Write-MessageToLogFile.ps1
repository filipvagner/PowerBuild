<#
    .Synopsis
        This function writes entry to log specified
    .Description
        This function writes entry to log specified and expects two mandatory variables.
        First variable is message that will be written to log file.
        Second variable is path to log file where message is going to be written.
        Each log has time stamp (yyyy-MM-dd HH:mm:ss) prefix.
    .Example
        Write-MessageToLogFile -LogMessage "Writing to log file $a" -LogFilePath C:\Users\username\Documents\LogFile.txt
    .Notes
        AUTHOR  : Filip Vagner
        EMAIL   : filip.vagner@hotmail.com
        CREATED : 29-07-2019
        NOTE    : Only one message at the time can be written
    .Link
        https://link.to.repository
#>
function Write-MessageToLogFile {
    [CmdletBinding()]
    param (
        # Message as string that will be written to log file
        [Parameter(Mandatory=$True)]
        [string] $LogMessage,
        # Path to log file
        [Parameter(Mandatory=$True)]
        [string] $LogFilePath
    )
    
    begin {
        $GetDateForLogEntry = (Get-Date -Format yyyy-MM-dd) + " " + (Get-Date -Format HH:mm:ss)
    }
    
    process {
        "$GetDateForLogEntry - $LogMessage" | Out-File -FilePath $LogFilePath -Append
    }
    
    end {
        Clear-Variable -Name GetDateForLogEntry
    }
}