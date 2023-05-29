. $PSScriptRoot\mdlp.api.ps1

$Settings = @{
    API = "https://api.mdlp.crpt.ru/api/v1/"                  
    CSP = "C:\Program Files\Crypto Pro\CSP\csptest.exe"

    ClientID = "12345678-90ab-cdef-1234-567890abcdef"        # replace with your own
    ClientSecret = "fedcba098765-4321-fedc-ba09-87654321"    # replace with your own

    Certificate = "b20062e0aaaeb5350ae357417ac70fa493d59425" # replace with your own
    UserID = "2c389b78-3efa-c48e-1d59-519f6ff17f3a"          # replace with your own
}

$GTINList = @(
    '12345678901234'
    # ...
    '43210987654321'
)


$Now = Get-Date
$Today = Get-Date -Format "yyyyMMdd"
$PeriodLast = ($Now.Year*12 + $Now.Month) - 1
$PeriodBeforeLast = $PeriodLast - 1


$WantedReports = @{
    "GENERAL_REPORT_ON_DISPOSAL_$PeriodLast" = @{
        "report_id" = "GENERAL_REPORT_ON_DISPOSAL"
        "params" = @{
             "1026_IC_Period_Type_WM" = "IC_Period_Month"
             "1027_IC_Period_Month_11_2019" = $PeriodLast.ToString()
             "1156_IC_Product_MDLP_general_gtin" = $GTINList
        }
    }

    "GENERAL_REPORT_ON_DISPOSAL_$PeriodBeforeLast" = @{
        "report_id" = "GENERAL_REPORT_ON_DISPOSAL"
        "params" = @{
             "1026_IC_Period_Type_WM" = "IC_Period_Month"
             "1027_IC_Period_Month_11_2019" = $PeriodBeforeLast.ToString()
             "1156_IC_Product_MDLP_general_gtin" = $GTINList
        }
    }

    "GENERAL_REPORT_ON_MOVEMENT_$PeriodLast" = @{
        "report_id" = "GENERAL_REPORT_ON_MOVEMENT"
        "params" = @{
             "1026_IC_Period_Type_WM" = "IC_Period_Month"
             "1027_IC_Period_Month_11_2019" = $PeriodLast.ToString()
             "1156_IC_Product_MDLP_general_gtin" = $GTINList
        }
    }

    "GENERAL_REPORT_ON_MOVEMENT_$PeriodBeforeLast" = @{
        "report_id" = "GENERAL_REPORT_ON_MOVEMENT"
        "params" = @{
             "1026_IC_Period_Type_WM" = "IC_Period_Month"
             "1027_IC_Period_Month_11_2019" = $PeriodBeforeLast.ToString()
             "1156_IC_Product_MDLP_general_gtin" = $GTINList
        }
    }
    "GENERAL_REPORT_ON_REMAINING_ITEMS_$Today" = @{
        "report_id" = "GENERAL_REPORT_ON_REMAINING_ITEMS"
    }
}


Enter-MDLPSession @Settings


$Attachments = @()
foreach ($ReportName in $WantedReports.Keys) {
    # Gracefully skip if already created
    if (Test-Path "$ReportName.zip") {
        Write-Host "Already cooked $ReportName"
        $Attachments = $Attachments + "$ReportName.zip"
        Continue
    }

    Write-Host "$ReportName - Creating export task"
    $Task = Create-MDLPExportTask -ReportID $WantedReports[$ReportName]['report_id'] -Params $WantedReports[$ReportName]['params']        
    if (!$Task) {
        Write-Error "Unable to create export task"
        Continue
    }
    Write-Host "$ReportName - Awaiting results for task: $($Task.task_id)"

    Sleep(30) # Give sometime to proccess
    $TaskResult = Wait-MDLPExportTask -Task $Task 

    Write-Host "$ReportName - Downloading report"
    Save-MDLPExportResult -Result $TaskResult -File "$ReportName.zip" | Request-MDLPExportResultRemove
    $Attachments = $Attachments + "$ReportName.zip"
}

Write-Host "Sending Message with files"
Send-MailMessage -From "mdlp-reporter" -To "important-stuff@company" -Subject "Monthly Reports" -Attachments $Attachments 