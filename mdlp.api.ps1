<#

.SYNOPSIS
Функции для работы с API системы MDLP для удобства использования в сценариях
Автоматический вход и обработка токена, учитывание параметров частоты вызова фукнций

.DESCRIPTION
Типовой сценарий использования

PS> Enter-MDLPSession @Settings
PS> $Task = Create-MDLPExportTast -ReportID "GENERAL_REPORT_ON_REMAINING_ITEMS"
PS> Start-Sleep 30 # Speculative wait due to heavy limits on API for query results
PS> $Result = Wait-MDLPExportTask -Task $Task 
PS> Save-MDLPExportResult -Result $Result -File "Report.zip" 
PS> Request-MDLPExportResultRemove
PS> Send-MailMessage -Attachments "Report.zip"

Или еще короче
PS> Enter-MDLPSession @Settings 
PS> Create-MDLPExportTast -ReportID "GENERAL_REPORT_ON_REMAINING_ITEMS" | Wait-MDLPExportTask | Save-MDLPExportResult -Result $Result -File "Report.zip" | Request-MDLPExportResultRemove
PS> Send-MailMessage -Attachments "Report.zip"

Реализованные вызовы API
* Метод для получения кода аутентификации + Метод для получения ключа сессии
  API: auth + token
  PS:  Get-MDLPToken

* Метод создания нового задания на выгрузку
  API: data/export/tasks
  PS:  New-MDLPExportTask

* Метод получения статуса задания на выгрузку
  API: data/export/tasks/{task_id}
  PS:  Get-MDLPExportTaskStatus
  
* Метод получения результирующих идентификаторов выгрузок данных
  API: data/export/results
  PS:  Get-MDLPExportResults

* Метод получения выгрузки 
  API: data/export/results/{result_id}/file
  PS:  Save-MDLPExportResult

* Метод удаления файла выгрузки
  API: data/export/results/{result_id}
  PS:  Request-MDLPExportResultRemove


.PARAMETER $Settings

$Settings = @{
    API = "https://api.mdlp.crpt.ru/api/v1/"
    CSP = "C:\Program Files\Crypto Pro\CSP\csptest.exe"
    Certificate  = "" # Certificate Thumbprint
    ClientID     = "" # MDLP Client ID
    ClientSecret = "" # MDLP Secret
    UserID       = "" # MDLP User Id or Certificate Thumbprint
}

#>

$Script:Methods = @(
    'Get-MDLPToken'
    'Set-MDLPSessionToken'
    'Invoke-MDLPMethod'
    'Sign-MDLPData'
    'New-MDLPExportTask'
    'Get-MDLPExportTaskStatus'
    'Get-MDLPExportResults'
    'Save-MDLPExportResult'
    'Request-MDLPExportResultRemove'
    'Modify-MDLPSession'
    'Wait-MDLPExportTask'
)

$Script:APIThrottleLimits = @{
    'auth' =  1
    'token' = 1
    'data/export/tasks' = 60
    'data/export/tasks/{task_id}' = 60
    'data/export/results' = 60
    'data/export/results/{result_id}/file' = 60
    'data/export/results/{result_id}' = 60
}

function Set-ActiveMDLPSession {
    param(
        [Parameter(Mandatory)] $Session,
        [switch] $PassThru
    )

    $Global:ActiveMDLPSession = $Session

    foreach ($Method in $Script:Methods) {
        $PSDefaultParameterValues[$Method + ":Session"] = { $Global:ActiveMDLPSession }
    }

    if ($PassThru) {
        return $Session
    }
}

function Enter-MDLPSession {
    param(
        [Parameter(Mandatory)][string] $API, 
        [Parameter(Mandatory)][string] $CSP,
        [Parameter(Mandatory)][string] $Certificate,
        [Parameter(Mandatory)][string] $ClientID,
        [Parameter(Mandatory)][string] $ClientSecret,
        [string] $UserID,
        [switch] $PassThru 
    )

    $Session = [PSCustomObject] @{
        API = $API
        CSP = $CSP
        Certificate = $Certificate
        ClientID = $ClientID
        ClientSecret = $ClientSecret
        UserID = $(if ($UserID) { $UserID } else { $Certificate }) 
        Token = $null
        TokenExpire = $null
        LastInvoked = @{}
    }

    Get-MDLPToken -Session $Session | Set-MDLPSessionToken -Session $Session

    return Set-ActiveMDLPSession -Session $Session -PassThru:$PassThru
}

function Exit-MDLPSession {
    if ($Global:ActiveMDLPSession) {
        Remove-Variable -Name "ActiveMDLPSession"
    }    
    foreach ($Method in $Script:Methods) {
        $PSDefaultParameterValues.Remove($Method + ":Session")
    }
}

function Invoke-MDLPMethod {
    param(
        [Parameter(Mandatory)] $Session,
        $Method, $Name, $Body, $OutFile, $PassThru
    )

    # Prepare URI
    $Uri = $Session.API + $Name
    $Uri |  Select-String "{(.*?)}" -AllMatches | Foreach { 
        $k = $_.matches.Value.Trim('{', '}')
        if ($Body.ContainsKey -and $Body.ContainsKey($k)) {
            $Uri = $Uri.Replace("{$k}",  $Body[$k])
            $Body.Remove($k)
        }        
    }

    $Headers = @{}

    if ($('put', 'post').Contains($Method.ToString().ToLower())) {
        if ($Body -ne $null) {
            $Body = $($Body | ConvertTo-Json)
        }
    }

    if ($('get', 'head', 'delete').Contains($Method.ToString().ToLower())) {
        # We need to rebuild Query parameters since Microsoft got their own way to iterate over the same query keys
        # while CRPT asks it in a direct way way
        # This will build /uri/?array_key=array_value_1&array_key=array_value_2
        if ($Body -is [hashtable]) {            
            $Request =  [System.UriBuilder]($Uri)
            $QueryValueCollection = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)
            foreach ($k in $Body.keys) {
                $Body[$k] | Foreach {
                    $QueryValueCollection.Add($k, $_)
                }
            }
            $Request.Query = $QueryValueCollection.ToString()
            $Uri = $Request.Uri.ToString()

            $Body = $null
        }
    }


    # Check if throttling required
    if ($Script:APIThrottleLimits.ContainsKey($Name)) {
        if ($Session.LastInvoked.ContainsKey($Name)) {
            $Passed = ($(Get-Date) - $Session.LastInvoked[$Name])
            $WaitTime = $Script:APIThrottleLimits[$Name] - $Passed.TotalSeconds
            if ($WaitTime -gt 0) {
                Write-Verbose "Throttling $($Method.ToUpper()) $Uri for $($WaitTime.ToString('#.##')) seconds"
                Start-Sleep -Milliseconds $(($WaitTime+1)*1000)
            }
        }
    }

    # Add Token if exits
    if ($Session.Token) {
        # Check if Token expired
        $isExpiredByLifeTime = ($Session.TokenExpire -and ($Session.TokenExpire -lt $(Get-Date)))
        $isExpiredByInactivity = ($Session.LastInvoked.ContainsKey('*') -and (($Session.LastInvoked['*'] + $(New-TimeSpan -Minutes 30)) -lt $(Get-Date)))

        if ($isExpiredByLifeTime -or $isExpiredByInactivity) {
            Write-Verbose "Token expired"
            Get-MDLPToken -Session $Session | Set-MDLPSessionToken -Session $Session
        }

        # Add Token
        if ($Session.Token) { 
            $Headers['Authorization'] = 'token ' + $Session.Token
        }
    }


    Write-Verbose "Invoking $($Method.ToUpper()) $Uri"

    if ($Script:APIThrottleLimits.ContainsKey($Name)) {
        $Session.LastInvoked[$Name] = $(Get-Date)
    }

    $Session.LastInvoked['*'] = $(Get-Date)
    $PassThru = (($OutFile -ne $null) -and ($PassThru -ne $null) -and $PassThru) -or $PassThru

    return Invoke-RestMethod -Method $Method -Uri $Uri -Body $Body -ContentType "application/json; charset=utf-8" -Headers $Headers -OutFile $OutFile -PassThru:$PassThru
}

function Sign-MDLPData {
    param(
        [Parameter(Mandatory)] $Session,
        [Parameter(Mandatory)] $Data
    )

    $DataTmpFile = [System.IO.Path]::GetTempFileName()
    $Data | Set-Content $DataTmpFile -NoNewline

    $SignatureTmpFile = [System.IO.Path]::GetTempFileName()
    $Signature = $false

    $csp_cmd = $Session.CSP

    Write-Verbose "Signing with Crypto Pro CSP executable"
    &$csp_cmd -notime -sfsign -sign -in $DataTmpFile -out $SignatureTmpFile -my $($Session.Certificate) -detached -base64 -add | Out-Null

    # If all goes fine    
    if ($?) {
        $Signature = $($(Get-Content -LiteralPath $SignatureTmpFile) -join "").Trim()        
        Remove-Item -LiteralPath $SignatureTmpFile
    }
    Remove-Item -LiteralPath $DataTmpFile
   
    return $Signature
}

function Get-MDLPToken {
    param(
        [Parameter(Mandatory)] $Session
    )
    
    Write-Verbose "Getting new token"

    $Data = @{
        "auth_type"     = "SIGNED_CODE"    
        "client_id"     = $Session.ClientID
        "client_secret" = $Session.ClientSecret
        "user_id"       = $Session.UserID
    }

    $AuthResponse = Invoke-MDLPMethod -Session $Session -Method Post -Name 'auth' -Body $Data

    $Data = @{
        "code"      = $AuthResponse.code
        "signature" = Sign-MDLPData -Session $Session -Data $AuthResponse.code
    }

    return Invoke-MDLPMethod -Session $Session -Method Post -Name 'token' -Body $Data
}

function Set-MDLPSessionToken {
    param(
        [Parameter(Mandatory)] $Session,
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, Position=0)] $Token,
        [switch] $PassThru
    )

    $Session.Token = $Token.token
    $Session.TokenExpire = $(Get-Date) + $(New-TimeSpan -Minutes $Token.life_time)

    if ($PassThru) {
        return $Token
    }
}

function New-MDLPExportTask {
    param(
        [Parameter(Mandatory)] $Session,
        [string] $ReportID,
        $Params
    )

    $Body = @{
        'report_id' = $ReportID
    }

    if ($Params) {
        $Body['params'] = $Params
    }

    return Invoke-MDLPMethod -Session $Session -Method Post -Name 'data/export/tasks' -Body $Body
}

function ConvertFrom-MDLPResponse {
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, Position=0)] $Task,
        [string] $Field = 'task_id'
    )

    if (($Task -is [PSCustomObject]) -and $Task.$Field) {
        return $Task.$Field
    } 

    if (($Task -is [Hashtable]) -and $Task.ContainsKey($Field)) {
        return $Task[$Field]
    } 


    # Last resort
    return $($Task | Out-String).Trim()
}

function Get-MDLPExportTaskStatus {
    param(
        [Parameter(Mandatory)] $Session,
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, Position=0)] $Task
    )

    $Body = @{
        'task_id' = $Task | ConvertFrom-MDLPResponse  -Field 'task_id'
    }

    return Invoke-MDLPMethod -Session $Session -Method Get -Name 'data/export/tasks/{task_id}' -Body $Body

}

function Get-MDLPExportResults {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Session,
        [Parameter(ValueFromPipeline=$true)][array] $Task
    )

    begin {
        $query_ids = [System.Collections.ArrayList]::new()
    }

    process {
        if ($Task) {
            $Task | Foreach { 
                $TaskId = $_ | ConvertFrom-MDLPResponse -Field 'task_id'
                [void] $query_ids.Add($TaskId)
            }
        }
    }

    end {
        
        $Page = 0
        $MaxSize = 1000

        $Result = [System.Collections.ArrayList]::new()
        do {
            $Body = @{
                'page' = $Page
                'size' = $MaxSize
            }

            if ($query_ids.Count) {
                $Body['task_ids'] = $query_ids
            }

            $Response = Invoke-MDLPMethod -Session $Session -Method Get -Name 'data/export/results' -Body $Body
            
            if (!$Response.total_count) {
                break;
            }

            $Response.list | Foreach {
                [void]$Result.Add($_)
            }

            $Page += 1

        } while ($Result.Count -lt $Response.total_count)

        return $Result
    }
}

function Wait-MDLPExportTask {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Session,
        [Parameter(ValueFromPipeline=$true)] $Task
    )

    do {        
        $TaskResult = $Task | Get-MDLPExportResults -Session $Session 
    } while ($TaskResult.available -ne "AVAILABLE")

    return $TaskResult
}

function Save-MDLPExportResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Session,
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, Position=0)] $Result,
        [Parameter(Mandatory=$true, Position=1)][string] $File
    )

    $Body = @{
        'result_id' = $Result | ConvertFrom-MDLPResponse -Field 'result_id'
    }

    Invoke-MDLPMethod -Session $Session -Method Get -Name 'data/export/results/{result_id}/file' -Body $Body -OutFile $File

    return $Result
}

function Request-MDLPExportResultRemove {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Session,
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, Position=0)] $Result
    )

    $Body = @{
        'result_id' = $Result | ConvertFrom-MDLPResponse -Field 'result_id'
    }

    Invoke-MDLPMethod -Session $Session -Method Delete -Name 'data/export/results/{result_id}' -Body $Body | Out-Null

}
