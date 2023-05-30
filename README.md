# mdlp.api.ps1
Функции для работы с API системы [МДЛП](https://честныйзнак.рф/business/projects/medical_devices/) для удобства использования в сценариях 

Автоматический вход и обработка токена, учитывание параметров частоты вызова фукнций

#### Требования
Требует установленного Crypto Pro и доступ в интернет.

### Реализованные вызовы API

Метод для получения кода аутентификации + Метод для получения ключа сессии
: API:  auth + token <br>
  PS:  `Get-MDLPToken`

Метод создания нового задания на выгрузку
: API: data/export/tasks  
  PS:  `New-MDLPExportTask`

Метод получения статуса задания на выгрузку
: API: data/export/tasks/{task_id}  
  PS: `Get-MDLPExportTaskStatus`
  
Метод получения результирующих идентификаторов выгрузок данных
: API: data/export/results  
  PS: `Get-MDLPExportResults`

Метод получения выгрузки 
: API: data/export/results/{result_id}/file  
  PS:  `Save-MDLPExportResult`

Метод удаления файла выгрузки
: API: data/export/results/{result_id}  
  PS:  `Request-MDLPExportResultRemove`

### Параметры
```PowerShell
$Settings = @{
    API = "https://api.mdlp.crpt.ru/api/v1/"                 # Обычно не меняется          
    CSP = "C:\Program Files\Crypto Pro\CSP\csptest.exe"      # Путь до Crypto Pro

    ClientID = "12345678-90ab-cdef-1234-567890abcdef"        # ИД Клиента из панели управления
    ClientSecret = "fedcba098765-4321-fedc-ba09-87654321"    # Секрет клиента

    Certificate = "b20062e0aaaeb5350ae357417ac70fa493d59425" # Отпечаток сертификата (thumbprint) пользователя
    UserID = "2c389b78-3efa-c48e-1d59-519f6ff17f3a"          # ИД пользователя (можно не указывать)
}
```

### Примеры использования
```PowerShell
Enter-MDLPSession @Settings
$Task = New-MDLPExportTask -ReportID "GENERAL_REPORT_ON_REMAINING_ITEMS"
Start-Sleep 30 # Speculative wait due to heavy limits on API for query results
$Result = Wait-MDLPExportTask -Task $Task 
Save-MDLPExportResult -Result $Result -File "Report.zip" 
Request-MDLPExportResultRemove
Send-MailMessage -Attachments "Report.zip"
```

или еще короче 
```PowerShell
Enter-MDLPSession @Settings 
New-MDLPExportTask -ReportID "GENERAL_REPORT_ON_REMAINING_ITEMS" | Wait-MDLPExportTask | Save-MDLPExportResult -File "Report.zip" | Request-MDLPExportResultRemove
Send-MailMessage -Attachments "Report.zip"
```


