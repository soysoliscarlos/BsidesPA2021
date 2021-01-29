
# Protegiendo tu Infraestructura Tecnológica con PowerShell...

## Estadisticas de Descarga de PowerShell
```
    Start-Process .\powershell.png
```
## ¿Por qué utilizar PowerShell?"
- PowerShell es tanto un lenguaje de línea de comandos como de scripting.
- PowerShell puede interactuar con un número vertiginoso de tecnologías.
- PowerShell está orientado a objetos.
- PowerShell no va a desaparecer.
- En Windows, PowerShell es realmente la única opción.

## Facilidad para administración de Hosts
### Administración Remota de equipos (También SSH)
#### Comandos: Enable-PSRemoting - Enter-PSSession
```
Enable-PSRemoting –force -SkipNetworkProfileCheck
$pc = "WS2019"
$cred = Get-Credential
Enter-PSSession -ComputerName $pc -Credential $Cred
Enter-PSSession -HostName debian -UserName root
```
### Apagado y Reincio de equipos
#### Comandos: Stop-Computer - Restart-Computer
```
Stop-Computer
Restart-Computer
Enter-PSSession -HostName debian -UserName root
```
### Verificación de puertos abiertos
#### Comandos: Test-Connection
```
Test-Connection -ComputerName $pc -TcpPort 3389 
Test-Connection -ComputerName $pc -TcpPort 445 
```
### Ejecución Remota de Scripts
#### Comandos: Invoke-Command
```
Invoke-Command -ComputerName $pc -ScriptBlock {Get-NetIPAddress | select IPAddress}  -Credential $Cred
```

## Detectando irregularidades
### Ver que permisos tiene sobre un archivo o directorio.
#### Comandos: Get-Acl
```
Get-Acl "C:\Windows\System32\cmd.exe" | fl
(Get-Acl -Path "C:\Windows\System32\cmd.exe").Access
(Get-Acl -Path "C:\Windows\System32\cmd.exe").Access.IdentityReference
```
### Ver eventos y registros del sistema
#### Comandos: Get-WinEvent | Módulo: PSEventViewer
#### Ver la lista de log diponibles en un Host
```
Get-WinEvent -ListLog *

Get-WinEvent -ListLog * -ComputerName $s -Credential $Cred
```
#### Obtener todos los proveedores de registros de eventos que escriben en un registro específico
```
(Get-WinEvent -ListLog Application).ProviderNames
```
#### Obtener los nombres de los proveedores de registros de eventos que contienen una cadena específica
```
Get-WinEvent -ListProvider *Policy*
```
#### Obtener todos los registros de un solo host.
```
$WMI = Get-CimInstance -ClassName 'Win32_NTEventlogfile' -ComputerName pandc01
$WMI | ft -AutoSize
$WMI[0] | fl
```
#### PSEventViewer
```
Install-Module PSEventViewer -Force
Import-Module PSEventViewer  
Get-Command -Module PSEventViewer 
Get-Events -maxevents 5 -verbose -LogType 'Setup'
Get-Events -maxevents 5 -verbose -LogType 'Setup' -ID 2
Get-Events -maxevents 5 -verbose -LogType 'Setup' -ID 2 | fl $_.Message
```

#### Comparando la versión de un archivo con los existente en nuestra BBDD
```
$version = "10.0.19041.1 (WinBuild.160101.0800)"
$appPath = "C:\Windows\System32\cmd.exe"
$appVersion = (get-item $apppath).versioninfo.fileversion
if( ( Test-Path $appPath) -and ( $appVersion -eq $version ) ){'Current Version'} else {'New Version'}
$(get-item C:\Windows\System32\cmd.exe).LastAccessTime
```

## Protegiendo tu infraestructura 
### Creando registros de eventos
#### Comandos: New-WinEvent
```
New-WinEvent -ProviderName "Microsoft-Windows-PowerShell" -Id 4103 -Payload @("Logs con Powershell", "La estamos pasando genial en el BSidesPA 2021", "BsidesPA2021")
Get-WinEvent -FilterHashtable @{ ProviderName="Microsoft-Windows-PowerShell"; Id = 4103 } -MaxEvents 1 | fl
```
### Windows update (PowerShell 5)
#### Comandos: Get-WindowsUpdate - Add-WUServiceManager - Install-WindowsUpdate
```
Install-Module PSWindowsUpdate -Force
Import-Module PSWindowsUpdate

Add-WUServiceManager -MicrosoftUpdate -Confirm:$false   
Get-WindowsUpdate
Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -asJob

$cred = Get-Credential
Update-WUModule -ComputerName ws2019 -local -credentinal $cred
```
### Gestionar Windows Defender
#### Cambiar las preferencias en Microsoft Defender
```
Get-MpPreference
Set-MpPreference -ExclusionExtension docx
Remove-MpPreference -ExclusionExtension docx
```
#### Ver el estado del Antivirus
```
Get-MpPreference |select DisableRealtimeMonitoring
```
#### Para activar la supervisión en tiempo real, ejecute el siguiente comando:
```
Set-MpPreference -DisableRealtimeMonitoring $false
```
#### Para desactivar la supervisión en tiempo real de Windows Defender, ejecute el siguiente comando:
```
Set-MpPreference -DisableRealtimeMonitoring $true
```
#### Tiempo de cuarentena antes de la eliminación
```
Set-MpPreference -QuarantinePurgeItemsAfterDelay 30
```
#### Actualiza las definiciones antimalware de un pc.
```
Update-MpSignature -asjob
```
#### Iniciar un scan de un os
```
Start-MpScan -asjob
```
#### Cómo eliminar una amenaza activa en Microsoft Defender
```
get-MpThreat
Remove-MpThreat
```
### Administrar el Windows Firewall
#### Comandos: Get-NetFirewallProfile  
#### Ver el estado del firewall
```
Get-NetFirewallProfile | Format-Table Name, Enabled
```
#### Deshabilitar firewall
```
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
```
#### Habilitar firewall
```
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
```

## Auditando con Powershell
### Uso del módulo "Pester"
```
Install-Module pester -Force
Import-Module pester

Get-Content .\Pester\RegSettings.ps1
Invoke-Pester -Path .\Pester\RegSettings.ps1
Invoke-Pester -Path .\Pester\RegSettings.ps1 -PassThru

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -name 'RestrictAnonymous' -Value '0' -Force

Invoke-Pester -Path .\Pester\RegSettings.ps1

Get-Content .\Pester\Linux_test.ps1
```

## ¿Qué hacer déspues de esta Presentación?
- Descargar e Instalar (o actualizar) PowerShell 7"
  Ingresa a https://github.com/PowerShell/PowerShell
    Read-Host
- Aprende los aspectos básicos
  "Estructura de los comandos, Operadores lógicos, condicionales y ciclos
- Revisa el repositorio de Github donde está lo que hemos visto hoy"
  https://github.com/soysoliscarlos/BsidesPA2021


## Referencias
https://www.alitajran.com/enable-windows-firewall-with-powershell/
https://www.itechtics.com/enable-disable-windows-defender/
https://www.windowscentral.com/how-manage-microsoft-defender-antivirus-powershell-windows-10
https://docs.microsoft.com/en-us/powershell/module/defender/?view=win10-ps
http://www.freetechanswers.com/2020/04/configuration-manager-sccm-powershell.html
https://evotec.xyz/powershell-everything-you-wanted-to-know-about-event-logs/

https://github.com/EvotecIT/PSEventViewer
https://evotec.xyz/hub/scripts/pseventviewer-powershell-module/
https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-7.1
https://www.sans.org/blog/powershell-tools-i-use-audit-and-compliance-measurement/
https://github.com/pester/Pester
http://woshub.com/pswindowsupdate-module/

