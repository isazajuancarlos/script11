# SPDX-FileCopyrightText: 2026 Juan Carlos Isaza
# SPDX-License-Identifier: LicenseRef-Xiliux-Propietario
<#
.SYNOPSIS
Windows 11 Pro – Hardening, Privacidad, Debloat y Rendimiento (script ÚNICO).

Adaptado y optimizado para Windows 11 **Pro** desde el script de LTSC 2024
(/mnt/data/scripts/win11ltsc/win11.ps1). La diferencia de fondo: LTSC viene limpio,
Pro trae TODA la carga de consumidor (apps de tienda, anuncios de Inicio/pantalla de
bloqueo, Copilot/Recall, Teams consumer, OneDrive). Por eso este script CONSERVA todo
el hardening/privacidad/rendimiento probado y AÑADE el debloat que Pro necesita.

Auto-eleva a Administrador (es un solo .ps1, sin run.bat). Opt-in por switch lo peligroso.

.PARAMETER EnableVBS
Credential Guard + VBS/HVCI. Riesgo: HVCI puede bloquear drivers de kernel (VPN/AV).

.PARAMETER EnableAccountPolicy
Bloqueo de cuenta + longitud mínima de contraseña. Riesgo: en equipo de un solo usuario.

.PARAMETER RemoveOneDrive
Desinstala OneDrive por completo. Opt-in: muchos lo usan; no se quita en una corrida normal.

.PARAMETER KeepBloat
NO quitar las apps de consumidor (debloat). Por defecto SÍ se quitan (es el punto en Pro).
#>

[CmdletBinding()]
param(
    [switch]$EnableVBS,
    [switch]$EnableAccountPolicy,
    [switch]$RemoveOneDrive,
    [switch]$KeepBloat
)

# =========================
# 0a. AUTO-ELEVACIÓN (script único: sin run.bat)
# =========================
$idActual = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object System.Security.Principal.WindowsPrincipal($idActual)
if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Elevando a Administrador..." -ForegroundColor Yellow
    $hostExe = (Get-Process -Id $PID).Path   # powershell.exe o pwsh.exe
    $argv = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$PSCommandPath`"") + $args
    try {
        Start-Process -FilePath $hostExe -Verb RunAs -ArgumentList $argv
    } catch {
        Write-Host "No se pudo elevar: $($_.Exception.Message)" -ForegroundColor Red
    }
    exit
}

# =========================
# 1. UTILIDADES Y LOGGING
# =========================
$script:Results = [System.Collections.ArrayList]::new()

function Ensure-Key {
    param([string]$Path)
    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force -ErrorAction SilentlyContinue | Out-Null
    }
}

function Log-Result {
    param([string]$Action, [string]$Status, [string]$Detail)
    $entry = [PSCustomObject]@{
        Action    = $Action
        Status    = $Status
        Detail    = $Detail
        Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    }
    [void]$script:Results.Add($entry)
    switch ($Status) {
        "OK"   { Write-Host "[OK] $Action - $Detail" -ForegroundColor Green }
        "SKIP" { Write-Host "[SKIP] $Action - $Detail" -ForegroundColor Yellow }
        default { Write-Host "[FAIL] $Action - $Detail" -ForegroundColor Red }
    }
}

function Set-RegistryValue {
    param([string]$Path, [string]$Name, [object]$Value, [string]$Type = "DWord")
    Ensure-Key $Path
    try {
        New-ItemProperty -Path $Path -Name $Name -PropertyType $Type -Value $Value -Force -ErrorAction Stop | Out-Null
        Log-Result $Name "OK" "$Path = $Value"
        return $true
    } catch {
        $ex = $_.Exception
        # Windows protege ciertos valores con una ACL que deniega la escritura incluso a Admin/SYSTEM.
        # Eso NO es un error del script: se registra como SKIP visible, no como FAIL rojo.
        if ($ex -is [System.UnauthorizedAccessException] -or $ex -is [System.Security.SecurityException]) {
            Log-Result $Name "SKIP" "Protegido por ACL del SO (no modificable): $Path"
        } else {
            Log-Result $Name "FAIL" "Error: $($ex.Message)"
        }
        return $false
    }
}

# =========================
# 1b. APLICACIÓN POR USUARIO (HKCU → HKU real)
# =========================
function Apply-UserHiveSettings {
    param([string]$HiveRoot)
    $base = "Registry::$HiveRoot"

    # --- IA, GameBar, barra de tareas (igual que LTSC) ---
    Set-RegistryValue "$base\Software\Policies\Microsoft\Windows\WindowsCopilot" "TurnOffWindowsCopilot" 1
    Set-RegistryValue "$base\Control Panel\Desktop\WindowMetrics"                "MinAnimate"              "0" "String"
    Set-RegistryValue "$base\Software\Microsoft\GameBar"                         "AllowAutoGameMode"       0
    Set-RegistryValue "$base\Software\Microsoft\Windows\CurrentVersion\GameDVR"  "AppCaptureEnabled"       0
    Set-RegistryValue "$base\System\GameConfigStore"                             "GameDVR_Enabled"         0
    Set-RegistryValue "$base\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "TaskbarDa"           0
    Set-RegistryValue "$base\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "ShowTaskViewButton"  0

    # --- PRO: anuncios y "sugerencias" (ContentDeliveryManager) ---
    # ESTO es lo que LTSC no necesita y Pro SÍ: Pro auto-instala apps promocionadas y pone
    # anuncios en Inicio y en la pantalla de bloqueo. Se apaga por usuario (es HKCU).
    $cdm = "$base\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
    foreach ($n in @(
        "ContentDeliveryAllowed","FeatureManagementEnabled","OemPreInstalledAppsEnabled",
        "PreInstalledAppsEnabled","PreInstalledAppsEverEnabled","SilentInstalledAppsEnabled",
        "SoftLandingEnabled","SystemPaneSuggestionsEnabled","SubscribedContentEnabled",
        "RotatingLockScreenEnabled","RotatingLockScreenOverlayEnabled",
        "SubscribedContent-310093Enabled","SubscribedContent-338387Enabled",
        "SubscribedContent-338388Enabled","SubscribedContent-338389Enabled",
        "SubscribedContent-338393Enabled","SubscribedContent-353694Enabled",
        "SubscribedContent-353696Enabled","SubscribedContent-353698Enabled")) {
        Set-RegistryValue $cdm $n 0
    }
    # Recomendaciones "Iris" del menú Inicio (24H2) y rastro de documentos recientes.
    $adv = "$base\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    Set-RegistryValue $adv "Start_IrisRecommendations" 0
    Set-RegistryValue $adv "Start_TrackDocs"           0
    # "Obtén consejos y sugerencias al usar Windows" (notificaciones promocionales).
    Set-RegistryValue "$base\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.Suggested" "Enabled" 0
    Set-RegistryValue "$base\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "ShowSyncProviderNotifications" 0
    # Pantalla de bloqueo: Windows Spotlight → imagen fija (sin "datos curiosos"/anuncios).
    Set-RegistryValue "$base\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SubscribedContent-338387Enabled" 0

    # --- Privacidad por-usuario minada de baselines (Sophia/simeononsecurity, MIT) 2026-11-10 ---
    # Experiencias "a medida" con datos de diagnóstico, ID de publicidad, voz en línea y Feedback
    # Hub: todo HKCU, por eso va aquí (no en 5h, que es HKLM). Complementa la privacidad HKLM.
    Set-RegistryValue "$base\Software\Microsoft\Windows\CurrentVersion\Privacy" "TailoredExperiencesWithDiagnosticDataEnabled" 0
    Set-RegistryValue "$base\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" "Enabled" 0
    Set-RegistryValue "$base\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" "HasAccepted" 0
    Set-RegistryValue "$base\Software\Microsoft\Siuf\Rules" "NumberOfSIUFInPeriod" 0

    # --- IA por-usuario minada de RemoveWindowsAI (capa limpia) 2026-11-10 ---
    $aiU = "$base\Software\Policies\Microsoft\Windows\WindowsAI"
    Set-RegistryValue $aiU "AllowRecallEnablement" 0
    Set-RegistryValue $aiU "TurnOffSavingSnapshots" 1
    Set-RegistryValue $aiU "DisableClickToDo" 1
    Set-RegistryValue "$base\Software\Microsoft\Windows\CurrentVersion\WindowsCopilot" "AllowCopilotRuntime" 0
    # Recolección implícita de tinta/texto y contactos para "personalización" de entrada (HKCU).
    Set-RegistryValue "$base\Software\Microsoft\InputPersonalization" "RestrictImplicitInkCollection" 1
    Set-RegistryValue "$base\Software\Microsoft\InputPersonalization" "RestrictImplicitTextCollection" 1
    Set-RegistryValue "$base\Software\Microsoft\InputPersonalization\TrainedDataStore" "HarvestContacts" 0
    Set-RegistryValue "$base\Software\Microsoft\Windows\CurrentVersion\CPSS\Store\InkingAndTypingPersonalization" "Value" 0
    # Que Windows NO vuelva a preinstalar el PWA de Copilot (le dice que ya está hecho).
    $pwa = "$base\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoInstalledPWAs"
    Set-RegistryValue $pwa "CopilotPWAPreinstallCompleted" 1
    # Bloquea el ítem "Preguntar a Copilot" del menú contextual del Explorador.
    Set-RegistryValue "$base\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" "{CB3B0003-8088-4EDE-8769-8B354AB2FF8C}" "" "String"
}

function Invoke-ForAllUserHives {
    Write-Host "`n=== Aplicando configuración por usuario ===" -ForegroundColor Cyan

    # 1. Hives de usuario YA cargados (sesiones activas / perfiles montados).
    $loadedSids = @(
        Get-ChildItem "Registry::HKEY_USERS" -ErrorAction SilentlyContinue |
            ForEach-Object { $_.PSChildName } |
            Where-Object { $_ -match '^S-1-5-21-\d+-\d+-\d+-\d+$' }
    )
    foreach ($sid in $loadedSids) {
        Apply-UserHiveSettings "HKEY_USERS\$sid"
        Log-Result "UserHive" "OK" "Aplicado a hive cargado ($sid)"
    }

    # 2. Perfiles EXISTENTES no cargados: montar NTUSER.DAT, aplicar, desmontar.
    $profiles = Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue |
        Where-Object { -not $_.Special -and $_.LocalPath -and (Test-Path "$($_.LocalPath)\NTUSER.DAT") }
    foreach ($p in $profiles) {
        if ($loadedSids -contains $p.SID) { continue }
        $tmpKey = "TMP_$($p.SID)"
        reg load "HKU\$tmpKey" "$($p.LocalPath)\NTUSER.DAT" 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Apply-UserHiveSettings "HKEY_USERS\$tmpKey"
            [System.GC]::Collect(); [System.GC]::WaitForPendingFinalizers()
            reg unload "HKU\$tmpKey" 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Log-Result "UserHive" "OK" "Aplicado a perfil no cargado ($($p.SID))"
            } else {
                Log-Result "UserHive" "FAIL" "Aplicado pero el hive no se desmontó ($($p.SID)); quedará cargado hasta reiniciar"
            }
        } else {
            Log-Result "UserHive" "SKIP" "No se pudo montar el hive de $($p.LocalPath)"
        }
    }

    # 3. Perfil Default → usuarios FUTUROS heredan la config.
    $defaultDat = "C:\Users\Default\NTUSER.DAT"
    if (Test-Path $defaultDat) {
        $tmpKey = "DEFAULT_HIVE_TEMP"
        reg load "HKU\$tmpKey" $defaultDat 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Apply-UserHiveSettings "HKEY_USERS\$tmpKey"
            [System.GC]::Collect(); [System.GC]::WaitForPendingFinalizers()
            reg unload "HKU\$tmpKey" 2>&1 | Out-Null
            if ($LASTEXITCODE -ne 0) {
                Log-Result "DefaultHive" "FAIL" "No se pudo desmontar el hive Default (puede quedar bloqueado)"
            } else {
                Log-Result "DefaultHive" "OK" "Aplicado al perfil Default"
            }
        } else {
            Log-Result "DefaultHive" "SKIP" "No se pudo montar el hive Default"
        }
    }
}

# =========================
# 2. TELEMETRÍA, IA Y PRIVACIDAD
# =========================
function Apply-UltimatePrivacy {
    Write-Host "`n=== Aplicando Privacidad, Bloqueo de IA y Telemetría ===" -ForegroundColor Cyan

    $telemetryServices = @("DiagTrack", "dmwappushservice", "MapsBroker", "lfsvc", "WerSvc")
    foreach ($service in $telemetryServices) {
        if (Get-Service $service -ErrorAction SilentlyContinue) {
            Stop-Service $service -Force -ErrorAction SilentlyContinue
            Set-Service $service -StartupType Disabled -ErrorAction SilentlyContinue
            Log-Result "ServiceDisable" "OK" "$service detenido"
        }
    }

    # TELEMETRÍA. OJO Pro (honesto, D30): el nivel 0 (Security) SOLO lo respetan
    # Enterprise/Education/LTSC. En **Pro** el piso efectivo es 1 (Required/Basic): poner 0
    # no da error pero Windows lo trata como 1. Se deja en 0 (no empeora) y se documenta.
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" 0
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "DoNotShowFeedbackNotifications" 1
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "DisableEnterpriseAuthProxy" 1
    # Limita la telemetría a lo mínimo con el valor que Pro SÍ respeta.
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "LimitEnhancedDiagnosticDataWindowsAnalytics" 0

    # COPILOT / RECALL / IA (Windows 11 24H2 Pro)
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" "TurnOffWindowsCopilot" 1
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" "DisableAIDataAnalysis" 1   # Recall
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" "TurnOffWindowsCopilot" 1

    # WIDGETS Y CHAT
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Dsh" "AllowNewsAndInterests" 0
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Chat" "ChatIcon" 3

    # BÚSQUEDA WEB Y BING
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "DisableWebSearch" 1
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "ConnectedSearchUseWeb" 0
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "EnableDynamicContentInWSB" 0
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowCortana" 0

    # PRIVACIDAD GENERAL
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" "DisabledByGroupPolicy" 1
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "PublishUserActivities" 0
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "UploadUserActivities" 0
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" "DisableLocation" 1
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" "DisableWindowsLocationProvider" 1

    # WINDOWS ERROR REPORTING
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" "Disabled" 1
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" "DontSendAdditionalData" 1

    Log-Result "Privacy" "OK" "Telemetría (piso Pro=1), Copilot, Recall, Widgets y WER bloqueados"
}

# =========================
# 2b. PRO: DEBLOAT DE APPS DE CONSUMIDOR
# =========================
function Remove-Bloatware {
    Write-Host "`n=== Debloat Pro: quitando apps de consumidor ===" -ForegroundColor Cyan

    # Apps a QUITAR (comodines sobre el nombre del paquete). Consumer/promocionadas que Pro
    # trae y un equipo de trabajo endurecido no usa. Riesgo medido (D18): ninguna es del SO.
    $quitar = @(
        "Microsoft.549981C3F5F10",          # Cortana
        "Microsoft.BingNews","Microsoft.BingWeather","Microsoft.BingSearch",
        "Microsoft.Copilot","Microsoft.Windows.Copilot","Microsoft.MicrosoftOfficeHub",
        "Microsoft.Clipchamp","Microsoft.GamingApp","Microsoft.XboxApp",
        "Microsoft.XboxGamingOverlay","Microsoft.XboxGameOverlay","Microsoft.Xbox.TCUI",
        "Microsoft.XboxSpeechToTextOverlay","Microsoft.GetHelp","Microsoft.Getstarted",
        "Microsoft.MicrosoftSolitaireCollection","Microsoft.People","Microsoft.Todos",
        "Microsoft.PowerAutomateDesktop","Microsoft.MicrosoftStickyNotes",
        "Microsoft.WindowsFeedbackHub","Microsoft.Messaging","Microsoft.OneConnect",
        "Microsoft.MixedReality.Portal","Microsoft.SkypeApp","Microsoft.Wallet",
        "Microsoft.Microsoft3DViewer","Microsoft.Print3D","MicrosoftTeams","MSTeams",
        "Microsoft.ZuneMusic","Microsoft.ZuneVideo","Microsoft.WindowsMaps",
        "Microsoft.MicrosoftJournal","Clipchamp.Clipchamp","Microsoft.OutlookForWindows",
        # --- minado de Raphire/Win11Debloat (MIT) 2026-11-10: bloat de PRIMERA PARTE que faltaba.
        # Solo Microsoft; NO se añade Camera/QuickAssist/YourPhone ni apps de terceros mainstream
        # (Spotify/Netflix/LinkedIn…) por uso legítimo (D18). Las ausentes se saltan sin error.
        "Microsoft.Windows.AIHub",                                   # hub de IA de Windows
        "Microsoft.3DBuilder","Microsoft.NetworkSpeedTest",
        "Microsoft.BingFinance","Microsoft.BingFoodAndDrink","Microsoft.BingHealthAndFitness",
        "Microsoft.BingSports","Microsoft.BingTranslator","Microsoft.BingTravel",
        "Microsoft.WindowsAlarms","Microsoft.WindowsSoundRecorder","Microsoft.Office.OneNote",
        "Microsoft.Office.Sway","Microsoft.MicrosoftPowerBIForWindows",
        "Microsoft.PCManager","Microsoft.MicrosoftPCManager","MicrosoftCorporationII.MicrosoftFamily",
        "Microsoft.windowscommunicationsapps",                       # Correo y Calendario UWP (legado)
        "MicrosoftWindows.Client.WebExperience","Microsoft.WidgetsPlatformRuntime"  # host de Widgets (ya off por política)
    )
    # KEEP duro: aunque casara un comodín, esto NUNCA se quita (romper el SO/base no es debloat).
    $conservar = @(
        "Microsoft.WindowsStore","Microsoft.StorePurchaseApp","Microsoft.DesktopAppInstaller",
        "Microsoft.WindowsTerminal","Microsoft.WindowsNotepad","Microsoft.Paint",
        "Microsoft.Windows.Photos","Microsoft.WindowsCalculator","Microsoft.ScreenSketch",
        "Microsoft.SecHealthUI","Microsoft.VCLibs","Microsoft.NET","Microsoft.UI.Xaml",
        "Microsoft.WebView2","Microsoft.WindowsAppRuntime","Microsoft.HEIF","Microsoft.VP9",
        "Microsoft.WebMediaExtensions","Microsoft.AV1","Microsoft.StartExperiences"
    )
    function EsConservado([string]$n) { foreach ($k in $conservar) { if ($n -like "$k*") { return $true } } return $false }

    $quitadas = 0
    # 1) Instaladas para cualquier usuario.
    foreach ($patron in $quitar) {
        Get-AppxPackage -AllUsers -Name "$patron*" -ErrorAction SilentlyContinue | ForEach-Object {
            if (-not (EsConservado $_.Name)) {
                Remove-AppxPackage -AllUsers -Package $_.PackageFullName -ErrorAction SilentlyContinue
                $quitadas++
            }
        }
    }
    # 2) Aprovisionadas (para que NO vuelvan en perfiles/instalaciones futuras).
    $prov = 0
    foreach ($patron in $quitar) {
        Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -like "$patron*" -and -not (EsConservado $_.DisplayName) } |
            ForEach-Object {
                Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName -ErrorAction SilentlyContinue | Out-Null
                $prov++
            }
    }
    Log-Result "Debloat" "OK" "$quitadas apps quitadas + $prov aprovisionadas (no vuelven); Store/Terminal/Notepad/Photos/Calc conservados"

    # 3) Recall como característica opcional (24H2): quitarla además de la política.
    try {
        $recall = Get-WindowsOptionalFeature -Online -FeatureName "Recall" -ErrorAction Stop
        if ($recall.State -eq "Enabled") {
            Disable-WindowsOptionalFeature -Online -FeatureName "Recall" -NoRestart -ErrorAction Stop | Out-Null
            Log-Result "Recall" "OK" "Característica Recall deshabilitada"
        } else {
            Log-Result "Recall" "SKIP" "Recall no habilitado"
        }
    } catch {
        Log-Result "Recall" "SKIP" "Recall no es una característica en este equipo"
    }
}

# =========================
# 2c. PRO: ONEDRIVE (opt-in -RemoveOneDrive)
# =========================
function Remove-OneDrive {
    Write-Host "`n=== Quitando OneDrive (opt-in) ===" -ForegroundColor Cyan
    Get-Process OneDrive -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    $setup = @("$env:SystemRoot\System32\OneDriveSetup.exe", "$env:SystemRoot\SysWOW64\OneDriveSetup.exe")
    $hecho = $false
    foreach ($s in $setup) {
        if (Test-Path $s) {
            Start-Process $s -ArgumentList "/uninstall" -Wait -ErrorAction SilentlyContinue
            $hecho = $true
        }
    }
    # Política: impedir el uso de OneDrive para almacenamiento de archivos.
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" "DisableFileSyncNGSC" 1
    if ($hecho) { Log-Result "OneDrive" "OK" "OneDrive desinstalado + sincronización deshabilitada por política" }
    else        { Log-Result "OneDrive" "SKIP" "No se encontró OneDriveSetup; solo se aplicó la política" }
}

# =========================
# 2d. QUITA DE IA EXTRA (mindalá: zoicware/RemoveWindowsAI) — SOLO políticas de registro
# =========================
# Minado 2026-11-10. Se toma SOLO la capa limpia y reversible de esa fuente: políticas que apagan
# Copilot/Recall/Click-to-Do/Paint-AI/Edge-AI y el acceso de apps a modelos de IA. NO se toma su
# cirugía de SO (borrar DLLs por TrustedInstaller, manipular CBS/WinSxS, sc.exe delete, .cab falso):
# es frágil y rompe los LCU/actualizaciones (D1/D18). La política basta y la red de rollback la cubre.
function Apply-AILockdownExtra {
    Write-Host "`n=== Quita de IA extra (políticas) ===" -ForegroundColor Cyan

    # --- WindowsAI: más allá de TurnOffWindowsCopilot/DisableAIDataAnalysis de la sección 2 ---
    $ai = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI"
    Set-RegistryValue $ai "AllowRecallEnablement" 0        # Recall no se puede activar
    Set-RegistryValue $ai "TurnOffSavingSnapshots" 1       # Recall no guarda capturas
    Set-RegistryValue $ai "DisableClickToDo" 1             # Click-to-Do off
    Set-RegistryValue $ai "DisableSettingsAgent" 1         # agente de IA en Configuración off
    Set-RegistryValue $ai "DisableAgentConnectors" 1
    Set-RegistryValue $ai "DisableAgentWorkspaces" 1
    Set-RegistryValue $ai "DisableRemoteAgentConnectors" 1

    # --- Acceso de apps a IA generativa / modelos del sistema: denegado por política (2 = Force Deny) ---
    $appp = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"
    Set-RegistryValue $appp "LetAppsAccessGenerativeAI" 2
    Set-RegistryValue $appp "LetAppsAccessSystemAIModels" 2

    # --- ConsentStore de máquina: sin IA generativa ni modelos del sistema ---
    $cs = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore"
    Set-RegistryValue "$cs\generativeAI"  "Value" "Deny" "String"
    Set-RegistryValue "$cs\systemAIModels" "Value" "Deny" "String"

    # --- Paint: sin funciones de IA generativa ---
    $paint = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Paint"
    foreach ($n in @("DisableImageCreator","DisableCocreator","DisableGenerativeFill","DisableGenerativeErase","DisableRemoveBackground")) {
        Set-RegistryValue $paint $n 1
    }

    # --- Edge: sin Copilot/IA en el navegador (políticas empresariales de Edge) ---
    $edge = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    Set-RegistryValue $edge "HubsSidebarEnabled" 0           # Copilot en barra lateral
    Set-RegistryValue $edge "CopilotPageContext" 0
    Set-RegistryValue $edge "ComposeInlineEnabled" 0         # IA de escritura en línea
    Set-RegistryValue $edge "BuiltInAIAPIsEnabled" 0
    Set-RegistryValue $edge "EdgeHistoryAISearchEnabled" 0
    Set-RegistryValue $edge "GenAILocalFoundationalModelSettings" 1   # 1 = modelo local off

    # --- AI Fabric Service: DESHABILITADO (no se borra —nuestro estilo es reversible, no sc.exe delete) ---
    if (Get-Service WSAIFabricSvc -ErrorAction SilentlyContinue) {
        Stop-Service WSAIFabricSvc -Force -ErrorAction SilentlyContinue
        Set-Service WSAIFabricSvc -StartupType Disabled -ErrorAction SilentlyContinue
    }

    Log-Result "AILockdown" "OK" "Recall/Click-to-Do/agentes off, apps sin IA generativa, Paint-AI off, Edge-AI off, WSAIFabricSvc deshabilitado"
}

# =========================
# 3. UI Y EXPERIENCIA
# =========================
function Customize-Win11UI {
    Write-Host "`n=== Limpiando Interfaz Windows 11 ===" -ForegroundColor Cyan

    # Ocultar "Recomendado" del Inicio. OJO Pro: HideRecommendedSection por política SOLO
    # aplica en Enterprise/Education; en Pro el efecto real lo dan las claves CDM por usuario
    # (Apply-UserHiveSettings). Se deja la política igual (inerte en Pro, útil si sube a Ent).
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "HideRecommendedSection" 1

    # Sugerencias en la nube / "experiencias de consumidor". En Pro 24H2 Microsoft redujo el
    # efecto de esta política; el debloat + CDM son el camino real. Se deja (no estorba).
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableWindowsConsumerFeatures" 1
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableConsumerAccountStateContent" 1
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableSoftLanding" 1
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableCloudOptimizedContent" 1

    Log-Result "UI" "OK" "Inicio limpio (recomendados/anuncios vía CDM por usuario + políticas)"
}

# =========================
# 4. WINDOWS UPDATE
# =========================
function Configure-WindowsUpdatePerformance {
    Write-Host "`n=== Optimizando Windows Update (Sin Drivers) ===" -ForegroundColor Cyan

    $wuBase = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
    $wuAU = "$wuBase\AU"
    Remove-ItemProperty -Path $wuBase -Name "UseWUServer" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $wuAU -Name "UseWUServer" -ErrorAction SilentlyContinue

    Set-RegistryValue $wuBase "ExcludeWUDriversInQualityUpdate" 1
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" "DODownloadMode" 0
    Set-RegistryValue $wuAU "AUOptions" 4
    Set-RegistryValue $wuAU "NoAutoRebootWithLoggedOnUsers" 1
    Set-RegistryValue $wuBase "DeferQualityUpdates" 0
    Set-RegistryValue $wuBase "DeferQualityUpdatesPeriodInDays" 0
    # Pro recibe feature updates más seguido que LTSC: diferir un poco evita saltos sorpresa,
    # sin bloquearlos del todo (en Pro el máximo real es 365 días).
    Set-RegistryValue $wuBase "DeferFeatureUpdates" 1
    Set-RegistryValue $wuBase "DeferFeatureUpdatesPeriodInDays" 120

    Log-Result "WindowsUpdate" "OK" "Update: solo seguridad (0 días), sin drivers, feature updates diferidos 120 d"
}

# =========================
# 5. SEGURIDAD Y HARDENING
# =========================
function Configure-SmartHardening {
    Write-Host "`n=== Aplicando Hardening ===" -ForegroundColor Cyan

    $uacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    Set-RegistryValue $uacPath "EnableLUA" 1
    Set-RegistryValue $uacPath "ConsentPromptBehaviorAdmin" 1
    Set-RegistryValue $uacPath "ConsentPromptBehaviorUser" 1
    Set-RegistryValue $uacPath "PromptOnSecureDesktop" 1
    Set-RegistryValue $uacPath "FilterAdministratorToken" 1
    Set-RegistryValue $uacPath "EnableInstallerDetection" 1

    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnableSmartScreen" 1
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "ShellSmartScreenLevel" "Warn" "String"

    if (Get-Command Set-MpPreference -ErrorAction SilentlyContinue) {
        Set-MpPreference -PUAProtection Enabled           -ErrorAction SilentlyContinue
        Set-MpPreference -MAPSReporting Advanced          -ErrorAction SilentlyContinue
        Set-MpPreference -SubmitSamplesConsent 1          -ErrorAction SilentlyContinue
        Set-MpPreference -CloudBlockLevel High            -ErrorAction SilentlyContinue
        Set-MpPreference -EnableNetworkProtection Enabled -ErrorAction SilentlyContinue
        Log-Result "Defender" "OK" "PUA, nube (MAPS), Network Protection y muestras-seguras activados"
    } else {
        Log-Result "Defender" "SKIP" "Set-MpPreference no disponible"
    }

    if (Get-Command Add-MpPreference -ErrorAction SilentlyContinue) {
        $asrBlock = @{
            "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" = "Robo de credenciales desde LSASS"
            "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" = "Ejecutables desde correo/webmail"
            "e6db77e5-3df2-4cf1-b95a-636979351e5b" = "Persistencia vía suscripción WMI"
            "d1e49aac-8f56-4280-b9ba-993a6d77406c" = "Procesos desde PSExec/WMI"
            "56a863a9-875e-4185-98a7-b882c64b5ce5" = "Drivers firmados vulnerables"
            "5beb7efe-fd9a-4556-801d-275e5ffc04cc" = "Scripts ofuscados"
            "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" = "Procesos hijos de Adobe Reader"
            "d3e037e1-3eb8-44c8-a917-57927947596d" = "JS/VBScript lanzando descargas"
            "26190899-1602-49e8-8b27-eb1d0a1ce869" = "Procesos hijos de Outlook"
            "c1db55ab-c21a-4637-bb3f-a12568109d35" = "Anti-ransomware avanzado"
        }
        foreach ($id in $asrBlock.Keys) {
            Add-MpPreference -AttackSurfaceReductionRules_Ids $id -AttackSurfaceReductionRules_Actions Enabled -ErrorAction SilentlyContinue
        }
        $asrAudit = @{
            "d4f940ab-401b-4efc-aadc-ad5f3c50688a" = "Office creando procesos hijos (audit)"
            "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b" = "API Win32 desde macros Office"
            "3b576869-a4ec-4529-8536-b80a7769e899" = "Office creando contenido ejecutable"
            "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84" = "Office inyectando en otros procesos"
            "01443614-cd74-433a-b99e-2ecdc07bfc25" = "Ejecutables sin prevalencia/confianza"
        }
        foreach ($id in $asrAudit.Keys) {
            Add-MpPreference -AttackSurfaceReductionRules_Ids $id -AttackSurfaceReductionRules_Actions AuditMode -ErrorAction SilentlyContinue
        }
        Add-MpPreference -AttackSurfaceReductionRules_Ids "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" -AttackSurfaceReductionRules_Actions Disabled -ErrorAction SilentlyContinue
        Log-Result "ASR" "OK" "10 reglas en bloqueo (incl. anti-ransomware), 5 en auditoría, USB permitido"
    }

    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -ErrorAction SilentlyContinue
    Log-Result "Security" "OK" "Hardening aplicado"
}

# =========================
# 5b. CREDENCIALES, RED Y SUPERFICIE
# =========================
function Apply-NetworkAndCredentialHardening {
    Write-Host "`n=== Endureciendo credenciales y resolución de nombres ===" -ForegroundColor Cyan

    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RunAsPPL" 1
    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" "UseLogonCredential" 0

    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" "EnableMulticast" 0
    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" "EnableMDNS" 0
    $nbPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces"
    if (Test-Path $nbPath) {
        Get-ChildItem $nbPath | ForEach-Object { Set-RegistryValue $_.PSPath "NetbiosOptions" 2 }
    }

    Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoDriveTypeAutoRun" 255
    Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoAutorun" 1

    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" "EnableScriptBlockLogging" 1
    try {
        Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart -ErrorAction Stop | Out-Null
        Log-Result "PowerShellV2" "OK" "PowerShell v2 deshabilitado"
    } catch {
        Log-Result "PowerShellV2" "SKIP" "No se pudo deshabilitar PS v2: $($_.Exception.Message)"
    }

    try {
        Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction Stop | Out-Null
        Log-Result "SMBv1" "OK" "SMBv1 deshabilitado"
    } catch {
        Log-Result "SMBv1" "SKIP" "SMBv1 ya ausente o no removible: $($_.Exception.Message)"
    }
    if (Get-Command Set-SmbServerConfiguration -ErrorAction SilentlyContinue) {
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction SilentlyContinue
    }

    $srvParams = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
    $wkParams  = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
    Set-RegistryValue $srvParams "RequireSecuritySignature" 1
    Set-RegistryValue $srvParams "EnableSecuritySignature"  1
    Set-RegistryValue $wkParams  "RequireSecuritySignature" 1
    Set-RegistryValue $wkParams  "EnableSecuritySignature"  1
    if (Get-Command Set-SmbServerConfiguration -ErrorAction SilentlyContinue) {
        Set-SmbServerConfiguration -RequireSecuritySignature $true -Force -ErrorAction SilentlyContinue
    }
    if (Get-Command Set-SmbClientConfiguration -ErrorAction SilentlyContinue) {
        Set-SmbClientConfiguration -RequireSecuritySignature $true -Force -ErrorAction SilentlyContinue
    }

    $lsa = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    Set-RegistryValue $lsa "LmCompatibilityLevel" 5
    $msv = "$lsa\MSV1_0"
    Set-RegistryValue $msv "NtlmMinClientSec" 537395200
    Set-RegistryValue $msv "NtlmMinServerSec" 537395200
    Set-RegistryValue $lsa "RestrictAnonymous"    1
    Set-RegistryValue $lsa "RestrictAnonymousSAM" 1

    Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" "Enabled" 0
    Set-RegistryValue "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows Script Host\Settings" "Enabled" 0

    Log-Result "NetCredHardening" "OK" "LSA PPL, WDigest, LLMNR/NetBIOS/mDNS, AutoRun, PS v2, SMBv1, SMB-signing, NTLMv2-only, anti-anon, WSH off"
}

# =========================
# 5c. TAREAS PROGRAMADAS DE TELEMETRÍA
# =========================
function Disable-TelemetryTasks {
    Write-Host "`n=== Deshabilitando tareas programadas de telemetría ===" -ForegroundColor Cyan
    Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\SQMClient\Windows" "CEIPEnable" 0

    $tasks = @(
        "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
        "\Microsoft\Windows\Application Experience\ProgramDataUpdater",
        "\Microsoft\Windows\Autochk\Proxy",
        "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
        "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
        "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask",
        "\Microsoft\Windows\Feedback\Siuf\DmClient",
        "\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload",
        "\Microsoft\Windows\Windows Error Reporting\QueueReporting",
        "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector"
    )
    $done = 0
    foreach ($t in $tasks) {
        $path = Split-Path $t -Parent
        $name = Split-Path $t -Leaf
        try {
            if (Get-ScheduledTask -TaskPath "$path\" -TaskName $name -ErrorAction SilentlyContinue) {
                Disable-ScheduledTask -TaskPath "$path\" -TaskName $name -ErrorAction Stop | Out-Null
                $done++
            }
        } catch { }
    }
    Log-Result "TelemetryTasks" "OK" "$done de $($tasks.Count) tareas de telemetría deshabilitadas"
}

# =========================
# 5d. AUDITORÍA FORENSE Y SUPERFICIE EXTRA
# =========================
function Apply-AuditAndExtraHardening {
    Write-Host "`n=== Auditoría forense y endurecimiento adicional ===" -ForegroundColor Cyan

    # Subcategorías por GUID (INVARIANTES por idioma; los nombres en inglés fallan en ES).
    $subcats = [ordered]@{
        "Logon"                     = "{0CCE9215-69AE-11D9-BED3-505054503030}"
        "Logoff"                    = "{0CCE9216-69AE-11D9-BED3-505054503030}"
        "Account Lockout"           = "{0CCE9217-69AE-11D9-BED3-505054503030}"
        "Other Logon/Logoff Events" = "{0CCE921C-69AE-11D9-BED3-505054503030}"
        "Credential Validation"     = "{0CCE923F-69AE-11D9-BED3-505054503030}"
        "Process Creation"          = "{0CCE922B-69AE-11D9-BED3-505054503030}"
        "Security Group Management" = "{0CCE9237-69AE-11D9-BED3-505054503030}"
        "User Account Management"   = "{0CCE9235-69AE-11D9-BED3-505054503030}"
        "Audit Policy Change"       = "{0CCE922F-69AE-11D9-BED3-505054503030}"
        "Sensitive Privilege Use"   = "{0CCE9228-69AE-11D9-BED3-505054503030}"
    }
    $okAudit = 0
    foreach ($guid in $subcats.Values) {
        auditpol /set /subcategory:"$guid" /success:enable /failure:enable 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) { $okAudit++ }
    }
    Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" "ProcessCreationIncludeCmdLine_Enabled" 1
    if ($okAudit -eq $subcats.Count) {
        Log-Result "AuditPolicy" "OK" "$okAudit de $($subcats.Count) subcategorías (por GUID) + línea de comandos en 4688"
    } else {
        Log-Result "AuditPolicy" "FAIL" "Solo $okAudit de $($subcats.Count) subcategorías; 4688 puede no generarse"
    }

    $psTransDir = "$env:SystemDrive\Logs\PSTranscripts"
    $psHives = @(
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell",
        "HKLM:\SOFTWARE\Policies\Microsoft\PowerShellCore"
    )
    foreach ($base in $psHives) {
        Set-RegistryValue "$base\ScriptBlockLogging" "EnableScriptBlockLogging" 1
        Set-RegistryValue "$base\ModuleLogging" "EnableModuleLogging" 1
        Set-RegistryValue "$base\ModuleLogging\ModuleNames" "*" "*" "String"
        Set-RegistryValue "$base\Transcription" "EnableTranscripting" 1
        Set-RegistryValue "$base\Transcription" "EnableInvocationHeader" 1
        Set-RegistryValue "$base\Transcription" "OutputDirectory" $psTransDir "String"
    }
    Log-Result "PowerShellLogging" "OK" "ScriptBlock+Module+Transcription en Windows PowerShell 5.1 Y PowerShell 7"

    if (Get-Command Set-ProcessMitigation -ErrorAction SilentlyContinue) {
        try {
            Set-ProcessMitigation -System -Enable DEP,EmulateAtlThunks,BottomUp,SEHOP,TerminateOnError,CFG -ErrorAction Stop
            Log-Result "ExploitProtection" "OK" "Mitigaciones de sistema: DEP, SEHOP, ASLR bottom-up, CFG"
        } catch {
            Log-Result "ExploitProtection" "SKIP" "No se pudo aplicar: $($_.Exception.Message)"
        }
    } else {
        Log-Result "ExploitProtection" "SKIP" "Set-ProcessMitigation no disponible"
    }

    if (Get-Command Set-MpPreference -ErrorAction SilentlyContinue) {
        $cfa = (Get-MpPreference -ErrorAction SilentlyContinue).EnableControlledFolderAccess
        if ($cfa -eq 0) {
            Set-MpPreference -EnableControlledFolderAccess AuditMode -ErrorAction SilentlyContinue
            Log-Result "ControlledFolderAccess" "OK" "Disabled → AuditMode (visibilidad anti-ransomware sin bloquear)"
        } else {
            Log-Result "ControlledFolderAccess" "SKIP" "Ya activo (estado=$cfa); no se degrada"
        }
    }

    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" "EnableAutoDoh" 2
    Log-Result "DoH" "OK" "DNS over HTTPS automático habilitado"

    $pnp = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
    Set-RegistryValue $pnp "RestrictDriverInstallationToAdministrators" 1
    Set-RegistryValue $pnp "NoWarningNoElevationOnInstall" 0
    Set-RegistryValue $pnp "UpdatePromptSettings" 0
    Log-Result "PointAndPrint" "OK" "Drivers de impresora solo por Admin (CVE-2021-34527)"

    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" "fAllowToGetHelp" 0
    if (Get-Service RemoteRegistry -ErrorAction SilentlyContinue) {
        Stop-Service RemoteRegistry -Force -ErrorAction SilentlyContinue
        Set-Service RemoteRegistry -StartupType Disabled -ErrorAction SilentlyContinue
    }
    Log-Result "RemoteSurface" "OK" "Remote Assistance off + Remote Registry deshabilitado"

    Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" "DisableWpad" 1
    Log-Result "WPAD" "OK" "WPAD off en WinHTTP (servicio intacto, Wi-Fi a salvo)"
}

# =========================
# 5g. HUECOS MINADOS DE FUENTES (mindalá: ansible-windows-hardening, privacy.sexy)
# =========================
function Apply-ExtraHardeningMinado {
    Write-Host "`n=== Endurecimiento adicional (minado de fuentes) ===" -ForegroundColor Cyan

    # --- Anti sesión-nula / SMB cliente (de dev-sec/ansible-windows-hardening, CIS base) ---
    # SafeDllSearchMode=1 (secuestro de orden de búsqueda de DLL). OJO (D30): la fuente ansible lo
    # ponía en 0 —que lo DESACTIVA—; el valor ENDURECIDO es 1 (lo verifiqué contra la semántica de
    # Microsoft, no copié el valor de la fuente). Es además el default moderno: lo reforzamos.
    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" "SafeDllSearchMode" 1
    $srv = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
    Set-RegistryValue $srv "RestrictNullSessAccess" 1            # sin acceso por sesión nula a pipes/shares
    Set-RegistryValue $srv "NullSessionShares" @() "MultiString" # ningún share accesible por sesión nula
    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "EnablePlainTextPassword" 0

    # --- Retención forense: tamaño de los registros de eventos (de ansible; su "1" era placeholder) ---
    # Logs pequeños ROTAN y pierden la evidencia justo cuando se necesita. KB: Security amplio.
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security"    "MaxSize" 196608  # 192 MiB
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" "MaxSize" 32768   # 32 MiB
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System"      "MaxSize" 32768

    # --- Privacidad extra (de undergroundwires/privacy.sexy) ---
    # Portapapeles: sin historial local ni sincronización a la nube de Microsoft.
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "AllowClipboardHistory" 0
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "AllowCrossDeviceClipboard" 0
    # Tinta y escritura: no recolectar implícitamente texto/trazos para "personalización".
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" "RestrictImplicitInkCollection" 1
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" "RestrictImplicitTextCollection" 1
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" "PreventHandwritingDataSharing" 1

    # --- Superficie remota: RDP entrante denegado (refuerza el default de Win 11 Pro) ---
    # Riesgo (D18): si usas RDP HACIA este equipo, habilítalo a mano; un equipo personal endurecido
    # va en deny por defecto. Complementa Remote Assistance/Registry off de la sección 5d.
    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" "fDenyTSConnections" 1

    Log-Result "ExtraHardening" "OK" "Anti-sesión-nula + SafeDllSearchMode=1 + sin plaintext SMB + logs forenses grandes + portapapeles/tinta sin nube + RDP entrante off"
}

# =========================
# 5h. HUECOS MINADOS DE BASELINES (mindalá: simeononsecurity W-O-H-D, Sophia-Script) — MIT
# =========================
# Minado 2026-11-10 contra el estado de HOY del script. Cada ajuste es el que el baseline
# APLICA y que a script11 le FALTABA; el VALOR es el ENDURECIDO verificado contra la semántica
# de Microsoft (la fuente dice QUÉ clave, no qué valor — misma disciplina D30 que 5g: no se copia
# el número de la fuente). No duplica 5/5b/5d/5g.
function Apply-MinadoBaselines {
    Write-Host "`n=== Endurecimiento adicional (baselines STIG/CIS minados) ===" -ForegroundColor Cyan

    # --- Instalador: sin MSI elevado por el usuario (vector de privesc; CIS 5.x) ---
    # AlwaysInstallElevated=1 en AMBAS ramas deja a cualquier usuario instalar un MSI como SYSTEM.
    # El valor seguro es 0 en las dos (si solo una es 0, no protege).
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" "AlwaysInstallElevated" 0
    Set-RegistryValue "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" "AlwaysInstallElevated" 0

    # --- Autoplay para dispositivos NO-volumen (MTP/WPD: cámaras, móviles) ---
    # 5b ya apaga AutoRun/AutoPlay de volúmenes; esto cierra la vía de los dispositivos MTP.
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "NoAutoplayfornonVolume" 1

    # --- SCHANNEL: desactivar protocolos TLS muertos (STIG). D18 (medio): equipos/impresoras
    # MUY viejos en LAN que solo hablen SSL3/TLS1.0 podrían no negociar. En 2026 TLS 1.2/1.3 es
    # universal; se dejan ESOS habilitados y se apagan SSL2/SSL3/TLS1.0/TLS1.1.
    $sch = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
    foreach ($proto in @("SSL 2.0","SSL 3.0","TLS 1.0","TLS 1.1")) {
        foreach ($lado in @("Client","Server")) {
            Set-RegistryValue "$sch\$proto\$lado" "Enabled" 0
            Set-RegistryValue "$sch\$proto\$lado" "DisabledByDefault" 1
        }
    }
    foreach ($proto in @("TLS 1.2","TLS 1.3")) {
        foreach ($lado in @("Client","Server")) {
            Set-RegistryValue "$sch\$proto\$lado" "Enabled" 1
            Set-RegistryValue "$sch\$proto\$lado" "DisabledByDefault" 0
        }
    }

    # --- .NET: forzar crypto fuerte y TLS del sistema (apps .NET viejas negociaban TLS 1.0) ---
    foreach ($net in @(
        "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319",
        "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319")) {
        Set-RegistryValue $net "SchUseStrongCrypto" 1
        Set-RegistryValue $net "SystemDefaultTlsVersions" 1
    }

    # --- WinRM: sin autenticación Basic ni tráfico sin cifrar (robo de credenciales remoto) ---
    foreach ($winrm in @(
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client",
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service")) {
        Set-RegistryValue $winrm "AllowBasic" 0
        Set-RegistryValue $winrm "AllowUnencryptedTraffic" 0
    }

    # --- Proveedores de fuentes por red: off (descarga de fuentes desde Internet) ---
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnableFontProviders" 0

    # --- Telemetría: tope duro adicional al AllowTelemetry=0 de la sección 2 (Pro piso=1) ---
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "MaxTelemetryAllowed" 1

    # --- Búsqueda: sin resultados de la nube (complementa DisableWebSearch de la sección 2) ---
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowCloudSearch" 0

    # --- Historial de actividad: el toggle MAESTRO (5 ya pone Publish/Upload=0) ---
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnableActivityFeed" 0
    # --- Personalización de entrada: toggle maestro (5g ya restringe Ink/Text implícitos) ---
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" "AllowInputPersonalization" 0
    # --- Sincronización de ajustes a la nube: off y sin override del usuario ---
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" "DisableSettingSync" 2
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" "DisableSettingSyncUserOverride" 1
    # --- Builds Insider: off (no promover el equipo a canal de previsualización) ---
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" "AllowBuildPreview" 0
    # --- WCN (Wi-Fi Protected Setup) UI: off ---
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\UI" "DisableWcnUi" 1

    # --- Pantalla de bloqueo: sin cámara, sin presentación, sin notificaciones de apps ---
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" "NoLockScreenCamera" 1
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" "NoLockScreenSlideshow" 1
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "DisableLockScreenAppNotifications" 1

    # --- LSA: sin hash LM almacenado (por defecto en Vista+, se fija explícito) ---
    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "NoLMHash" 1
    # --- Auditoría de acceso a LSASS (IFEO AuditLevel=8): registra lo que RunAsPPL bloquearía;
    # es visibilidad forense (Event 3065/3066), no bloqueo. Complementa LSA PPL de la sección 5b.
    Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" "AuditLevel" 8

    # --- Defender: reportes genéricos y de MRT off (no se desactiva la nube/MAPS de la sección 5) ---
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" "DisableGenericReports" 1
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\MRT" "DontReportInfectionInformation" 1
    # --- Defender en sandbox (contiene al propio motor si lo atacan). Variable de máquina. ---
    [Environment]::SetEnvironmentVariable("MP_FORCE_USE_SANDBOX", "1", "Machine")

    # --- Media Player: servicio de compartición de red off (reduce superficie) ---
    if (Get-Service WMPNetworkSvc -ErrorAction SilentlyContinue) {
        Stop-Service WMPNetworkSvc -Force -ErrorAction SilentlyContinue
        Set-Service WMPNetworkSvc -StartupType Disabled -ErrorAction SilentlyContinue
    }

    # --- Apps en segundo plano: denegadas por política. D18 (ALTO): las apps UWP CONSERVADAS
    # no corren en segundo plano (p. ej. notificaciones). Un equipo endurecido con el consumer
    # debloateado no las necesita; si alguna hace falta, se relaja esta política a mano.
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" "LetAppsRunInBackground" 2

    Log-Result "MinadoBaselines" "OK" "AlwaysInstallElevated=0, TLS viejo off (TLS1.2/1.3 on), .NET strong-crypto, WinRM sin Basic, font-providers off, telemetría tope, activity/sync/input off, lock screen duro, NoLMHash, auditoría LSASS, Defender reports off + sandbox, WMPNetworkSvc off, apps en 2º plano off"
}

# =========================
# 5e. CREDENTIAL GUARD / VBS — OPT-IN
# =========================
function Apply-CredentialGuardVBS {
    Write-Host "`n=== Credential Guard + VBS/HVCI (opt-in) ===" -ForegroundColor Cyan
    $dg = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
    Set-RegistryValue $dg "EnableVirtualizationBasedSecurity" 1
    Set-RegistryValue $dg "RequirePlatformSecurityFeatures"   1
    Set-RegistryValue "$dg\Scenarios\HypervisorEnforcedCodeIntegrity" "Enabled" 1
    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "LsaCfgFlags" 2
    Log-Result "CredentialGuard" "OK" "VBS+HVCI+Credential Guard (sin lock UEFI, reversible). REQUIERE REINICIO y hardware compatible"
    Write-Host "  [!] Si tras reiniciar un driver de kernel (VPN/AV) falla: revertir con LsaCfgFlags=0 y HVCI Enabled=0" -ForegroundColor Yellow
}

# =========================
# 5f. POLÍTICAS DE CUENTA — OPT-IN
# =========================
function Apply-AccountPolicy {
    Write-Host "`n=== Políticas de cuenta (opt-in) ===" -ForegroundColor Cyan
    net accounts /lockoutthreshold:10 2>&1 | Out-Null
    net accounts /lockoutduration:15  2>&1 | Out-Null
    net accounts /lockoutwindow:15    2>&1 | Out-Null
    net accounts /minpwlen:14         2>&1 | Out-Null
    net accounts /maxpwage:unlimited  2>&1 | Out-Null
    Log-Result "AccountPolicy" "OK" "Bloqueo 10/15min, longitud mínima 14, sin caducidad forzada"
}

# =========================
# 6. RENDIMIENTO
# =========================
function Optimize-SystemPerf {
    Write-Host "`n=== Optimizando Rendimiento del Sistema ===" -ForegroundColor Cyan

    # SharedAccess = ICS: deshabilitar rompe Mobile Hotspot.
    $services = @("XblAuthManager", "XblGameSave", "XboxNetApiSvc", "SharedAccess", "RetailDemo", "SysMain", "CDPSvc")
    foreach ($svc in $services) {
        Stop-Service $svc -Force -ErrorAction SilentlyContinue
        Set-Service $svc -StartupType Disabled -ErrorAction SilentlyContinue
    }

    $hpGUID = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
    powercfg /setactive $hpGUID 2>$null
    if ($LASTEXITCODE -eq 0) { Log-Result "PowerPlan" "OK" "Plan Alto Rendimiento activado" }
    else                     { Log-Result "PowerPlan" "SKIP" "Plan no disponible en este equipo" }

    powercfg /h off 2>$null
    Log-Result "Hibernate" "OK" "Hibernación deshabilitada (escritorio)"

    $null = cmd /c "DISM /Online /Set-ReservedStorageState /State:Disabled" 2>&1
    if ($LASTEXITCODE -eq 0) { Log-Result "ReservedStorage" "OK" "Almacenamiento reservado deshabilitado" }
    else                     { Log-Result "ReservedStorage" "SKIP" "No se pudo cambiar (update pendiente o ya deshabilitado)" }

    fsutil behavior set disablelastaccess 1 2>$null | Out-Null
    Log-Result "NTFS-LastAccess" "OK" "Last Access Time deshabilitado"

    $lzxMarker = "$env:SystemDrive\Logs\winsxs_lzx_done.flag"
    $lzx = "C:\Windows\WinSxS"
    if (Test-Path $lzx) {
        if (-not (Test-Path $lzxMarker)) {
            Write-Host "Comprimiendo WinSxS (LZX)... (puede tardar varios minutos)" -ForegroundColor Gray
            $null = cmd /c "compact /c /s:`"$lzx`" /i /q /EXE:LZX"
            New-Item -Path $lzxMarker -ItemType File -Force | Out-Null
            Log-Result "WinSxS-LZX" "OK" "Compresión LZX aplicada"
        } else {
            Log-Result "WinSxS-LZX" "SKIP" "Ya comprimido en ejecución previa"
        }
    }

    Remove-Item "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "C:\Windows\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
    Log-Result "Perf" "OK" "Servicios Xbox y GameBar fuera, compresión aplicada"
}

# =========================
# 7. VERIFICACIÓN FINAL
# =========================
function Show-Status {
    Write-Host "`n===== ESTADO FINAL (Win 11 Pro) =====" -ForegroundColor Cyan
    $checks = @(
        @{ Label="Telemetría";     Value=(Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -EA SilentlyContinue).AllowTelemetry; OK={ param($v) $v -le 1 }; OKMsg="Mínima (piso Pro=1)"; FailMsg={ param($v) "Nivel $v" } }
        @{ Label="Copilot/IA";     Value=(Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot"  -Name "TurnOffWindowsCopilot" -EA SilentlyContinue).TurnOffWindowsCopilot; OK={ param($v) $v -eq 1 }; OKMsg="Bloqueado"; FailMsg={ "Activo" } }
        @{ Label="Recall/AI";      Value=(Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" -Name "DisableAIDataAnalysis" -EA SilentlyContinue).DisableAIDataAnalysis; OK={ param($v) $v -eq 1 }; OKMsg="Bloqueado"; FailMsg={ "Activo" } }
        @{ Label="Anuncios Inicio"; Value=(Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -EA SilentlyContinue).DisableWindowsConsumerFeatures; OK={ param($v) $v -eq 1 }; OKMsg="Política puesta"; FailMsg={ "Sin política" } }
        @{ Label="WER";            Value=(Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -EA SilentlyContinue).Disabled; OK={ param($v) $v -eq 1 }; OKMsg="Deshabilitado"; FailMsg={ "Activo" } }
        @{ Label="Drivers en WU";  Value=(Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -EA SilentlyContinue).ExcludeWUDriversInQualityUpdate; OK={ param($v) $v -eq 1 }; OKMsg="Bloqueado"; FailMsg={ "Permitido" } }
        @{ Label="UAC";            Value=(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -EA SilentlyContinue).EnableLUA; OK={ param($v) $v -eq 1 }; OKMsg="Habilitado"; FailMsg={ "Deshabilitado" } }
        @{ Label="Firewall";       Value=(Get-NetFirewallProfile -Profile Private -EA SilentlyContinue).Enabled; OK={ param($v) $v -eq $true }; OKMsg="Activo"; FailMsg={ "Inactivo" } }
        @{ Label="DiagTrack";      Value=(Get-Service DiagTrack -EA SilentlyContinue).StartType; OK={ param($v) $v -eq "Disabled" }; OKMsg="Deshabilitado"; FailMsg={ param($v) "StartType=$v" } }
        @{ Label="SysMain";        Value=(Get-Service SysMain -EA SilentlyContinue).StartType; OK={ param($v) $v -eq "Disabled" }; OKMsg="Deshabilitado"; FailMsg={ param($v) "StartType=$v" } }
        @{ Label="LSA Protect";    Value=(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -EA SilentlyContinue).RunAsPPL; OK={ param($v) $v -eq 1 }; OKMsg="Activo (PPL)"; FailMsg={ "Inactivo" } }
        @{ Label="LLMNR";          Value=(Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -EA SilentlyContinue).EnableMulticast; OK={ param($v) $v -eq 0 }; OKMsg="Deshabilitado"; FailMsg={ "Activo" } }
        @{ Label="SMB signing";    Value=(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -EA SilentlyContinue).RequireSecuritySignature; OK={ param($v) $v -eq 1 }; OKMsg="Obligatorio"; FailMsg={ "No exigido" } }
        @{ Label="NTLM";           Value=(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -EA SilentlyContinue).LmCompatibilityLevel; OK={ param($v) $v -eq 5 }; OKMsg="Solo NTLMv2"; FailMsg={ param($v) "Nivel $v" } }
        @{ Label="Script Host";    Value=(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -EA SilentlyContinue).Enabled; OK={ param($v) $v -eq 0 }; OKMsg="Deshabilitado"; FailMsg={ "Activo" } }
        @{ Label="Auditoría 4688"; Value=(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -EA SilentlyContinue).ProcessCreationIncludeCmdLine_Enabled; OK={ param($v) $v -eq 1 }; OKMsg="Línea de cmd on"; FailMsg={ "Sin línea de cmd" } }
        @{ Label="DNS over HTTPS"; Value=(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "EnableAutoDoh" -EA SilentlyContinue).EnableAutoDoh; OK={ param($v) $v -eq 2 }; OKMsg="Automático"; FailMsg={ param($v) "Modo $v" } }
        @{ Label="Point-and-Print"; Value=(Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name "RestrictDriverInstallationToAdministrators" -EA SilentlyContinue).RestrictDriverInstallationToAdministrators; OK={ param($v) $v -eq 1 }; OKMsg="Solo Admin"; FailMsg={ "Abierto" } }
        @{ Label="Credential Guard"; Value=(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LsaCfgFlags" -EA SilentlyContinue).LsaCfgFlags; OK={ param($v) $v -ge 1 }; OKMsg="Configurado"; FailMsg={ "Off (opt-in: -EnableVBS)" } }
    )
    foreach ($c in $checks) {
        $isOK = & $c.OK $c.Value
        if ($isOK) {
            Write-Host ("  {0,-17} [OK] {1}" -f "$($c.Label):", $c.OKMsg) -ForegroundColor Green
        } else {
            $msg = & $c.FailMsg $c.Value
            Write-Host ("  {0,-17} [!]  {1}" -f "$($c.Label):", $msg) -ForegroundColor Red
        }
    }

    # PRO: cuántas apps de consumidor quedan (visibilidad del debloat).
    $restantes = @(Get-AppxProvisionedPackage -Online -EA SilentlyContinue | Where-Object {
        $_.DisplayName -match 'BingNews|BingWeather|Clipchamp|GamingApp|Xbox|Solitaire|Copilot|MicrosoftTeams|MSTeams|ZuneMusic|ZuneVideo'
    }).Count
    if ($restantes -eq 0) { Write-Host ("  {0,-17} [OK] 0 restantes" -f "Debloat Pro:") -ForegroundColor Green }
    else                  { Write-Host ("  {0,-17} [!]  {1} apps de consumidor aprovisionadas aún" -f "Debloat Pro:", $restantes) -ForegroundColor Red }
}

# =========================
# 0. RED DE SEGURIDAD (ROLLBACK)
# =========================
function Backup-RegistryState {
    param([string]$OutDir)
    Write-Host "`n=== Respaldo para rollback (registro + punto de restauración) ===" -ForegroundColor Cyan
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $bakDir = Join-Path $OutDir "backup-$stamp"
    New-Item -Path $bakDir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null

    $branches = @(
        "HKLM\SOFTWARE\Policies\Microsoft",
        "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies",
        "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings",
        "HKLM\SOFTWARE\Microsoft\SQMClient",
        "HKLM\SOFTWARE\Microsoft\Windows Script Host",
        "HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
        "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest",
        "HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters",
        "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters",
        "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
        "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters",
        "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard",
        "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance"
    )
    $saved = 0
    foreach ($b in $branches) {
        $safe = ($b -replace '[\\ ]','_')
        $file = Join-Path $bakDir "$safe.reg"
        $null = reg export $b $file /y 2>&1
        if ($LASTEXITCODE -eq 0) { $saved++ }
    }
    if ($saved -eq $branches.Count) {
        Log-Result "RegBackup" "OK" "$saved de $($branches.Count) ramas exportadas a $bakDir (evidencia; el rollback real es el punto de restauración)"
    } else {
        Log-Result "RegBackup" "FAIL" "Solo $saved de $($branches.Count) ramas exportadas a $bakDir"
    }

    $null = auditpol /backup /file:"$bakDir\auditpol.csv" 2>&1
    if ($LASTEXITCODE -eq 0) { Log-Result "AuditBackup" "OK" "Política de auditoría respaldada" }
    else                     { Log-Result "AuditBackup" "SKIP" "No se pudo respaldar auditpol (exit $LASTEXITCODE)" }

    try {
        Enable-ComputerRestore -Drive "$env:SystemDrive\" -ErrorAction SilentlyContinue
        Checkpoint-Computer -Description "Pre script11.ps1 (Win11 Pro)" -RestorePointType "MODIFY_SETTINGS" -WarningVariable rpWarn -WarningAction SilentlyContinue -ErrorAction Stop
        if ($rpWarn) {
            Log-Result "RestorePoint" "SKIP" "No creado (ya hubo uno en 24 h). Rollback del registro limitado a los .reg: $($rpWarn[0].Message)"
        } else {
            Log-Result "RestorePoint" "OK" "Punto de restauración creado"
        }
    } catch {
        Log-Result "RestorePoint" "SKIP" "No creado (System Restore off): $($_.Exception.Message)"
    }
}

# =========================
# 0b. ACL DE LOS LOGS (antes de escribir nada)
# =========================
function Secure-LogDirectories {
    # Un script de hardening NO puede dejar sus propios logs y transcripciones legibles por
    # cualquier usuario: las transcripciones de PowerShell capturan líneas de comandos (y a veces
    # secretos). Se restringe ANTES de escribir. SIDs (invariantes por idioma): S-1-5-18=SYSTEM,
    # S-1-5-32-544=Administradores, S-1-5-11=Usuarios autenticados, S-1-3-4=OWNER RIGHTS.
    param([string]$LogDir, [string]$TransDir)

    New-Item -Path $LogDir -ItemType Directory -Force | Out-Null
    # C:\Logs: sin herencia; solo SYSTEM y Administradores (control total). Los .log del script
    # viven aquí y los escribe el propio admin.
    icacls $LogDir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" 2>&1 | Out-Null
    $e1 = $LASTEXITCODE

    New-Item -Path $TransDir -ItemType Directory -Force | Out-Null
    # PSTranscripts: la transcripción de TODO el sistema la escribe la sesión de CADA usuario.
    # Integridad forense (el usuario registrado NO debe poder manipular su propio rastro):
    #   - Usuarios autenticados: permiso de CONTENEDOR (CI, SIN OI) → pueden CREAR su archivo
    #     (WD/AD) y atravesar/leer-atributos (X/RA), pero NO tienen ACE sobre los archivos ajenos
    #     (sin OI = no se propaga a archivos) → no leen ni escriben transcripciones de otros.
    #   - OWNER RIGHTS (S-1-3-4), NO "Creator Owner": clave. El dueño de un archivo tiene
    #     READ_CONTROL+WRITE_DAC IMPLÍCITOS; con WRITE_DAC reescribiría su DACL y se daría DELETE
    #     para borrar su rastro. La ACE OWNER RIGHTS REEMPLAZA esos derechos implícitos por solo
    #     R,W → el dueño lee/escribe LO SUYO pero NO puede cambiar la ACL ni borrar.
    #   - SYSTEM/Admins: control total (recolección/rotación).
    # RESIDUAL HONESTO (D30): `AD` (crear subdir) es OBLIGATORIO — la transcripción de PS crea una
    # subcarpeta por FECHA en la sesión de cada usuario; sin `AD` no se registra NADA (log que
    # calla, peor que el hueco). El dueño de la subcarpeta que crea retiene control de ELLA; cerrar
    # eso exigiría que SYSTEM pre-cree las carpetas con una tarea programada (maquinaria que se
    # rompe tras N días y es superficie nueva — D37) o reenviar fuera del host (WEF/SIEM, exige
    # infraestructura). En un equipo de UN SOLO usuario-admin el auto-borrado del propio rastro es
    # un vector casi vacío (el admin ya puede todo); esta ACL es defensa en profundidad y queda
    # correcta si hubiera un 2º usuario. **El canal forense AUTORITATIVO y resistente a
    # manipulación es el registro de eventos** (ScriptBlockLogging + ModuleLogging, ya activos):
    # un no-admin no puede borrar `Microsoft-Windows-PowerShell/Operational`. La transcripción a
    # archivo es complemento, no la evidencia de la que dependemos.
    icacls $TransDir /inheritance:r /grant:r `
        "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" `
        "*S-1-5-11:(CI)(WD,AD,RA,X)" "*S-1-3-4:(OI)(CI)(R,W)" 2>&1 | Out-Null
    $e2 = $LASTEXITCODE

    if ($e1 -eq 0 -and $e2 -eq 0) {
        Log-Result "LogACL" "OK" "C:\Logs solo SYSTEM/Admin; PSTranscripts: usuarios solo CREAN (sin leer/escribir ajenas), propietario R/W sin borrar"
    } else {
        Log-Result "LogACL" "FAIL" "icacls: C:\Logs exit=$e1, PSTranscripts exit=$e2"
    }
}

# =========================
# EJECUCIÓN
# =========================
Clear-Host
$startTime = Get-Date
$logDir  = "$env:SystemDrive\Logs"
$logBase = "$logDir\$(Get-Date -Format 'yyyyMMdd-HHmmss')-win11pro-hardening"
# ACL ANTES de que Start-Transcript escriba el .log o la transcripción del sistema se active.
Secure-LogDirectories -LogDir $logDir -TransDir "$logDir\PSTranscripts"
Start-Transcript -Path "$logBase.log" -Force | Out-Null
Write-Host "Iniciando Win 11 Pro – Hardening/Debloat (script11)..." -ForegroundColor Cyan

trap {
    Write-Host "`n[ERROR FATAL] $_" -ForegroundColor Red
    $script:Results | Export-Csv -Path "$logBase-error.csv" -NoTypeInformation -Encoding UTF8 -ErrorAction SilentlyContinue
    Stop-Transcript -ErrorAction SilentlyContinue
    exit 1
}

Backup-RegistryState -OutDir $logDir
Apply-UltimatePrivacy
Apply-AILockdownExtra
if (-not $KeepBloat) { Remove-Bloatware }
Disable-TelemetryTasks
Customize-Win11UI
Configure-WindowsUpdatePerformance
Configure-SmartHardening
Apply-NetworkAndCredentialHardening
Apply-AuditAndExtraHardening
Apply-ExtraHardeningMinado
Apply-MinadoBaselines
if ($EnableVBS)           { Apply-CredentialGuardVBS }
if ($EnableAccountPolicy) { Apply-AccountPolicy }
if ($RemoveOneDrive)      { Remove-OneDrive }
Optimize-SystemPerf
Invoke-ForAllUserHives

Write-Host "`nAplicando políticas de grupo..." -ForegroundColor Cyan
gpupdate /force | Out-Null

Show-Status

$endTime = Get-Date
Write-Host "`nCompletado en $(($endTime - $startTime).ToString('mm\:ss'))" -ForegroundColor Green
Write-Host "REINICIA EL EQUIPO PARA APLICAR TODOS LOS CAMBIOS." -ForegroundColor Yellow

$script:Results | Export-Csv -Path "$logBase.csv" -NoTypeInformation -Encoding UTF8
Stop-Transcript | Out-Null
Write-Host "Logs: $logBase.log / .csv" -ForegroundColor Gray
Pause
