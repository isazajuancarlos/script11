# script11 — Windows 11 Pro: hardening, privacidad, debloat y rendimiento

**La configuración general está en `~/.claude/CLAUDE.md`.** Aquí solo lo propio del repo.

## Qué es

Un **único `script11.ps1`** que endurece, limpia y optimiza **Windows 11 Pro**. Adaptado y
optimizado desde el script de **LTSC 2024** (`/mnt/data/scripts/win11ltsc/win11.ps1`). Se
auto-eleva a Administrador (no necesita `run.bat`). `LicenseRef-Xiliux-Propietario`.

## Por qué PowerShell y no Rust (D38)

La excepción de la D38 aplica igual que en `escaner-windows`: el script interroga y configura
subsistemas de Windows que son **cmdlets de primera clase** (`Set-MpPreference`, `auditpol`,
`Get-AppxPackage`, `Disable-WindowsOptionalFeature`, `reg load`, el registro). Un binario Rust
haría *shell-out* en casi cada línea. El lenguaje correcto aquí es PowerShell.

## Qué cambia respecto del de LTSC (y por qué)

LTSC viene limpio; **Pro trae toda la carga de consumidor**. Lo que se CONSERVA (funciona igual
en Pro): privacidad/telemetría, Copilot/Recall por política, Windows Update sin drivers,
UAC/SmartScreen/Defender/ASR, hardening de credenciales/red, auditoría forense, Exploit
Protection, CFA, DoH, Point-and-Print, VBS/Credential Guard (opt-in), políticas de cuenta
(opt-in), rendimiento. Lo que se **AÑADE** para Pro:

- **Debloat de appx** (`Remove-Bloatware`): quita apps de consumidor (Bing, Xbox, Clipchamp,
  Teams consumer, Solitaire, Copilot, Cortana…) instaladas **y aprovisionadas** (no vuelven),
  con una lista KEEP dura (Store/Terminal/Notepad/Photos/Calc/Defender UI/runtimes).
- **Anuncios de Inicio y pantalla de bloqueo** (`ContentDeliveryManager`, por usuario): lo que
  en Pro de verdad apaga las "sugerencias", auto-instalaciones y Spotlight.
- **OneDrive** (`-RemoveOneDrive`, opt-in): desinstala + política.
- **Recall** como característica opcional (24H2) además de la política.
- **Auto-elevación** para ser un solo `.ps1`.

## Caveats honestos (D30)

- **Telemetría nivel 0** solo la respetan Enterprise/Edu/LTSC; en **Pro el piso efectivo es 1**
  (Required). Se deja en 0 (no empeora) y `Show-Status` lo valida con `-le 1`.
- `HideRecommendedSection` / `DisableWindowsConsumerFeatures` por política están **capadas en
  Pro**; el efecto real lo dan el debloat + las claves CDM por usuario. Se dejan igual (inertes
  en Pro, útiles si el equipo sube a Enterprise).
- **NO ejecutado aquí** (no hay Windows ni `pwsh` en el centro Linux): verificado por autoría +
  balance de delimitadores. **Lo corre Juan en un Windows 11 Pro** (D28), con la red de rollback
  de la sección 0 (respaldo de ramas + punto de restauración).

## Uso

```powershell
# normal (se auto-eleva): hardening + debloat
.\script11.ps1
# opciones
.\script11.ps1 -RemoveOneDrive              # quita OneDrive
.\script11.ps1 -EnableVBS                   # Credential Guard/VBS (reinicio; riesgo drivers)
.\script11.ps1 -EnableAccountPolicy         # bloqueo de cuenta + longitud mínima
.\script11.ps1 -KeepBloat                   # NO quitar apps de consumidor
```

Logs en `C:\Logs\yyyyMMdd-HHmmss-win11pro-hardening.log`/`.csv`. Reiniciar al terminar.
