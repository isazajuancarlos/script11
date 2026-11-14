# script11

Endurecimiento, *debloat* y optimización de **Windows 11 Pro** en un único script de PowerShell (`script11.ps1`).

## Qué hace
- **Hardening / privacidad**: ajustes de seguridad y telemetría (en Pro el piso es nivel 1).
- **Debloat**: quita appx de consumidor (Bing, Xbox, Clipchamp, Teams-consumer, Copilot, Cortana…) con lista KEEP dura; anuncios de Inicio y pantalla de bloqueo; OneDrive (`-RemoveOneDrive`, opt-in); Recall.
- **Rendimiento**: optimizaciones varias del sistema.
- **Auto-eleva** a Administrador (no necesita `run.bat`).

## Uso
```powershell
# En una terminal de Windows 11 Pro:
.\script11.ps1
```

## Red de seguridad
Respaldo de ramas de registro + punto de restauración antes de aplicar cambios.

## Avisos honestos
- La telemetría nivel 0 solo la respeta Windows Enterprise; en Pro el piso es 1.
- `HideRecommendedSection` / `DisableWindowsConsumerFeatures` vienen capadas en Pro — el debloat + ContentDeliveryManager son el camino real.

## Licencia
`LicenseRef-Xiliux-Propietario` — © Juan Carlos Isaza.
