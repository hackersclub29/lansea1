# LANSeal Windows Client - Hardened

## Overview
Native Windows IKEv2 VPN client configuration matching the LANSeal hardened design:
- **Permanent LAN block** (no toggle) with gateway exclusion
- **Explicit split-tunnel routes** for 10.77.0.0/24 and 10.24.10.0/24
- **Low VPN interface metric** via scheduled task
- **Certificate EKU validation** (clientAuth + serverAuth)
- **MachineCertificate authentication** (system-wide, no user login required)

## Files
| File | Purpose |
|------|---------|
| `Install-LANSealClient-Hardened.ps1` | Main installer (run once as Admin) |
| `LANSeal-Connect.ps1` | Connect helper (generated) |
| `LANSeal-Test.ps1` | Verification script (generated) |
| `LANSeal-Disconnect.ps1` | Disconnect helper (generated) |

## Prerequisites
- Windows 10/11 Pro/Enterprise (IKEv2 MachineCertificate requires Pro+)
- PowerShell 5.1+
- Administrator rights
- Certificate files in `C:\lanseal\`:
  - `ca.pem` — LANSeal CA certificate
  - `client.p12` — Client certificate + private key (PFX)

## Installation

### 1. Prepare Certificates
Copy your certificate files to `C:\lanseal\`:
```
C:\lanseal\ca.pem
C:\lanseal\client.p12
```

### 2. Run Installer (PowerShell as Administrator)
```powershell
# Test mode (dry run)
.\Install-LANSealClient-Hardened.ps1 -CertDir "C:\lanseal" -TestMode

# Real install (with password)
.\Install-LANSealClient-Hardened.ps1 -CertDir "C:\lanseal" -P12Password "your-p12-password"

# Force (no prompts)
.\Install-LANSealClient-Hardened.ps1 -CertDir "C:\lanseal" -P12Password "your-p12-password" -Force
```

### 3. Connect
```powershell
C:\lanseal\LANSeal-Connect.ps1
```

### 4. Verify
```powershell
C:\lanseal\LANSeal-Test.ps1
```

Expected output when connected:
```
Tunnel: CONNECTED
Route Tests: 10.77.0.1 -> Reply, 10.24.10.1 -> Reply
VPN Routes: 10.77.0.0/24, 10.24.10.0/24 (metric 1)
Interface Metric: 5
```

When disconnected:
```
Tunnel: DISCONNECTED
Expected: ping 10.24.10.1 should FAIL (blocked)
```

### 5. Disconnect
```powershell
C:\lanseal\LANSeal-Disconnect.ps1
```

## Design Guarantees

| Scenario | 10.24.10.x (Router/Printers) | 10.77.0.x (LANSeal) | Internet |
|----------|------------------------------|---------------------|----------|
| **Tunnel UP** | ✅ Encrypted via gateway | ✅ Encrypted direct | ✅ Direct (split) |
| **Tunnel DOWN** | 🚫 **BLOCKED** (firewall) | 🚫 **BLOCKED** | ✅ Direct (split) |

**No plaintext fallback ever.**

## Firewall Rules Created
| Rule | Direction | Action | Scope |
|------|-----------|--------|-------|
| `LANSeal-Block-LAN-Out` | Outbound | Block | 10.24.10.0/24, 10.77.0.0/24 (except gateway) |
| `LANSeal-Block-LAN-In` | Inbound | Block | 10.24.10.0/24, 10.77.0.0/24 (except gateway) |
| `LANSeal-IKE-Out/In` | Both | Allow | Gateway IP, UDP 500/4500 |
| `LANSeal-ESP-Out/In` | Both | Allow | Gateway IP, Protocol 50 |
| `LANSeal-DHCP-Out/In` | Both | Allow | UDP 67/68 |

Rules apply **only to physical interfaces** (Ethernet/WiFi). VPN adapter unaffected.

## Certificate Requirements
- **CA** → `LocalMachine\Root` (Trusted Root)
- **Client cert+key** → `LocalMachine\My` (Personal) with `Exportable`
- **Gateway cert** must have EKU: `Client Authentication (1.3.6.1.5.5.7.3.2)` + `Server Authentication (1.3.6.1.5.5.7.3.1)`
- **Gateway cert SAN** must match `gw.lanseal.home.arpa`

## Troubleshooting

### "rasdial failed with exit code 691"
- Certificate not in `LocalMachine\My` or wrong password
- Gateway cert not trusted (check `LocalMachine\Root`)

### "No connection could be made" / Timeout
- Gateway unreachable (check `ping 10.24.10.235`)
- Firewall blocking IKE/ESP (check rules with `Get-NetFirewallRule -Name LANSeal-*`)

### Routes not working
- Run `C:\lanseal\LANSeal-Test.ps1` to diagnose
- Check VPN interface metric: `Get-NetAdapter | Where-Object {$_.Name -like '*LANSeal*'} | Select Name, InterfaceMetric`
- Should be 5 (lower than physical ~25)

### Printer not accessible via tunnel
- Ensure Pi connector is running on LANSeal subnet (10.77.0.50)
- Print to `10.77.0.50:9100` (raw) or `10.77.0.50:631` (IPP)

## Rollback
```powershell
# Remove VPN
Remove-VpnConnection -Name LANSeal -Force

# Remove firewall rules
Get-NetFirewallRule -Name "LANSeal-*" | Remove-NetFirewallRule

# Remove certificates
Remove-Item Cert:\LocalMachine\Root\<CA_THUMBPRINT>
Remove-Item Cert:\LocalMachine\My\<CLIENT_THUMBPRINT>

# Remove scheduled task
Unregister-ScheduledTask -TaskName "LANSeal-SetVPNMetric" -Confirm:$false

# Delete helper scripts
Remove-Item C:\lanseal\LANSeal-*.ps1
```

## Integration with LANSeal Project
- Gateway must advertise `local_ts = 10.77.0.0/24, 10.24.10.0/24`
- Gateway must NAT `10.77.0.0/24 -> 10.24.10.0/24`
- Gateway strongSwan: `lanseal-windows` connection with `cacerts = lanseal-ca.pem`
- Pi connector (optional): `10.77.0.50` forwards printer ports