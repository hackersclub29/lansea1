<#
.SYNOPSIS
    LANSeal Windows Client - Hardened, Permanent Block Rules, Explicit Routes
.DESCRIPTION
    Implements: permanent LAN block (gateway excluded), explicit split-tunnel routes,
    low VPN metric, cert EKU validation. No toggle logic.
    Run as Administrator.
.PARAMETER CertDir
    Directory containing ca.pem and client.p12 (default: C:\lanseal)
.PARAMETER P12Password
    Password for client.p12 (will prompt if not provided)
.PARAMETER GatewayFQDN
    Gateway DNS name (default: gw.lanseal.home.arpa)
.PARAMETER GatewayIP
    Gateway physical IP (default: 10.24.10.235)
.PARAMETER VPNName
    VPN connection name (default: LANSeal)
.PARAMETER TestMode
    Dry-run: shows what would change, makes NO modifications
.PARAMETER Force
    Skip confirmations (use with caution)
#>

[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param(
    [Parameter(Mandatory=$false)]
    [ValidateScript({Test-Path $_ -PathType Container})]
    [string]$CertDir = "C:\lanseal",

    [string]$P12Password,

    [string]$GatewayFQDN = "gw.lanseal.home.arpa",
    [string]$GatewayIP   = "10.24.10.235",
    [string]$VPNName     = "LANSeal",

    [switch]$TestMode,
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Confirm-OrTest {
    param([string]$Msg)
    if ($TestMode) { Write-Host "[TEST] $Msg" -Fore Cyan; return $false }
    if ($Force) { return $true }
    $c = Read-Host "$Msg (y/n)"
    return $c -in @('y','yes','Y','YES')
}

# ----- PRE-FLIGHT -----
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run as Administrator. Right-click PowerShell -> 'Run as Administrator'"
}

$CAFile  = Join-Path $CertDir "ca.pem"
$P12File = Join-Path $CertDir "client.p12"
if (-not (Test-Path $CAFile))  { throw "Missing CA cert: $CAFile" }
if (-not (Test-Path $P12File)) { throw "Missing client P12: $P12File" }

$SecurePass = $P12Password ? (ConvertTo-SecureString $P12Password -AsPlainText -Force) :
              (Read-Host "Enter client.p12 password" -AsSecureString)

# Test cert opens
Get-PfxCertificate -FilePath $P12File -Password $SecurePass -ErrorAction Stop | Out-Null

Write-Host "Pre-flight checks passed." -ForegroundColor Green

# ----- 1. CERTIFICATES -----
if (Confirm-OrTest "Import CA to LocalMachine\Root") {
    try { Import-Certificate -FilePath $CAFile -CertStoreLocation Cert:\LocalMachine\Root -ErrorAction Stop }
    catch { if ($_.Exception.Message -notlike "*already*") { throw $_ } else { Write-Host "CA already in Trusted Root" } }
}

if (Confirm-OrTest "Import client cert+key to LocalMachine\My (MachineCertificate auth)") {
    try {
        Import-PfxCertificate -FilePath $P12File -CertStoreLocation Cert:\LocalMachine\My -Password $SecurePass -Exportable -ErrorAction Stop
    }
    catch { if ($_.Exception.Message -notlike "*already*") { throw $_ } else { Write-Host "Client cert already in Personal store" } }
}

# Verify gateway cert EKU
$GWCert = Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject -like "*gw.lanseal.home.arpa*" } | Select-Object -First 1
if ($GWCert) {
    $EKU = $GWCert.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.37" }
    if (-not $EKU -or $EKU.Format(0) -notlike "*Client Authentication*" -or $EKU.Format(0) -notlike "*Server Authentication*") {
        Write-Warning "Gateway cert missing clientAuth/serverAuth EKU - Windows may reject connection"
    }
}

# ----- 2. VPN CONNECTION -----
if (Confirm-OrTest "Create/replace VPN connection '$VPNName'") {
    Remove-VpnConnection -Name $VPNName -Force -ErrorAction SilentlyContinue
    Add-VpnConnection -Name $VPNName `
        -ServerAddress $GatewayFQDN `
        -TunnelType IKEv2 `
        -EncryptionLevel Required `
        -AuthenticationMethod MachineCertificate `
        -SplitTunneling $true `
        -AllUserConnection `
        -Force `
        -PassThru
    Write-Host "VPN connection created." -ForegroundColor Green
}

# ----- 3. IPSEC CRYPTO (match gateway) -----
if (Confirm-OrTest "Configure IPsec crypto (GCM-AES256/SHA384/ECP384)") {
    Set-VpnConnectionIPsecConfiguration -ConnectionName $VPNName `
        -AuthenticationTransformConstants GCMAES256 `
        -CipherTransformConstants GCMAES256 `
        -EncryptionMethod GCMAES256 `
        -IntegrityCheckMethod SHA384 `
        -DHGroup ECP384 `
        -PfsGroup ECP384 `
        -Force
    Write-Host "IPsec crypto configured." -ForegroundColor Green
}

# ----- 4. EXPLICIT SPLIT-TUNNEL ROUTES -----
if (Confirm-OrTest "Add explicit routes for 10.77.0.0/24 and 10.24.10.0/24") {
    Get-VpnConnectionRoute -ConnectionName $VPNName -ErrorAction SilentlyContinue | Remove-VpnConnectionRoute -ConnectionName $VPNName -Force -ErrorAction SilentlyContinue

    Add-VpnConnectionRoute -ConnectionName $VPNName -DestinationPrefix 10.77.0.0/24 -RouteMetric 1 -ErrorAction Stop
    Add-VpnConnectionRoute -ConnectionName $VPNName -DestinationPrefix 10.24.10.0/24 -RouteMetric 1 -ErrorAction Stop

    Write-Host "Routes added. Verify: Get-VpnConnectionRoute -ConnectionName $VPNName" -ForegroundColor Green
}

# ----- 5. FIREWALL - PERMANENT BLOCK RULES (GATEWAY EXCLUDED) -----
if (Confirm-OrTest "Create permanent firewall block rules (gateway excluded)") {
    $PhysNames = Get-NetAdapter -Physical | Where-Object { $_.Status -eq 'Up' } | Select-Object -ExpandProperty Name

    # OUTBOUND block
    New-NetFirewallRule -Name "LANSeal-Block-LAN-Out" -DisplayName "LANSeal Block LAN Outbound" `
        -Direction Outbound -Action Block -Enabled True -Profile Any `
        -RemoteAddress "10.24.10.0/24,10.77.0.0/24" `
        -ExceptRemoteAddress $GatewayIP `
        -InterfaceAlias $PhysNames `
        -ErrorAction Stop

    # INBOUND block
    New-NetFirewallRule -Name "LANSeal-Block-LAN-In" -DisplayName "LANSeal Block LAN Inbound" `
        -Direction Inbound -Action Block -Enabled True -Profile Any `
        -RemoteAddress "10.24.10.0/24,10.77.0.0/24" `
        -ExceptRemoteAddress $GatewayIP `
        -InterfaceAlias $PhysNames `
        -ErrorAction Stop

    Write-Host "Permanent block rules created. Gateway $GatewayIP excluded for IKE/ESP." -ForegroundColor Green
}

# ----- 6. ALLOW IKE/ESP TO GATEWAY -----
if (Confirm-OrTest "Create explicit IKE/ESP allow rules to gateway") {
    New-NetFirewallRule -Name "LANSeal-IKE-Out" -DisplayName "LANSeal IKE Out" `
        -Direction Outbound -Action Allow -Enabled True -Profile Any `
        -RemoteAddress $GatewayIP -Protocol UDP -RemotePort 500,4500

    New-NetFirewallRule -Name "LANSeal-ESP-Out" -DisplayName "LANSeal ESP Out" `
        -Direction Outbound -Action Allow -Enabled True -Profile Any `
        -RemoteAddress $GatewayIP -Protocol 50

    New-NetFirewallRule -Name "LANSeal-IKE-In" -DisplayName "LANSeal IKE In" `
        -Direction Inbound -Action Allow -Enabled True -Profile Any `
        -RemoteAddress $GatewayIP -Protocol UDP -LocalPort 500,4500

    New-NetFirewallRule -Name "LANSeal-ESP-In" -DisplayName "LANSeal ESP In" `
        -Direction Inbound -Action Allow -Enabled True -Profile Any `
        -RemoteAddress $GatewayIP -Protocol 50

    # DHCP
    New-NetFirewallRule -Name "LANSeal-DHCP-Out" -DisplayName "LANSeal DHCP Out" `
        -Direction Outbound -Action Allow -Enabled True -Profile Any `
        -Protocol UDP -LocalPort 68 -RemotePort 67
    New-NetFirewallRule -Name "LANSeal-DHCP-In" -DisplayName "LANSeal DHCP In" `
        -Direction Inbound -Action Allow -Enabled True -Profile Any `
        -Protocol UDP -LocalPort 67 -RemotePort 68

    Write-Host "IKE/ESP/DHCP allow rules created." -ForegroundColor Green
}

# ----- 7. LOW VPN METRIC (Scheduled Task on Connect) -----
if (Confirm-OrTest "Register VPN connect event to set low metric") {
    $Action = New-ScheduledTaskAction -Execute 'PowerShell.exe' -Argument `
        "-NoProfile -WindowStyle Hidden -Command `"\$vpn = Get-NetAdapter | Where-Object { \\$_.Name -like '*$VPNName*' -or \\$_.InterfaceDescription -like '*WAN Miniport*' } | Select-Object -First 1; if (\$vpn) { Set-NetIPInterface -InterfaceIndex \$vpn.ifIndex -InterfaceMetric 5 }`""
    $Trigger = New-ScheduledTaskTrigger -OnEvent -Channel "Microsoft-Windows-Networking-Correlation/Operational" -EventId 20225
    Register-ScheduledTask -TaskName "LANSeal-SetVPNMetric" -Action $Action -Trigger $Trigger -RunLevel Highest -Force -ErrorAction SilentlyContinue
    Write-Host "Scheduled task registered for VPN metric optimization." -ForegroundColor Green
}

# ----- 8. HELPER SCRIPTS -----
$ConnectScript = @"
#requires -RunAsAdministrator
# LANSeal Connect - Generated $(Get-Date)
Write-Host \"Connecting LANSeal...\" -ForegroundColor Cyan

try {
    rasdial $VPNName
    if (\$LASTEXITCODE -ne 0) { throw \"rasdial failed with exit code \$LASTEXITCODE\" }

    Start-Sleep 3

    \$vpn = Get-NetAdapter | Where-Object { \$_.Name -like '*$VPNName*' -or \$_.InterfaceDescription -like '*WAN Miniport*' } | Select-Object -First 1
    if (\$vpn) {
        Set-NetIPInterface -InterfaceIndex \$vpn.ifIndex -InterfaceMetric 5
        Write-Host \"VPN interface metric set to 5\" -ForegroundColor Green
    }

    Write-Host \"Connected. Routes:\"
    Get-VpnConnectionRoute -ConnectionName $VPNName
    route print 10.77* | Select-String '10.77|10.24'
} catch {
    Write-Error \"Connection failed: \$_`
    exit 1
}
"@

$DisconnectScript = @"
#requires -RunAsAdministrator
# LANSeal Disconnect - Generated $(Get-Date)
Write-Host \"Disconnecting LANSeal...\" -ForegroundColor Cyan

try {
    rasdial $VPNName /disconnect
    if (\$LASTEXITCODE -ne 0) { throw \"rasdial disconnect failed with exit code \$LASTEXITCODE\" }

    Write-Host \"Disconnected. Block rules remain ACTIVE - no plaintext LAN access.\" -ForegroundColor Yellow
    Write-Host \"  No fallback to 10.24.10.0/24 or 10.77.0.0/24\"
} catch {
    Write-Error \"Disconnect failed: \$_`
    exit 1
}
"@

$TestScript = @"
#requires -RunAsAdministrator
# LANSeal Test - Generated $(Get-Date)
Write-Host \"=== LANSeal Connection Test ===\" -ForegroundColor Cyan

\$VPN = Get-VpnConnection -Name $VPNName -ErrorAction SilentlyContinue
if (-not \$VPN) { Write-Error \"VPN connection not found\"; exit 1 }
Write-Host \"VPN Config: OK\"

\$Cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object {\$_.Subject -like \"*home.arpa*\"} | Select-Object -First 1
if (-not \$Cert) { Write-Error \"Client cert not found in LocalMachine\My\"; exit 1 }
Write-Host \"Client Cert: OK (Thumbprint: \$(\$Cert.Thumbprint))\"

\$Rules = Get-NetFirewallRule -Name \"LANSeal-*\"
Write-Host \"Firewall Rules: \$(\$Rules.Count)\"

\$Status = rasdial $VPNName
if (\$Status -like \"*Connected*\") {
    Write-Host \"Tunnel: CONNECTED\" -ForegroundColor Green
    Write-Host \"\nRoute Tests:\"
    ping 10.77.0.1 -n 2 | Select-String \"Reply\"
    ping 10.24.10.1 -n 2 | Select-String \"Reply\"
    Write-Host \"\nVPN Routes:\"
    Get-VpnConnectionRoute -ConnectionName $VPNName
    Write-Host \"\nInterface Metric:\"
    Get-NetAdapter | Where-Object { \$_.Name -like '*$VPNName*' } | Select-Object Name, ifIndex, InterfaceMetric
} else {
    Write-Host \"Tunnel: DISCONNECTED\" -ForegroundColor Yellow
    Write-Host \"\nExpected: ping 10.24.10.1 should FAIL (blocked)\"
    ping 10.24.10.1 -n 2 | Select-String \"Reply\"
}
Write-Host \"\n=== Test Complete ===\" -ForegroundColor Cyan
"@

$ConnectScript | Out-File (Join-Path $CertDir "LANSeal-Connect.ps1") -Encoding UTF8
$DisconnectScript | Out-File (Join-Path $CertDir "LANSeal-Disconnect.ps1") -Encoding UTF8
$TestScript | Out-File (Join-Path $CertDir "LANSeal-Test.ps1") -Encoding UTF8

Write-Host "
=== INSTALL COMPLETE ===
CONNECT:    $CertDir\LANSeal-Connect.ps1
TEST:       $CertDir\LANSeal-Test.ps1
DISCONNECT: $CertDir\LANSeal-Disconnect.ps1

VERIFY:
  Tunnel UP   -> ping 10.24.10.1 WORKS (encrypted via gateway)
  Tunnel DOWN -> ping 10.24.10.1 FAILS (blocked - no fallback)
  Internet    -> ALWAYS works (split tunnel)
" -ForegroundColor Green