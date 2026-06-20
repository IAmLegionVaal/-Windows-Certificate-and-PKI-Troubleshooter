[CmdletBinding()]
param(
    [Parameter()]
    [string]$RemoteHost,

    [Parameter()]
    [ValidateRange(1,65535)]
    [int]$Port = 443,

    [Parameter()]
    [ValidateRange(1,3650)]
    [int]$WarningDays = 30,

    [Parameter()]
    [string]$OutputPath = (Join-Path $PWD ("Certificate-PKI-{0:yyyyMMdd_HHmmss}" -f (Get-Date)))
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
$ErrorLog = Join-Path $OutputPath 'command-errors.log'

function Invoke-Safe {
    param([scriptblock]$ScriptBlock,[string]$Label)
    try { & $ScriptBlock }
    catch { "[$(Get-Date -Format o)] $Label :: $($_.Exception.Message)" | Add-Content $ErrorLog; $null }
}

function Get-CertificateRows {
    param([string]$Path,[string]$Scope)
    foreach ($cert in Get-ChildItem -Path $Path -Recurse -ErrorAction SilentlyContinue) {
        if ($cert -isnot [System.Security.Cryptography.X509Certificates.X509Certificate2]) { continue }
        $eku = @($cert.Extensions | Where-Object { $_.Oid.FriendlyName -eq 'Enhanced Key Usage' } | ForEach-Object { $_.Format($false) }) -join '; '
        $san = @($cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' } | ForEach-Object { $_.Format($false) }) -join '; '
        $days = [math]::Floor(($cert.NotAfter - (Get-Date)).TotalDays)
        [pscustomobject]@{
            Scope = $Scope
            Store = Split-Path $cert.PSParentPath -Leaf
            Subject = $cert.Subject
            Issuer = $cert.Issuer
            Thumbprint = $cert.Thumbprint
            SerialNumber = $cert.SerialNumber
            NotBefore = $cert.NotBefore
            NotAfter = $cert.NotAfter
            DaysRemaining = $days
            Status = if ($days -lt 0) { 'Expired' } elseif ($days -le $WarningDays) { 'ExpiringSoon' } else { 'Valid' }
            HasPrivateKey = $cert.HasPrivateKey
            EnhancedKeyUsage = $eku
            SubjectAlternativeName = $san
        }
    }
}

$computerCerts = @(Get-CertificateRows -Path 'Cert:\LocalMachine' -Scope 'LocalMachine')
$userCerts = @(Get-CertificateRows -Path 'Cert:\CurrentUser' -Scope 'CurrentUser')
$allCerts = @($computerCerts + $userCerts)
$allCerts | Export-Csv (Join-Path $OutputPath 'certificate-inventory.csv') -NoTypeInformation -Encoding UTF8

$roots = Get-ChildItem Cert:\LocalMachine\Root -ErrorAction SilentlyContinue |
    Select-Object Subject, Issuer, Thumbprint, NotBefore, NotAfter
$roots | Export-Csv (Join-Path $OutputPath 'trusted-roots.csv') -NoTypeInformation -Encoding UTF8

$intermediates = Get-ChildItem Cert:\LocalMachine\CA -ErrorAction SilentlyContinue |
    Select-Object Subject, Issuer, Thumbprint, NotBefore, NotAfter
$intermediates | Export-Csv (Join-Path $OutputPath 'intermediate-cas.csv') -NoTypeInformation -Encoding UTF8

$chainResults = foreach ($cert in Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue) {
    $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
    $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::Online
    $chain.ChainPolicy.RevocationFlag = [System.Security.Cryptography.X509Certificates.X509RevocationFlag]::ExcludeRoot
    $ok = $false
    try { $ok = $chain.Build($cert) } catch {}
    [pscustomobject]@{
        Subject = $cert.Subject
        Thumbprint = $cert.Thumbprint
        ChainBuildSucceeded = $ok
        ChainElements = $chain.ChainElements.Count
        ChainStatus = (@($chain.ChainStatus | ForEach-Object { $_.Status.ToString() + ': ' + $_.StatusInformation.Trim() }) -join '; ')
    }
}
$chainResults | Export-Csv (Join-Path $OutputPath 'chain-validation.csv') -NoTypeInformation -Encoding UTF8

$start = (Get-Date).AddDays(-7)
$events = New-Object System.Collections.Generic.List[object]
foreach ($log in @('Microsoft-Windows-CAPI2/Operational','Application')) {
    $items = Invoke-Safe -Label "Events $log" -ScriptBlock {
        Get-WinEvent -FilterHashtable @{ LogName=$log; StartTime=$start } -ErrorAction Stop |
            Where-Object { $_.ProviderName -match 'CAPI2|CertificateServicesClient|Schannel|CertEnroll' -or $_.Message -match 'certificate|revocation|trust' } |
            Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,Message
    }
    foreach ($item in @($items)) {
        if ($item) {
            $events.Add([pscustomobject]@{ LogName=$log; TimeCreated=$item.TimeCreated; Id=$item.Id; Level=$item.LevelDisplayName; Provider=$item.ProviderName; Message=$item.Message })
        }
    }
}
$events | Export-Csv (Join-Path $OutputPath 'certificate-events.csv') -NoTypeInformation -Encoding UTF8

$enterpriseCa = Invoke-Safe -Label 'Enterprise CA discovery' -ScriptBlock {
    & certutil.exe -config - -ping 2>&1 | Out-String
}
$enterpriseCa | Set-Content (Join-Path $OutputPath 'enterprise-ca-discovery.txt') -Encoding UTF8

$remoteTls = $null
if ($RemoteHost) {
    $remoteTls = Invoke-Safe -Label 'Remote TLS test' -ScriptBlock {
        $client = New-Object System.Net.Sockets.TcpClient
        $client.Connect($RemoteHost,$Port)
        try {
            $ssl = New-Object System.Net.Security.SslStream($client.GetStream(),$false,({$true}))
            $ssl.AuthenticateAsClient($RemoteHost)
            $remote = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $ssl.RemoteCertificate
            [pscustomobject]@{
                Host = $RemoteHost
                Port = $Port
                Protocol = $ssl.SslProtocol.ToString()
                CipherAlgorithm = $ssl.CipherAlgorithm.ToString()
                CipherStrength = $ssl.CipherStrength
                Subject = $remote.Subject
                Issuer = $remote.Issuer
                Thumbprint = $remote.Thumbprint
                NotBefore = $remote.NotBefore
                NotAfter = $remote.NotAfter
                DaysRemaining = [math]::Floor(($remote.NotAfter-(Get-Date)).TotalDays)
            }
        }
        finally { $client.Dispose() }
    }
    $remoteTls | Export-Csv (Join-Path $OutputPath 'remote-tls.csv') -NoTypeInformation -Encoding UTF8
}

$summary = [pscustomobject]@{
    CollectedAt = (Get-Date).ToString('o')
    ComputerName = $env:COMPUTERNAME
    CertificatesInspected = $allCerts.Count
    ExpiredCertificates = @($allCerts | Where-Object Status -eq 'Expired').Count
    ExpiringSoon = @($allCerts | Where-Object Status -eq 'ExpiringSoon').Count
    LocalMachinePersonalCertificates = @(Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue).Count
    TrustedRootCertificates = @($roots).Count
    IntermediateCertificates = @($intermediates).Count
    ChainFailures = @($chainResults | Where-Object { -not $_.ChainBuildSucceeded }).Count
    CertificateRelatedEvents = $events.Count
    RemoteHostTested = [bool]$RemoteHost
    RemoteCertificateDaysRemaining = if ($remoteTls) { $remoteTls.DaysRemaining } else { $null }
}
$summary | Export-Csv (Join-Path $OutputPath 'summary.csv') -NoTypeInformation -Encoding UTF8
$summary | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $OutputPath 'summary.json') -Encoding UTF8

$style = '<style>body{font-family:Segoe UI,Arial;margin:28px;color:#172033}table{border-collapse:collapse;width:100%}th,td{border:1px solid #d5dde7;padding:7px;text-align:left}th{background:#eaf2f8}h1,h2{color:#0b3558}</style>'
$body = @()
$body += $summary | ConvertTo-Html -Fragment -PreContent '<h2>Summary</h2>'
$body += $allCerts | Sort-Object DaysRemaining | Select-Object -First 100 | ConvertTo-Html -Fragment -PreContent '<h2>Certificate Inventory</h2>'
$body += $chainResults | ConvertTo-Html -Fragment -PreContent '<h2>Chain Validation</h2>'
if ($remoteTls) { $body += $remoteTls | ConvertTo-Html -Fragment -PreContent '<h2>Remote TLS</h2>' }
$body += '<p>Diagnostic-only. Review certificate identifiers before external sharing.</p>'
ConvertTo-Html -Title 'Certificate and PKI Health' -Head $style -Body $body | Set-Content (Join-Path $OutputPath 'Certificate-PKI-Report.html') -Encoding UTF8

Write-Host "Certificate and PKI collection completed: $OutputPath"
