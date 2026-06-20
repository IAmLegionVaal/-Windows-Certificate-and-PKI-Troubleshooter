# Windows Certificate and PKI Troubleshooter

A read-only PowerShell toolkit for collecting Windows certificate-store, trust-chain, revocation, TLS, auto-enrolment, and PKI service evidence.

## Features

- Local computer and current-user certificate inventory
- Expired and soon-to-expire certificate detection
- Private-key availability and enhanced key usage review
- Root and intermediate trust-store inventory
- Certificate-chain validation with status details
- CRL and AIA URL extraction
- Auto-enrolment and CAPI2 event collection
- Enterprise CA discovery where domain tools are available
- Remote TLS certificate testing for a host and port
- CSV, JSON, HTML, and text outputs

## Usage

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\src\Test-CertificatePkiHealth.ps1
```

Test a remote TLS service:

```powershell
.\src\Test-CertificatePkiHealth.ps1 -RemoteHost example.com -Port 443 -WarningDays 30
```

## Safety

The toolkit does not enrol, renew, remove, import, export, trust, revoke, or modify certificates or PKI configuration.

## Privacy

Certificate subjects, SANs, serial numbers, and infrastructure names may be sensitive. Review reports before external sharing.

## Validation

Test against a healthy certificate, an expired lab certificate, an untrusted chain, and a host with an incomplete intermediate chain.

## Author

Dewald Pretorius — L2 IT Support Engineer
