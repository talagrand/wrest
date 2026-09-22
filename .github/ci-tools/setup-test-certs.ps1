<#
.SYNOPSIS
    Creates (or removes) the client certificates wrest's mutual-TLS tests
    need.

.DESCRIPTION
    Called by the CI workflow, and runnable by hand on a Windows box to
    reproduce what CI does.

    Certificates are created in CurrentUser\My with a non-exportable key,
    the case these tests exist to cover, and are unique to the run so two
    runs on one machine cannot delete each other's certificates.

.EXAMPLE
    ./.github/ci-tools/setup-test-certs.ps1 -ClientCertificate
    ./.github/ci-tools/setup-test-certs.ps1 -DisposableCertificate
    ./.github/ci-tools/setup-test-certs.ps1 -Cleanup
#>
[CmdletBinding()]
param(
    # Create the client certificate and report its thumbprint.
    [switch] $ClientCertificate,

    # Create a second certificate for the test that deletes one out from
    # under a live Identity.  Separate from the main certificate so that
    # deletion cannot disturb tests running in parallel.
    [switch] $DisposableCertificate,

    # Remove certificates left by an earlier run, then exit.
    [switch] $Cleanup
)

$ErrorActionPreference = 'Stop'

$SubjectPrefix = 'CN=wrest-test-'
$RunId = [guid]::NewGuid().ToString('N').Substring(0, 12)

# Append to GITHUB_ENV under Actions; set the variable in the current
# session either way, so a local run needs no copy-and-paste.
function Publish-Variable {
    param([string] $Name, [string] $Value)

    Write-Host "$Name=$Value"
    Set-Item -Path "env:$Name" -Value $Value
    if ($env:GITHUB_ENV) {
        "$Name=$Value" | Out-File -FilePath $env:GITHUB_ENV -Append -Encoding utf8
    }
}

function New-TestCertificate {
    param(
        # Names the certificate's purpose; becomes part of the subject.
        [Parameter(Mandatory)]
        [string] $Role
    )

    $cert = New-SelfSignedCertificate `
        -Subject "${SubjectPrefix}$Role-$RunId" `
        -CertStoreLocation 'Cert:\CurrentUser\My' `
        -KeyExportPolicy NonExportable `
        -KeyUsage DigitalSignature, KeyEncipherment `
        -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.2') `
        -NotAfter (Get-Date).AddDays(1)

    if (-not $cert.Thumbprint) {
        throw "$Role certificate created without a thumbprint"
    }

    $cert
}

function Remove-TestCertificates {
    param(
        # Remove only expired certificates, so tidying up after an earlier
        # run cannot disturb one happening concurrently on the same machine.
        [switch] $ExpiredOnly
    )

    if (-not (Test-Path 'Cert:\CurrentUser\My')) { return }
    $now = Get-Date

    $certs = Get-ChildItem 'Cert:\CurrentUser\My' -ErrorAction SilentlyContinue | Where-Object {
        $_.Subject -like "$SubjectPrefix*" -and
        (-not $ExpiredOnly -or $_.NotAfter -lt $now)
    }

    foreach ($cert in $certs) {
        Write-Host "removing $($cert.Subject) $($cert.Thumbprint)"
        Remove-Item $cert.PSPath -Force -ErrorAction SilentlyContinue
    }
}

if ($Cleanup) {
    Remove-TestCertificates
    return
}

if ($ClientCertificate) {
    Remove-TestCertificates -ExpiredOnly
    $cert = New-TestCertificate -Role 'client'
    Publish-Variable -Name 'WREST_MTLS_THUMBPRINT' -Value $cert.Thumbprint
}

if ($DisposableCertificate) {
    $cert = New-TestCertificate -Role 'disposable'
    Publish-Variable -Name 'WREST_MTLS_DISPOSABLE_THUMBPRINT' -Value $cert.Thumbprint
}
