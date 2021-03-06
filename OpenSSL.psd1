#
# Module manifest for module 'OpenSSL'
#

@{

# Script module or binary module file associated with this manifest.
RootModule = 'OpenSSL.psm1'

# Version number of this module.
ModuleVersion = '1.0.0'

# ID used to uniquely identify this module
GUID = 'a878250b-f88e-4d6e-8434-a0f29f66c9eb'

# Author of this module
Author = 'Sameer Zeidat'

# Description of the functionality provided by this module
Description = 'Wrapper cmdlets for OpenSSL command line tool'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '3.0'

# Minimum version of the .NET Framework required by this module
DotNetFrameworkVersion = '4.0'

# Minimum version of the common language runtime (CLR) required by this module
CLRVersion = '4.0'

# Functions to export from this module
FunctionsToExport = @(
    "New-PrivateKey",
    "Get-PrivateKey",
    "Convert-PrivateKey",
    "Export-PublicKey",
    "Get-PublicKey",
    "Convert-PublicKey",
    "New-SelfSignedCertificate",
    "Get-Certificate",
    "Convert-Certificate",
    "New-CertificateRequest",
    "Get-CertificateRequest",
    "Convert-CertificateRequest",
    "Invoke-SignCertificateRequest",
    "New-CertificateStore",
    "Export-PrivateKey",
    "Export-ClientCertificate",
    "Export-AuthorityCertificate"
    )

# Private data
PrivateData = @{
PSData = @{
# Tags applied to this module. These help with module discovery in online galleries.
Tags = @('PKI', 'Certificate', 'OpenSSL')

# A URL to the license for this module.
LicenseUri = 'https://github.com/szeidat/OpenSSL/blob/master/LICENSE'

# A URL to the main website for this project.
ProjectUri = 'https://github.com/szeidat/OpenSSL'

# ReleaseNotes of this module
ReleaseNotes = 'Version 1.0.0
Initial release.'
}
}
}
