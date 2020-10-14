Function New-PrivateKey {
    <#
    .SYNOPSIS
        Generate a private key.

    .DESCRIPTION
        The New-PrivateKey command generates a private key. The generated key can be optionally encrypted with a password.

    .PARAMETER KeyFile
        Output key file name.

    .PARAMETER KeySize
        Key size in bits (e.g. 2048). Default is 2048 bits. Minimum is 1 and maximum is 8192.

    .PARAMETER KeyPassword
        Password for key encryption.

    .PARAMETER Cipher
        Cipher for key encryption (e.g. DES, DES3, IDEA). Default is DES3.

    .PARAMETER Overwrite
        Overwrite the key file if it already exists.

    .PARAMETER OpenSslPath
        Full path to the OpenSSL executable file. Optional if 'openssl.exe' is already located in the shell's command search path.

    .EXAMPLE
        New-PrivateKey key.pem
        Generate a private key. Output the key to file 'key.pem'.

    .EXAMPLE
        New-PrivateKey key.pem -KeyPassword (Read-Host -Prompt Password -AsSecureString)
        Generate a private key. Prompt for key encryption password. Output the key to file 'key.pem'.

    .EXAMPLE
        New-PrivateKey key.pem -KeySize 1024 -Overwrite
        Generate a 1024-bit private key. Output the key to file 'key.pem'. Overwrite file if exists.

    .INPUTS
        None

    .OUTPUTS
        None
    #>

    [CmdletBinding()]
    Param (
    [Parameter(Mandatory=$true, HelpMessage="Output key file name", ParameterSetName="General", Position=0)]
    [ValidateNotNullOrEmpty()]
    [String]
    $KeyFile,

    [Parameter(Mandatory=$false, HelpMessage="Key size in bits", ParameterSetName="General")]
    [ValidateNotNullOrEmpty()]
    [ValidateRange(512, 8192)]
    [Int]
    $KeySize=2048,

    [Parameter(Mandatory=$false, HelpMessage="Password for key encryption", ParameterSetName="General")]
    [ValidateNotNullOrEmpty()]
    [SecureString]
    $KeyPassword,

    [Parameter(Mandatory=$false, HelpMessage="Cipher for key encryption", ParameterSetName="General")]
    [ValidateSet('DES', 'DES3', 'IDEA', 'AES128', 'AES192', 'AES256', 'CAMELLIA128', 'CAMELLIA192', 'CAMELLIA256')]
    [ValidateNotNullOrEmpty()]
    [String]
    $Cipher="DES3",

    [Parameter(Mandatory=$false, HelpMessage="Overwrite output key file if exists", ParameterSetName="General")]
    [ValidateNotNullOrEmpty()]
    [Switch]
    $Overwrite,

    [Parameter(Mandatory=$false, HelpMessage="OpenSSL executable file path", ParameterSetName="General")]
    [ValidateNotNullOrEmpty()]
    [String]
    $OpenSslPath
    )

    # OpenSSL executable
    $opensslexe = "openssl.exe"
    if ($OpenSslPath) {
        if (Test-Path -PathType Container $OpenSslPath) { 
            Write-Error "Invalid openssl file name"
            Return
        }
        if (!(Test-Path -PathType Leaf $OpenSslPath)) {
            Write-Error "Openssl file '$OpenSslPath' not found"
            Return
        }
        $opensslexe = $OpenSslPath
    }

    # OpenSSL arguments
    $arguments = @("genpkey")

    # Algorithm argument
    $arguments += "-algorithm RSA"

    # Pass and cipher argument
    if ($KeyPassword) {
        $password = (New-Object PSCredential "User",$KeyPassword).GetNetworkCredential().Password
        if (![string]::IsNullOrEmpty($password.Trim())) {
            $arguments += "-pass"
            $arguments += "pass:$password"
            $arguments += "-$Cipher".ToLower()
        }
    }

    # Pkeyopt argument
    if ($KeySize) {
        $arguments += "-pkeyopt"
        $arguments += "rsa_keygen_bits:$KeySize"
    }
    
    # Out argument
    if ($KeyFile) { 
        if (Test-Path -PathType Container $KeyFile) { 
            Write-Error "Invalid output key file name"
            Return
        } elseif ((Test-Path -PathType Leaf $KeyFile) -and (!$Overwrite)) {
            Write-Error "Key file exists (use -Overwrite to overwrite it)"
            Return
        }
        $arguments += "-out"
        $arguments += "`"$KeyFile`""
    }

    # Verbose output
    Write-Verbose "Command:`n`nopenssl $([RegEx]::Replace($arguments, 'pass:[^\s].* ', 'pass:*** '))`n`n"

    # Run command
    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    $pinfo.FileName = "$opensslexe"
    $pinfo.RedirectStandardError = $true
    $pinfo.RedirectStandardOutput = $true
    $pinfo.UseShellExecute = $false
    $pinfo.Arguments = $arguments
    $pinfo.WorkingDirectory = Convert-Path .
    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $pinfo
    $proc.Start() | Out-Null
    $proc.WaitForExit(10000) | Out-Null
    $stdout = $proc.StandardOutput.ReadToEnd()
    $stderr = $proc.StandardError.ReadToEnd()

    # Check errors
    if ($proc.ExitCode) {
        Write-Error $stderr
    } else {
        Write-Output $stdout
    }

    # Verbose output
    Write-Verbose "Output:`n`n$stdout`n`n"
    Write-Verbose "Errors:`n`n$stderr`n`n"
}

Function Get-PrivateKey {
    <#
    .SYNOPSIS
        Get private key details.

    .DESCRIPTION
        The Get-PrivateKey command gets the private key details from an input key file.

    .PARAMETER KeyFile
        Input Key file name.

    .PARAMETER KeyPassword
        Password for key encryption.

    .PARAMETER OpenSslPath
        Full path to the OpenSSL executable file. Optional if 'openssl.exe' is already located in the shell's command search path.

    .EXAMPLE
        Get-PrivateKey key.pem
        Get private key details from input key file 'key.pem'.

    .EXAMPLE
        Get-PrivateKey key.pem -KeyPassword (Read-Host -Prompt Password -AsSecureString)
        Get private key details from encrypted input key file 'key.pem'. Prompt for key encryption password.

    .INPUTS
        None

    .OUTPUTS
        System.String
    #>

    [CmdletBinding()]
    Param (
    [Parameter(Mandatory=$true, HelpMessage="Input key file name", ParameterSetName="General", Position=0)]
    [ValidateNotNullOrEmpty()]
    [String]
    $KeyFile,

    [Parameter(Mandatory=$false, HelpMessage="Password for key encryption", ParameterSetName="General")]
    [ValidateNotNullOrEmpty()]
    [SecureString]
    $KeyPassword,

    [Parameter(Mandatory=$false, HelpMessage="OpenSSL executable file path", ParameterSetName="General")]
    [ValidateNotNullOrEmpty()]
    [String]
    $OpenSslPath
    )

    # OpenSSL executable
    $opensslexe = "openssl.exe"
    if ($OpenSslPath) {
        if (Test-Path -PathType Container $OpenSslPath) { 
            Write-Error "Invalid openssl file name"
            Return
        }
        if (!(Test-Path -PathType Leaf $OpenSslPath)) {
            Write-Error "Openssl file '$OpenSslPath' not found"
            Return
        }
        $opensslexe = $OpenSslPath
    }

    # OpenSSL arguments
    $arguments = @("pkey")

    # In argument
    if ($KeyFile) { 
        if (Test-Path -PathType Container $KeyFile) { 
            Write-Error "Invalid input key file name"
            Return
        } elseif (!(Test-Path -PathType Leaf $KeyFile)) {
            Write-Error "Input key file '$KeyFile' not found"
            Return
        }
        $arguments += "-in"
        $arguments += "`"$KeyFile`""
    }

    # Inform argument
    if (!(Get-Content $KeyFile | Select-String "BEGIN" -SimpleMatch -Quiet)) {
        $arguments += "-inform DER"
    }

    # Passin argument
    $password = ''
    if ($KeyPassword) {
        $password = (New-Object PSCredential "User",$KeyPassword).GetNetworkCredential().Password
    }
    $arguments += "-passin"
    $arguments += "pass:$password"

    # Text argument
    $arguments += "-text"

    # Noout argument
    $arguments += "-noout"
    
    # Verbose output
    Write-Verbose "Command:`n`nopenssl $([RegEx]::Replace($arguments, 'pass:[^\s].* ', 'pass:*** '))`n`n"

    # Run command
    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    $pinfo.FileName = "$opensslexe"
    $pinfo.RedirectStandardError = $true
    $pinfo.RedirectStandardOutput = $true
    $pinfo.UseShellExecute = $false
    $pinfo.Arguments = $arguments
    $pinfo.WorkingDirectory = Convert-Path .
    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $pinfo
    $proc.Start() | Out-Null
    $proc.WaitForExit(10000) | Out-Null
    $stdout = $proc.StandardOutput.ReadToEnd()
    $stderr = $proc.StandardError.ReadToEnd()

    # Check errors
    if ($proc.ExitCode) {
        Write-Error $stderr
    } else {
        Write-Output $stdout
    }

    # Verbose output
    Write-Verbose "Output:`n`n$stdout`n`n"
    Write-Verbose "Errors:`n`n$stderr`n`n"
}

Function Convert-PrivateKey {
    <#
    .SYNOPSIS
        Convert private key file format.

    .DESCRIPTION
        The Convert-PrivateKey command converts a private key to PEM or DER format

    .PARAMETER KeyFile
        Input key file name.

    .PARAMETER KeyPassword
        Password for key encryption.

    .PARAMETER OutputFile
        Output file name

    .PARAMETER OutputFormat
        Output file format (PEM or DER).

    .PARAMETER OutputPassword
        Password for output key encryption.

    .PARAMETER OutputCipher
        Cipher for output key encryption (e.g. DES, DES3, IDEA). Default is DES3.

    .PARAMETER Overwrite
        Overwrite the output file if it already exists.

    .PARAMETER OpenSslPath
        Full path to the OpenSSL executable file. Optional if 'openssl.exe' is already located in the shell's command search path.

    .EXAMPLE
        Convert-PrivateKey key.pem -OutputFile key.der -OutputFormat DER
        Convert private key file 'key.pem' to DER format. Output to file 'key.der'.

    .EXAMPLE
        Convert-PrivateKey key.pem -KeyPassword (Read-Host -Prompt Password -AsSecureString) -OutputFile key.der -OutputFormat DER -Overwrite
        Convert private key file 'cert.pem' to DER format. Prompt for key encryption password. Output to file 'key.der'. Overwrite file if exists.

    .EXAMPLE
        Convert-PrivateKey key.pem -OutputFile key.der -OutputFormat DER -OutputPassword (Read-Host -Prompt Password -AsSecureString)
        Convert private key file 'cert.pem' to DER format. Output to file 'key.der'. Prompt for output encryption password.

    .INPUTS
        None

    .OUTPUTS
        None
    #>

    [CmdletBinding()]
    Param (
    [Parameter(Mandatory=$true, HelpMessage="Input key file name", ParameterSetName="General", Position=0)]
    [ValidateNotNullOrEmpty()]
    [String]
    $KeyFile,

    [Parameter(Mandatory=$false, HelpMessage="Password for key encryption", ParameterSetName="General")]
    [ValidateNotNullOrEmpty()]
    [SecureString]
    $KeyPassword,

    [Parameter(Mandatory=$true, HelpMessage="Output key file name", ParameterSetName="General")]
    [ValidateNotNullOrEmpty()]
    [String]
    $OutputFile,

    [Parameter(Mandatory=$true, HelpMessage="Output file format (PEM or DER)", ParameterSetName="General")]
    [ValidateSet('PEM', 'DER')]
    [ValidateNotNullOrEmpty()]
    [String]
    $OutputFormat,

    [Parameter(Mandatory=$false, HelpMessage="Password for output key encryption", ParameterSetName="General")]
    [ValidateNotNullOrEmpty()]
    [SecureString]
    $OutputPassword,

    [Parameter(Mandatory=$false, HelpMessage="Cipher for output key encryption", ParameterSetName="General")]
    [ValidateSet('DES', 'DES3', 'IDEA', 'AES128', 'AES192', 'AES256', 'CAMELLIA128', 'CAMELLIA192', 'CAMELLIA256')]
    [ValidateNotNullOrEmpty()]
    [String]
    $OutputCipher="DES3",

    [Parameter(Mandatory=$false, HelpMessage="Overwrite output file if exists", ParameterSetName="General")]
    [ValidateNotNullOrEmpty()]
    [Switch]
    $Overwrite,

    [Parameter(Mandatory=$false, HelpMessage="OpenSSL executable file path", ParameterSetName="General")]
    [ValidateNotNullOrEmpty()]
    [String]
    $OpenSslPath
    )

    # OpenSSL executable
    $opensslexe = "openssl.exe"
    if ($OpenSslPath) {
        if (Test-Path -PathType Container $OpenSslPath) { 
            Write-Error "Invalid openssl file name"
            Return
        }
        if (!(Test-Path -PathType Leaf $OpenSslPath)) {
            Write-Error "Openssl file '$OpenSslPath' not found"
            Return
        }
        $opensslexe = $OpenSslPath
    }

    # OpenSSL arguments
    $arguments = @("pkey")

    # In argument
    if ($KeyFile) { 
        if (Test-Path -PathType Container $KeyFile) { 
            Write-Error "Invalid input key file name"
            Return
        } elseif (!(Test-Path -PathType Leaf $KeyFile)) {
            Write-Error "Input key file '$KeyFile' not found"
            Return
        }
        $arguments += "-in"
        $arguments += "`"$KeyFile`""
    }

    # Inform argument
    if (!(Get-Content $KeyFile | Select-String "BEGIN" -SimpleMatch -Quiet)) {
        $arguments += "-inform DER"
    }

    # Passin argument
    $password = ''
    if ($KeyPassword) {
        $password = (New-Object PSCredential "User",$KeyPassword).GetNetworkCredential().Password
    }
    $arguments += "-passin"
    $arguments += "pass:$password"

    # Passout and cipher argument
    if ($OutputPassword) {
        $password = (New-Object PSCredential "User",$OutputPassword).GetNetworkCredential().Password
        if (![string]::IsNullOrEmpty($password.Trim())) {
            $arguments += "-passout"
            $arguments += "pass:$password"
            $arguments += "-$OutputCipher".ToLower()
        }
    }

    # Out argument
    if ($OutputFile) { 
        if (Test-Path -PathType Container $OutputFile) { 
            Write-Error "Invalid output file name"
            Return
        } elseif ((Test-Path -PathType Leaf $OutputFile) -and (!$Overwrite)) {
            Write-Error "Output file exists (use -Overwrite to overwrite it)"
            Return
        }
        $arguments += "-out"
        $arguments += "`"$OutputFile`""
    }

    # Outform argument
    $arguments += "-outform"
    $arguments += $OutputFormat
    
    # Verbose output
    Write-Verbose "Command:`n`nopenssl $([RegEx]::Replace($arguments, 'pass:[^\s].* ', 'pass:*** '))`n`n"

    # Run command
    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    $pinfo.FileName = "$opensslexe"
    $pinfo.RedirectStandardError = $true
    $pinfo.RedirectStandardOutput = $true
    $pinfo.UseShellExecute = $false
    $pinfo.Arguments = $arguments
    $pinfo.WorkingDirectory = Convert-Path .
    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $pinfo
    $proc.Start() | Out-Null
    $proc.WaitForExit(10000) | Out-Null
    $stdout = $proc.StandardOutput.ReadToEnd()
    $stderr = $proc.StandardError.ReadToEnd()

    # Check errors
    if ($proc.ExitCode) {
        Write-Error $stderr
    } else {
        Write-Output $stdout
    }

    # Verbose output
    Write-Verbose "Output:`n`n$stdout`n`n"
    Write-Verbose "Errors:`n`n$stderr`n`n"
}

Function Export-PublicKey {
    <#
    .SYNOPSIS
        Export public key.

    .DESCRIPTION
        The Export-PublicKey command exports the public key from an input key, certificate, or certificate request file.

    .PARAMETER KeyFile
        Input key file name.

    .PARAMETER KeyPassword
        Password for key encryption.

    .PARAMETER CertificateFile
        Input certificate file name.

    .PARAMETER RequestFile
        Input request file name.

    .PARAMETER OutputFile
        Output file name

    .PARAMETER Overwrite
        Overwrite the output file if it already exists.

    .PARAMETER OpenSslPath
        Full path to the OpenSSL executable file. Optional if 'openssl.exe' is already located in the shell's command search path.

    .EXAMPLE
        Export-PublicKey -KeyFile key.pem -OutputFile keypub.pem
        Export public key from input key file 'key.pem'. Output to file 'keypub.pem'.

    .EXAMPLE
        Export-PublicKey -KeyFile key.pem -KeyPassword (Read-Host -Prompt Password -AsSecureString) -OutputFile keypub.pem
        Export public key from encrypted input key file 'key.pem'. Prompt for key encryption password. Output to file 'keypub.pem'.

    .EXAMPLE
        Export-PublicKey -CertificateFile cert.pem -OutputFile keypub.pem
        Export public key from certificate input file 'cert.pem'. Output to file 'keypub.pem'.

    .EXAMPLE
        Export-PublicKey -RequestFile csr.pem -OutputFile keypub.pem
        Export public key from certificate signing request input file 'csr.pem'. Output to file 'keypub.pem'.

    .INPUTS
        None

    .OUTPUTS
        None
    #>

    [CmdletBinding()]
    Param (
    [Parameter(Mandatory=$true, HelpMessage="Input key file name", ParameterSetName="Key", Position=0)]
    [ValidateNotNullOrEmpty()]
    [String]
    $KeyFile,

    [Parameter(Mandatory=$false, HelpMessage="Password for key encryption", ParameterSetName="Key")]
    [ValidateNotNullOrEmpty()]
    [SecureString]
    $KeyPassword,

    [Parameter(Mandatory=$true, HelpMessage="Input certificate file name", ParameterSetName="Certificate", Position=0)]
    [ValidateNotNullOrEmpty()]
    [String]
    $CertificateFile,

    [Parameter(Mandatory=$true, HelpMessage="Input request file name", ParameterSetName="Request", Position=0)]
    [ValidateNotNullOrEmpty()]
    [String]
    $RequestFile,

    [Parameter(Mandatory=$true, HelpMessage="Output file name", ParameterSetName="Key")]
    [Parameter(Mandatory=$true, HelpMessage="Output file name", ParameterSetName="Certificate")]
    [Parameter(Mandatory=$true, HelpMessage="Output file name", ParameterSetName="Request")]
    [ValidateNotNullOrEmpty()]
    [String]
    $OutputFile,

    [Parameter(Mandatory=$false, HelpMessage="Overwrite output file if exists", ParameterSetName="Key")]
    [Parameter(Mandatory=$false, HelpMessage="Overwrite output file if exists", ParameterSetName="Certificate")]
    [Parameter(Mandatory=$false, HelpMessage="Overwrite output file if exists", ParameterSetName="Request")]
    [ValidateNotNullOrEmpty()]
    [Switch]
    $Overwrite,

    [Parameter(Mandatory=$false, HelpMessage="OpenSSL executable file path", ParameterSetName="Key")]
    [Parameter(Mandatory=$false, HelpMessage="OpenSSL executable file path", ParameterSetName="Certificate")]
    [Parameter(Mandatory=$false, HelpMessage="OpenSSL executable file path", ParameterSetName="Request")]
    [ValidateNotNullOrEmpty()]
    [String]
    $OpenSslPath
    )

    # Key file
    if ($KeyFile) { 
        if (Test-Path -PathType Container $KeyFile) { 
            Write-Error "Invalid input key file name"
            Return
        } elseif (!(Test-Path -PathType Leaf $KeyFile)) {
            Write-Error "Input key file '$KeyFile' not found"
            Return
        }

        # OpenSSL executable
        $opensslexe = "openssl.exe"
        if ($OpenSslPath) {
            if (Test-Path -PathType Container $OpenSslPath) { 
                Write-Error "Invalid openssl file name"
                Return
            }
            if (!(Test-Path -PathType Leaf $OpenSslPath)) {
                Write-Error "Openssl file '$OpenSslPath' not found"
                Return
            }
            $opensslexe = $OpenSslPath
        }

        # OpenSSL arguments
        $arguments = @("pkey")

        # In argument
        $arguments += "-in"
        $arguments += "`"$KeyFile`""

        # Inform argument
        if (!(Get-Content $KeyFile | Select-String "BEGIN" -SimpleMatch -Quiet)) {
            $arguments += "-inform DER"
        }

        # Passin argument
        $password = ''
        if ($KeyPassword) {
            $password = (New-Object PSCredential "User",$KeyPassword).GetNetworkCredential().Password
        }
        $arguments += "-passin"
        $arguments += "pass:$password"

        # Pubout argument
        $arguments += "-pubout"

        # Out argument
        if ($OutputFile) { 
            if (Test-Path -PathType Container $OutputFile) { 
                Write-Error "Invalid output file name"
                Return
            } elseif ((Test-Path -PathType Leaf $OutputFile) -and (!$Overwrite)) {
                Write-Error "Output file exists (use -Overwrite to overwrite it)"
                Return
            }
            $arguments += "-out"
            $arguments += "`"$OutputFile`""
        }

        # Verbose output
        Write-Verbose "Command:`n`nopenssl $([RegEx]::Replace($arguments, 'pass:[^\s].* ', 'pass:*** '))`n`n"

        # Run command
        $pinfo = New-Object System.Diagnostics.ProcessStartInfo
        $pinfo.FileName = "$opensslexe"
        $pinfo.RedirectStandardError = $true
        $pinfo.RedirectStandardOutput = $true
        $pinfo.UseShellExecute = $false
        $pinfo.Arguments = $arguments
        $pinfo.WorkingDirectory = Convert-Path .
        $proc = New-Object System.Diagnostics.Process
        $proc.StartInfo = $pinfo
        $proc.Start() | Out-Null
        $proc.WaitForExit(10000) | Out-Null
        $stdout = $proc.StandardOutput.ReadToEnd()
        $stderr = $proc.StandardError.ReadToEnd()

        # Check errors
        if ($proc.ExitCode) {
            Write-Error $stderr
        } else {
            Write-Output $stdout
        }

        # Verbose output
        Write-Verbose "Output:`n`n$stdout`n`n"
        Write-Verbose "Errors:`n`n$stderr`n`n"
    }

    # Certificate file
    if ($CertificateFile) { 
        if (Test-Path -PathType Container $CertificateFile) { 
            Write-Error "Invalid certificate input file name"
            Return
        } elseif (!(Test-Path -PathType Leaf $CertificateFile)) {
            Write-Error "Input certificate file '$CertificateFile' not found"
            Return
        }

        # OpenSSL executable
        $opensslexe = "openssl.exe"
        if ($OpenSslPath) {
            if (Test-Path -PathType Container $Path) { 
                Write-Error "Invalid openssl file name"
                Return
            }
            if (!(Test-Path -PathType Leaf $Path)) {
                Write-Error "Openssl file '$Path' not found"
                Return
            }
            $opensslexe = $Path
        }

        # OpenSSL arguments
        $arguments = @("x509")

        # In argument
        $arguments += "-in"
        $arguments += "`"$CertificateFile`""

        # Inform argument
        if (!(Get-Content $CertificateFile | Select-String "BEGIN" -SimpleMatch -Quiet)) {
            $arguments += "-inform DER"
        }

        # Pubkey argument
        $arguments += "-pubkey"
    
        # Noout argument
        $arguments += "-noout"

        # Output file
        if ($OutputFile) {
            if (Test-Path -PathType Container $OutputFile) { 
                Write-Error "Invalid output file name"
                Return
            } elseif ((Test-Path -PathType Leaf $OutputFile) -and (!$Overwrite)) {
                Write-Error "Output file exists (use -Overwrite to overwrite it)"
                Return
            }
        }

        # Verbose output
        Write-Verbose "Command:`n`nopenssl $([RegEx]::Replace($arguments, 'pass:[^\s].* ', 'pass:*** '))`n`n"

        # Run command
        $pinfo = New-Object System.Diagnostics.ProcessStartInfo
        $pinfo.FileName = "$opensslexe"
        $pinfo.RedirectStandardError = $true
        $pinfo.RedirectStandardOutput = $true
        $pinfo.UseShellExecute = $false
        $pinfo.Arguments = $arguments
        $pinfo.WorkingDirectory = Convert-Path .
        $proc = New-Object System.Diagnostics.Process
        $proc.StartInfo = $pinfo
        $proc.Start() | Out-Null
        $proc.WaitForExit(10000) | Out-Null
        $stdout = $proc.StandardOutput.ReadToEnd()
        $stderr = $proc.StandardError.ReadToEnd()

        # Check errors
        if ($proc.ExitCode) {
            Write-Error $stderr
        } else {
            Set-Content $OutputFile $stdout
        }

        # Verbose output
        Write-Verbose "Output:`n`n$stdout`n`n"
        Write-Verbose "Errors:`n`n$stderr`n`n"
    }

    # Request file
    if ($RequestFile) { 
        if (Test-Path -PathType Container $RequestFile) { 
            Write-Error "Invalid request input file name"
            Return
        } elseif (!(Test-Path -PathType Leaf $RequestFile)) {
            Write-Error "Input request file '$RequestFile' not found"
            Return
        }

        # OpenSSL executable
        $opensslexe = "openssl.exe"
        if ($OpenSslPath) {
            if (Test-Path -PathType Container $Path) { 
                Write-Error "Invalid openssl file name"
                Return
            }
            if (!(Test-Path -PathType Leaf $Path)) {
                Write-Error "Openssl file '$Path' not found"
                Return
            }
            $opensslexe = $Path
        }

        # OpenSSL arguments
        $arguments = @("req")

        # In argument
        $arguments += "-in"
        $arguments += "`"$RequestFile`""

        # Inform argument
        if (!(Get-Content $RequestFile | Select-String "BEGIN" -SimpleMatch -Quiet)) {
            $arguments += "-inform DER"
        }

        # Pubkey argument
        $arguments += "-pubkey"

        # Noout argument
        $arguments += "-noout"
        
        # Output file
        if ($OutputFile) {
            if (Test-Path -PathType Container $OutputFile) { 
                Write-Error "Invalid output file name"
                Return
            } elseif ((Test-Path -PathType Leaf $OutputFile) -and (!$Overwrite)) {
                Write-Error "Output file exists (use -Overwrite to overwrite it)"
                Return
            }
        }

        # Verbose output
        Write-Verbose "Command:`n`nopenssl $([RegEx]::Replace($arguments, 'pass:[^\s].* ', 'pass:*** '))`n`n"

        # Run command
        $pinfo = New-Object System.Diagnostics.ProcessStartInfo
        $pinfo.FileName = "$opensslexe"
        $pinfo.RedirectStandardError = $true
        $pinfo.RedirectStandardOutput = $true
        $pinfo.UseShellExecute = $false
        $pinfo.Arguments = $arguments
        $pinfo.WorkingDirectory = Convert-Path .
        $proc = New-Object System.Diagnostics.Process
        $proc.StartInfo = $pinfo
        $proc.Start() | Out-Null
        $proc.WaitForExit(10000) | Out-Null
        $stdout = $proc.StandardOutput.ReadToEnd()
        $stderr = $proc.StandardError.ReadToEnd()

        # Check errors
        if ($proc.ExitCode) {
            Write-Error $stderr
        } else {
            Set-Content $OutputFile $stdout
        }

        # Verbose output
        Write-Verbose "Output:`n`n$stdout`n`n"
        Write-Verbose "Errors:`n`n$stderr`n`n"
    }
}

Function Get-PublicKey {
    <#
    .SYNOPSIS
        Get public key details.

    .DESCRIPTION
        The Get-PublicKey command gets the public key details from an input key file.

    .PARAMETER KeyFile
        Input Key file name.

    .PARAMETER OpenSslPath
        Full path to the OpenSSL executable file. Optional if 'openssl.exe' is already located in the shell's command search path.

    .EXAMPLE
        Get-PublicKey keypub.pem
        Get public key details from input key file 'keypub.pem'.

    .EXAMPLE
        Get-PublicKey keypub.pem -OpenSslPath 'c:\openssl\openssl.exe'
        Get public key details from input key file 'keypub.pem'. Use the openssl path provided.

    .INPUTS
        None

    .OUTPUTS
        System.String
    #>

    [CmdletBinding()]
    Param (
    [Parameter(Mandatory=$true, HelpMessage="Input key file name", ParameterSetName="General", Position=0)]
    [ValidateNotNullOrEmpty()]
    [String]
    $KeyFile,

    [Parameter(Mandatory=$false, HelpMessage="OpenSSL executable file path", ParameterSetName="General")]
    [ValidateNotNullOrEmpty()]
    [String]
    $OpenSslPath
    )

    # OpenSSL executable
    $opensslexe = "openssl.exe"
    if ($OpenSslPath) {
        if (Test-Path -PathType Container $OpenSslPath) { 
            Write-Error "Invalid openssl file name"
            Return
        }
        if (!(Test-Path -PathType Leaf $OpenSslPath)) {
            Write-Error "Openssl file '$OpenSslPath' not found"
            Return
        }
        $opensslexe = $OpenSslPath
    }

    # OpenSSL arguments
    $arguments = @("pkey")

    # In argument
    if ($KeyFile) { 
        if (Test-Path -PathType Container $KeyFile) { 
            Write-Error "Invalid input key file name"
            Return
        } elseif (!(Test-Path -PathType Leaf $KeyFile)) {
            Write-Error "Input key file '$KeyFile' not found"
            Return
        }
        $arguments += "-in"
        $arguments += "`"$KeyFile`""
    }

    # Inform argument
    if (!(Get-Content $KeyFile | Select-String "BEGIN" -SimpleMatch -Quiet)) {
        $arguments += "-inform DER"
    }

    # Pubin argument
    $arguments += '-pubin'

    # Text argument
    $arguments += "-text"

    # Noout argument
    $arguments += "-noout"
    
    # Verbose output
    Write-Verbose "Command:`n`nopenssl $([RegEx]::Replace($arguments, 'pass:[^\s].* ', 'pass:*** '))`n`n"

    # Run command
    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    $pinfo.FileName = "$opensslexe"
    $pinfo.RedirectStandardError = $true
    $pinfo.RedirectStandardOutput = $true
    $pinfo.UseShellExecute = $false
    $pinfo.Arguments = $arguments
    $pinfo.WorkingDirectory = Convert-Path .
    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $pinfo
    $proc.Start() | Out-Null
    $proc.WaitForExit(10000) | Out-Null
    $stdout = $proc.StandardOutput.ReadToEnd()
    $stderr = $proc.StandardError.ReadToEnd()

    # Check errors
    if ($proc.ExitCode) {
        Write-Error $stderr
    } else {
        Write-Output $stdout
    }

    # Verbose output
    Write-Verbose "Output:`n`n$stdout`n`n"
    Write-Verbose "Errors:`n`n$stderr`n`n"
}

Function Convert-PublicKey {
    <#
    .SYNOPSIS
        Convert public key file format.

    .DESCRIPTION
        The Convert-PublicKey command converts a public key to PEM or DER format

    .PARAMETER KeyFile
        Input key file name.

    .PARAMETER OutputFile
        Output file name

    .PARAMETER OutputFormat
        Output file format (PEM or DER).

    .PARAMETER Overwrite
        Overwrite the output file if it already exists.

    .PARAMETER OpenSslPath
        Full path to the OpenSSL executable file. Optional if 'openssl.exe' is already located in the shell's command search path.

    .EXAMPLE
        Convert-PublicKey keypub.pem -OutputFile keypub.der -OutputFormat DER
        Convert public key file 'keypub.pem' to DER format. Output to file 'keypub.der'.

    .EXAMPLE
        Convert-PublicKey keypub.pem -OutputFile keypub.der -OutputFormat DER -Overwrite
        Convert public key file 'keypub.pem' to DER format. Output to file 'keypub.der'. Overwrite file if exists.

    .INPUTS
        None

    .OUTPUTS
        None
    #>

    [CmdletBinding()]
    Param (
    [Parameter(Mandatory=$true, HelpMessage="Input key file name", ParameterSetName="General", Position=0)]
    [ValidateNotNullOrEmpty()]
    [String]
    $KeyFile,

    [Parameter(Mandatory=$true, HelpMessage="Output key file name", ParameterSetName="General")]
    [ValidateNotNullOrEmpty()]
    [String]
    $OutputFile,

    [Parameter(Mandatory=$true, HelpMessage="Output file format (PEM or DER)", ParameterSetName="General")]
    [ValidateSet('PEM', 'DER')]
    [ValidateNotNullOrEmpty()]
    [String]
    $OutputFormat,

    [Parameter(Mandatory=$false, HelpMessage="Overwrite output file if exists", ParameterSetName="General")]
    [ValidateNotNullOrEmpty()]
    [Switch]
    $Overwrite,

    [Parameter(Mandatory=$false, HelpMessage="OpenSSL executable file path", ParameterSetName="General")]
    [ValidateNotNullOrEmpty()]
    [String]
    $OpenSslPath
    )

    # OpenSSL executable
    $opensslexe = "openssl.exe"
    if ($OpenSslPath) {
        if (Test-Path -PathType Container $OpenSslPath) { 
            Write-Error "Invalid openssl file name"
            Return
        }
        if (!(Test-Path -PathType Leaf $OpenSslPath)) {
            Write-Error "Openssl file '$OpenSslPath' not found"
            Return
        }
        $opensslexe = $OpenSslPath
    }

    # OpenSSL arguments
    $arguments = @("pkey")

    # In argument
    if ($KeyFile) { 
        if (Test-Path -PathType Container $KeyFile) { 
            Write-Error "Invalid input key file name"
            Return
        } elseif (!(Test-Path -PathType Leaf $KeyFile)) {
            Write-Error "Input key file '$KeyFile' not found"
            Return
        }
        $arguments += "-in"
        $arguments += "`"$KeyFile`""
    }

    # Inform argument
    if (!(Get-Content $KeyFile | Select-String "BEGIN" -SimpleMatch -Quiet)) {
        $arguments += "-inform DER"
    }

    # Pubin argument
    $arguments += '-pubin'

    # Out argument
    if ($OutputFile) { 
        if (Test-Path -PathType Container $OutputFile) { 
            Write-Error "Invalid output file name"
            Return
        } elseif ((Test-Path -PathType Leaf $OutputFile) -and (!$Overwrite)) {
            Write-Error "Output file exists (use -Overwrite to overwrite it)"
            Return
        }
        $arguments += "-out"
        $arguments += "`"$OutputFile`""
    }

    # Outform argument
    $arguments += "-outform"
    $arguments += $OutputFormat
    
    # Verbose output
    Write-Verbose "Command:`n`nopenssl $([RegEx]::Replace($arguments, 'pass:[^\s].* ', 'pass:*** '))`n`n"

    # Run command
    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    $pinfo.FileName = "$opensslexe"
    $pinfo.RedirectStandardError = $true
    $pinfo.RedirectStandardOutput = $true
    $pinfo.UseShellExecute = $false
    $pinfo.Arguments = $arguments
    $pinfo.WorkingDirectory = Convert-Path .
    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $pinfo
    $proc.Start() | Out-Null
    $proc.WaitForExit(10000) | Out-Null
    $stdout = $proc.StandardOutput.ReadToEnd()
    $stderr = $proc.StandardError.ReadToEnd()

    # Check errors
    if ($proc.ExitCode) {
        Write-Error $stderr
    } else {
        Write-Output $stdout
    }

    # Verbose output
    Write-Verbose "Output:`n`n$stdout`n`n"
    Write-Verbose "Errors:`n`n$stderr`n`n"
}

Function New-SelfSignedCertificate {
    <#
    .SYNOPSIS
        Generate a self-signed certificate.

    .DESCRIPTION
        The New-SelfSignedCertificate command generates a self-signed certificate using the key provided and the certificate options specified.

    .PARAMETER KeyFile
        Input key file name.

    .PARAMETER KeyPassword
        Key encryption password.

    .PARAMETER SubjectName
        Subject name fields. Each field is prefixed with the corresponding identifier (i.e. CN for CommonName, E for E-mail, O for Organization, OU for OrganizationalUnit, C for Country, ST for State, or L for Locality). For example "CN:User, E:user@domain.com, C:AU"

    .PARAMETER CertificateFile
        Output certificate file name.

    .PARAMETER ValidDays
        Certificate validy in days. Default is 30 days. Minimum is 30 and maximum is 9125 (i.e. 25 years).

    .PARAMETER BasicUsage
        Certificate key usage values. A combination of one or more of the predefined values can be supplied. If omitted the certificate will not have the "Key Usage" field added.

    .PARAMETER ExtendedUsage
        Certificate extended key usage values. A combination of one or more of the predefined values can be supplied. If omitted the certificate will not have the "Enhanced key usage" field added.

    .PARAMETER SubjectAlternative
        Subject alternative name fields. Each field is prefixed with the corresponding identifier (i.e. IP, DNS, URI, RID, email, or otherName). For example "IP:10.1.1.1, DNS:server.net".

    .PARAMETER Authority
        Set certificate authority flag.

    .PARAMETER Overwrite
        Overwrite the certificate file if it already exists.

    .PARAMETER OpenSslPath
        Full path to the OpenSSL executable file. Optional if 'openssl.exe' is already located in the shell's command search path.

    .EXAMPLE
        New-SelfSignedCertificate key.pem CN:server.domain.com cert.pem
        Generate a self-signed certificate using input key file 'key.pem' and subject name provided. Output certificate to file 'cert.pem'.

    .EXAMPLE
        New-SelfSignedCertificate key.pem CN:server.domain.com cert.pem -ValidDays 3650
        Generate a self-signed certificate, valid for 10 years, using input key file 'key.pem' and subject name provided. Output certificate to file 'cert.pem'.

    .EXAMPLE
        New-SelfSignedCertificate key.pem CN:user@domain.com cert.pem -ValidDays 3650 -SubjectAlternative "otherName:msUPN;UTF8:firstname lastname"
        Generate a self-signed certificate, valid for 10 years, using input key file 'key.pem' and subject and alternative subject names provided. Output certificate to file 'cert.pem'.

    .INPUTS
        None

    .OUTPUTS
        None
    #>

    [CmdletBinding()]
    Param (
    [Parameter(Mandatory=$true, HelpMessage="Input key file name", ParameterSetName="General", Position=0)]
    [ValidateNotNullOrEmpty()]
    [String]
    $KeyFile,

    [Parameter(Mandatory=$false, HelpMessage="Key encryption password", ParameterSetName="General")]
    [ValidateNotNullOrEmpty()]
    [SecureString]
    $KeyPassword,

    [Parameter(Mandatory=$true, HelpMessage="Subject name fields (e.g. C:AU, ST:NSW, CN:User)", ParameterSetName="General", Position=1)]
    [ValidateNotNullOrEmpty()]
    [ValidatePattern('^(CN|E|O|OU|C|ST|L):[^,:]+$', Options='IgnoreCase')]
    [String[]]
    $SubjectName,

    [Parameter(Mandatory=$true, HelpMessage="Output certificate file name", ParameterSetName="General", Position=2)]
    [ValidateNotNullOrEmpty()]
    [String]
    $CertificateFile,

    [Parameter(Mandatory=$false, HelpMessage="Certificate validity in days", ParameterSetName="General")]
    [ValidateNotNullOrEmpty()]
    [ValidateRange(30, 9125)]
    [Int]
    $ValidDays,

    [Parameter(Mandatory=$false, HelpMessage="Certificate basic key usage", ParameterSetName="General")]
    [ValidateNotNullOrEmpty()]
    [ValidateSet('digitalSignature', 'nonRepudiation', 'keyEncipherment', 'dataEncipherment', 'keyAgreement', 'keyCertSign', 'cRLSign', 'encipherOnly', 'decipherOnly', IgnoreCase=$false)]
    [String[]]
    $BasicUsage,

    [Parameter(Mandatory=$false, HelpMessage="Certificate extended key usage", ParameterSetName="General")]
    [ValidateNotNullOrEmpty()]
    [ValidateSet('serverAuth', 'clientAuth', 'codeSigning', 'emailProtection', 'timeStamping', 'msCodeInd', 'msCodeCom', 'msCTLSign', 'msSGC', 'msEFS', 'nsSGC', IgnoreCase=$false)]
    [String[]]
    $ExtendedUsage,

    [Parameter(Mandatory=$false, HelpMessage="Subject alternative name fields (e.g. IP:10.1.1.1, DNS:server.net)", ParameterSetName="General")]
    [ValidateNotNullOrEmpty()]
    [ValidatePattern('^(IP|DNS|URI|RID|otherName|email):[^,]+$', Options='None')]
    [String[]]
    $SubjectAlternative,

    [Parameter(Mandatory=$false, HelpMessage="Set certificate authority flag", ParameterSetName="General")]
    [ValidateNotNullOrEmpty()]
    [Switch]
    $Authority,

    [Parameter(Mandatory=$false, HelpMessage="Overwrite certificate file if exists", ParameterSetName="General")]
    [ValidateNotNullOrEmpty()]
    [Switch]
    $Overwrite,

    [Parameter(Mandatory=$false, HelpMessage="OpenSSL executable file path", ParameterSetName="General")]
    [ValidateNotNullOrEmpty()]
    [String]
    $OpenSslPath
    )

    # OpenSSL executable
    $opensslexe = "openssl.exe"
    if ($OpenSslPath) {
        if (Test-Path -PathType Container $OpenSslPath) { 
            Write-Error "Invalid openssl file name"
            Return
        }
        if (!(Test-Path -PathType Leaf $OpenSslPath)) {
            Write-Error "Openssl file '$OpenSslPath' not found"
            Return
        }
        $opensslexe = $OpenSslPath
    }

    # OpenSSL arguments
    $arguments = @("req")

    # New argument
    $arguments += "-new"

    # X509 argument
    $arguments += "-x509"

    # Rand argument
    $rand = Join-Path $env:TEMP "opensslrand"
    Get-Random | Set-Content $rand
    $arguments += "-rand"
    $arguments += "`"$rand`""

    # Key argument
    if ($KeyFile) { 
        if (Test-Path -PathType Container $KeyFile) { 
            Write-Error "Invalid input key file name"
            Return
        } elseif (!(Test-Path -PathType Leaf $KeyFile)) {
            Write-Error "Input key file '$KeyFile' not found"
            Return
        }
        $arguments += "-key"
        $arguments += "`"$KeyFile`""
    }

    # Keyform argument
    if (!(Get-Content $KeyFile | Select-String "BEGIN" -SimpleMatch -Quiet)) {
        $arguments += "-keyform DER"
    }
    
    # Passin argument
    $password = ''
    if ($KeyPassword) {
        $password = (New-Object PSCredential "User",$KeyPassword).GetNetworkCredential().Password
    }
    $arguments += "-passin"
    $arguments += "pass:$password"

    # Days argument
    if ($ValidDays) { 
        $arguments += "-days"
        $arguments += $ValidDays
    }

    # Config argument
    $config = Join-Path $env:TEMP "opensslconf"
    "[req]" | Set-Content $config
    "default_md = sha1" | Add-Content $config
    "prompt = no" | Add-Content $config
    "distinguished_name = subject" | Add-Content $config
    "x509_extensions = extensions" | Add-Content $config
    $arguments += "-config"
    $arguments += "`"$config`""

    # Config subject
    "[subject]" | Add-Content $config
    foreach ($part in $SubjectName) {
        $parts = $part.Split(':')
        if ($parts[0].ToUpper() -eq 'CN') {
            "commonName = {0}" -f $parts[1] | Add-Content $config
        }
        if ($parts[0] -eq 'E') {
            "emailAddress = {0}" -f $parts[1] | Add-Content $config
        }
        if ($parts[0] -eq 'O') {
            "organizationName = {0}" -f $parts[1] | Add-Content $config
        }
        if ($parts[0] -eq 'OU') {
            "organizationalUnitName = {0}" -f $parts[1] | Add-Content $config
        }
        if ($parts[0] -eq 'C') {
            "countryName = {0}" -f $parts[1] | Add-Content $config
        }
        if ($parts[0] -eq 'ST') {
            "stateOrProvinceName = {0}" -f $parts[1] | Add-Content $config
        }
        if ($parts[0] -eq 'L') {
            "localityName = {0}" -f $parts[1] | Add-Content $config
        }
    }

    # Config extensions
    "[extensions]" | Add-Content $config
    "basicConstraints = CA:{0}" -f $Authority.ToString().ToUpper() | Add-Content $config
    "authorityKeyIdentifier = keyid, issuer" | Add-Content $config
    "subjectKeyIdentifier = hash" | Add-Content $config
    if ($BasicUsage) {
        "keyUsage = {0}" -f [String]::Join(', ', $BasicUsage) | Add-Content $config
    }
    if ($ExtendedUsage) {
        "extendedKeyUsage = {0}" -f [String]::Join(', ', $ExtendedUsage) | Add-Content $config
    }
    if ($SubjectAlternative) {
        "subjectAltName = {0}" -f [String]::Join(', ', $SubjectAlternative) | Add-Content $config
    }
  
    # Out argument
    if ($CertificateFile) { 
        if (Test-Path -PathType Container $CertificateFile) { 
            Write-Error "Invalid output certificate file name"
            Return
        } elseif ((Test-Path -PathType Leaf $CertificateFile) -and (!$Overwrite)) {
            Write-Error "Output certificate file exists (use -Overwrite to overwrite it)"
            Return
        }
        $arguments += "-out"
        $arguments += "`"$CertificateFile`""
    }

    # Verbose output
    Write-Verbose "Command:`n`nopenssl $([RegEx]::Replace($arguments, 'pass:[^\s].* ', 'pass:*** '))`n`n"

    # Run command
    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    $pinfo.FileName = "$opensslexe"
    $pinfo.RedirectStandardError = $true
    $pinfo.RedirectStandardOutput = $true
    $pinfo.UseShellExecute = $false
    $pinfo.Arguments = $arguments
    $pinfo.WorkingDirectory = Convert-Path .
    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $pinfo
    $proc.Start() | Out-Null
    $proc.WaitForExit(10000) | Out-Null
    $stdout = $proc.StandardOutput.ReadToEnd()
    $stderr = $proc.StandardError.ReadToEnd()

    # Check errors
    if ($proc.ExitCode) {
        Write-Error $stderr
    } else {
        Write-Output $stdout
    }

    # Verbose output
    Write-Verbose "Output:`n`n$stdout`n`n"
    Write-Verbose "Errors:`n`n$stderr`n`n"
}

Function Get-Certificate {
    <#
    .SYNOPSIS
        Get certificate details.

    .DESCRIPTION
        The Get-Certificate command gets certificate details from a certificate file.

    .PARAMETER CertificateFile
        Input certificate file name.

    .PARAMETER OpenSslPath
        Full path to the OpenSSL executable file. Optional if 'openssl.exe' is already located in the shell's command search path.

    .EXAMPLE
        Get-Certificate cert.pem
        Get certificate from certificate file 'cert.pem'.

    .EXAMPLE
        Get-Certificate cert.pem  -OpenSslPath C:\OpenSSL\bin\openssl.exe
        Get certificate from certificate file 'cert.pem'. Use OpenSSL execuable file provided.

    .INPUTS
        None

    .OUTPUTS
        System.String
    #>

    [CmdletBinding()]
    Param (
    [Parameter(Mandatory=$true, HelpMessage="Input certificate file name", ParameterSetName="General", Position=0)]
    [ValidateNotNullOrEmpty()]
    [String]
    $CertificateFile,

    [Parameter(Mandatory=$false, HelpMessage="OpenSSL executable file path", ParameterSetName="General")]
    [ValidateNotNullOrEmpty()]
    [String]
    $OpenSslPath
    )

    # OpenSSL executable
    $opensslexe = "openssl.exe"
    if ($OpenSslPath) {
        if (Test-Path -PathType Container $OpenSslPath) { 
            Write-Error "Invalid openssl file name"
            Return
        }
        if (!(Test-Path -PathType Leaf $OpenSslPath)) {
            Write-Error "Openssl file '$OpenSslPath' not found"
            Return
        }
        $opensslexe = $OpenSslPath
    }

    # OpenSSL arguments
    $arguments = @("x509")

    # In argument
    if ($CertificateFile) { 
        if (Test-Path -PathType Container $CertificateFile) { 
            Write-Error "Invalid input certificate file name"
            Return
        } elseif (!(Test-Path -PathType Leaf $CertificateFile)) {
            Write-Error "Input certificate file '$CertificateFile' not found"
            Return
        }
        $arguments += "-in"
        $arguments += "`"$CertificateFile`""
    }

    # Inform argument
    if (!(Get-Content $CertificateFile | Select-String "BEGIN" -SimpleMatch -Quiet)) {
        $arguments += "-inform DER"
    }

    # Text argument
    $arguments += "-text"

    # Fingerprint argument
    $arguments += "-fingerprint"

    # Noout argument
    $arguments += "-noout"
    
    # Verbose output
    Write-Verbose "Command:`n`nopenssl $([RegEx]::Replace($arguments, 'pass:[^\s].* ', 'pass:*** '))`n`n"

    # Run command
    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    $pinfo.FileName = "$opensslexe"
    $pinfo.RedirectStandardError = $true
    $pinfo.RedirectStandardOutput = $true
    $pinfo.UseShellExecute = $false
    $pinfo.Arguments = $arguments
    $pinfo.WorkingDirectory = Convert-Path .
    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $pinfo
    $proc.Start() | Out-Null
    $proc.WaitForExit(10000) | Out-Null
    $stdout = $proc.StandardOutput.ReadToEnd()
    $stderr = $proc.StandardError.ReadToEnd()

    # Check errors
    if ($proc.ExitCode) {
        Write-Error $stderr
    } else {
        Write-Output $stdout
    }

    # Verbose output
    Write-Verbose "Output:`n`n$stdout`n`n"
    Write-Verbose "Errors:`n`n$stderr`n`n"
}

Function Convert-Certificate {
    <#
    .SYNOPSIS
        Convert certificate file format.

    .DESCRIPTION
        The Convert-Certificate command converts a certificate to PEM or DER format

    .PARAMETER CertificateFile
        Input certificate file name.

    .PARAMETER OutputFile
        Output file name

    .PARAMETER OutputFormat
        Output file format (PEM or DER).

    .PARAMETER Overwrite
        Overwrite the output file if it already exists.

    .PARAMETER OpenSslPath
        Full path to the OpenSSL executable file. Optional if 'openssl.exe' is already located in the shell's command search path.

    .EXAMPLE
        Convert-Certificate cert.pem -OutputFile cert.der -OutputFormat DER
        Convert certificate file 'cert.pem' to DER format. Output to file 'cert.der'.

    .EXAMPLE
        Convert-Certificate cert.pem -OutputFile cert.der -OutputFormat DER -Overwrite
        Convert certificate file 'cert.pem' to DER format. Output to file 'cert.der'. Overwrite file if exists.

    .INPUTS
        None

    .OUTPUTS
        None
    #>

    [CmdletBinding()]
    Param (
    [Parameter(Mandatory=$true, HelpMessage="Input certificate file name", ParameterSetName="General", Position=0)]
    [ValidateNotNullOrEmpty()]
    [String]
    $CertificateFile,

    [Parameter(Mandatory=$true, HelpMessage="Output format (PEM or DER)", ParameterSetName="General")]
    [ValidateSet('PEM', 'DER')]
    [ValidateNotNullOrEmpty()]
    [String]
    $OutputFormat,

    [Parameter(Mandatory=$true, HelpMessage="Output certificate file name", ParameterSetName="General")]
    [ValidateNotNullOrEmpty()]
    [String]
    $OutputFile,

    [Parameter(Mandatory=$false, HelpMessage="Overwrite output file if exists", ParameterSetName="General")]
    [ValidateNotNullOrEmpty()]
    [Switch]
    $Overwrite,

    [Parameter(Mandatory=$false, HelpMessage="OpenSSL executable file path", ParameterSetName="General")]
    [ValidateNotNullOrEmpty()]
    [String]
    $OpenSslPath
    )

    # OpenSSL executable
    $opensslexe = "openssl.exe"
    if ($OpenSslPath) {
        if (Test-Path -PathType Container $OpenSslPath) { 
            Write-Error "Invalid openssl file name"
            Return
        }
        if (!(Test-Path -PathType Leaf $OpenSslPath)) {
            Write-Error "Openssl file '$OpenSslPath' not found"
            Return
        }
        $opensslexe = $OpenSslPath
    }

    # OpenSSL arguments
    $arguments = @("x509")

    # In argument
    if ($CertificateFile) { 
        if (Test-Path -PathType Container $CertificateFile) { 
            Write-Error "Invalid input certificate file name"
            Return
        } elseif (!(Test-Path -PathType Leaf $CertificateFile)) {
            Write-Error "Input certificate file '$CertificateFile' not found"
            Return
        }
        $arguments += "-in"
        $arguments += "`"$CertificateFile`""
    }

    # Inform argument
    if (!(Get-Content $CertificateFile | Select-String "BEGIN" -SimpleMatch -Quiet)) {
        $arguments += "-inform DER"
    }

    # Out argument
    if ($OutputFile) { 
        if (Test-Path -PathType Container $OutputFile) { 
            Write-Error "Invalid output file name"
            Return
        } elseif ((Test-Path -PathType Leaf $OutputFile) -and (!$Overwrite)) {
            Write-Error "Output file exists (use -Overwrite to overwrite it)"
            Return
        }
        $arguments += "-out"
        $arguments += "`"$OutputFile`""
    }

    # Outform argument
    $arguments += "-outform"
    $arguments += $OutputFormat
    
    # Verbose output
    Write-Verbose "Command:`n`nopenssl $([RegEx]::Replace($arguments, 'pass:[^\s].* ', 'pass:*** '))`n`n"

    # Run command
    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    $pinfo.FileName = "$opensslexe"
    $pinfo.RedirectStandardError = $true
    $pinfo.RedirectStandardOutput = $true
    $pinfo.UseShellExecute = $false
    $pinfo.Arguments = $arguments
    $pinfo.WorkingDirectory = Convert-Path .
    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $pinfo
    $proc.Start() | Out-Null
    $proc.WaitForExit(10000) | Out-Null
    $stdout = $proc.StandardOutput.ReadToEnd()
    $stderr = $proc.StandardError.ReadToEnd()

    # Check errors
    if ($proc.ExitCode) {
        Write-Error $stderr
    } else {
        Write-Output $stdout
    }

    # Verbose output
    Write-Verbose "Output:`n`n$stdout`n`n"
    Write-Verbose "Errors:`n`n$stderr`n`n"
}

Function New-CertificateRequest {
    <#
    .SYNOPSIS
        Generate a certificate signing request.

    .DESCRIPTION
        The New-CertificateRequest command generates a certificate signing request using the key provided and the certificate options specified.

    .PARAMETER KeyFile
        Input key file name.

    .PARAMETER KeyPassword
        Key encryption password.

    .PARAMETER SubjectName
        Subject name fields. Each field is prefixed with the corresponding identifier (i.e. CN for CommonName, E for E-mail, O for Organization, OU for OrganizationalUnit, C for Country, ST for State, or L for Locality). For example "CN:User, E:user@domain.com, C:AU"

    .PARAMETER RequestFile
        Output request file name.

    .PARAMETER ValidDays
        Certificate validy in days. Default is 30 days. Minimum is 30 and maximum is 9125 (i.e. 25 years).

    .PARAMETER BasicUsage
        Certificate key usage values. A combination of one or more of the predefined values can be supplied. If omitted the certificate will not have the "Key Usage" field added.

    .PARAMETER ExtendedUsage
        Certificate extended key usage values. A combination of one or more of the predefined values can be supplied. If omitted the certificate will not have the "Enhanced key usage" field added.

    .PARAMETER SubjectAlternative
        Subject alternative name fields. Each field is prefixed with the corresponding identifier (i.e. IP, DNS, URI, RID, email, or otherName). For example "IP:10.1.1.1, DNS:server.net".

    .PARAMETER Overwrite
        Overwrite the certificate file if it already exists.

    .PARAMETER OpenSslPath
        Full path to the OpenSSL executable file. Optional if 'openssl.exe' is already located in the shell's command search path.

    .EXAMPLE
        New-CertificateRequest key.pem CN:server.domain.com csr.pem
        Generate a certificate signing request using input key file 'key.pem' and subject name provided. Output certificate request to file 'csr.pem'.

    .EXAMPLE
        New-CertificateRequest key.pem CN:server.domain.com csr.pem -KeyPassword (Read-Host -Prompt Password -AsSecureString)
        Generate a certificate signing request using input key file 'key.pem' and subject name provided. Prompt for key encryption password. Output certificate request to file 'csr.pem'.

    .EXAMPLE
        New-CertificateRequest key.pem CN:user@domain.com csr.pem -SubjectAlternative "otherName:msUPN;UTF8:firstname lastname"
        Generate a certificate signing request using input key file 'key.pem' and subject and alternative subject names provided. Output certificate request to file 'csr.pem'.

    .INPUTS
        None

    .OUTPUTS
        None
    #>

    [CmdletBinding()]
    Param (
    [Parameter(Mandatory=$true, HelpMessage="Input key file name", ParameterSetName="General", Position=0)]
    [ValidateNotNullOrEmpty()]
    [String]
    $KeyFile,

    [Parameter(Mandatory=$false, HelpMessage="Key encryption password", ParameterSetName="General")]
    [ValidateNotNullOrEmpty()]
    [SecureString]
    $KeyPassword,

    [Parameter(Mandatory=$true, HelpMessage="Subject name fields (e.g. C:AU, ST:NSW, CN:User)", ParameterSetName="General", Position=1)]
    [ValidateNotNullOrEmpty()]
    [ValidatePattern('^(CN|E|O|OU|C|ST|L):[^,:]+$', Options='IgnoreCase')]
    [String[]]
    $SubjectName,

    [Parameter(Mandatory=$true, HelpMessage="Output certificate request file name", ParameterSetName="General", Position=2)]
    [ValidateNotNullOrEmpty()]
    [String]
    $RequestFile,

    [Parameter(Mandatory=$false, HelpMessage="Certificate validity in days", ParameterSetName="General")]
    [ValidateNotNullOrEmpty()]
    [ValidateRange(30, 9125)]
    [Int]
    $ValidDays,

    [Parameter(Mandatory=$false, HelpMessage="Certificate basic key usage", ParameterSetName="General")]
    [ValidateNotNullOrEmpty()]
    [ValidateSet('digitalSignature', 'nonRepudiation', 'keyEncipherment', 'dataEncipherment', 'keyAgreement', 'keyCertSign', 'cRLSign', 'encipherOnly', 'decipherOnly', IgnoreCase=$false)]
    [String[]]
    $BasicUsage,

    [Parameter(Mandatory=$false, HelpMessage="Certificate extended key usage", ParameterSetName="General")]
    [ValidateNotNullOrEmpty()]
    [ValidateSet('serverAuth', 'clientAuth', 'codeSigning', 'emailProtection', 'timeStamping', 'msCodeInd', 'msCodeCom', 'msCTLSign', 'msSGC', 'msEFS', 'nsSGC', IgnoreCase=$false)]
    [String[]]
    $ExtendedUsage,

    [Parameter(Mandatory=$false, HelpMessage="Subject alternative name fields (e.g. IP:10.1.1.1, DNS:server.net)", ParameterSetName="General")]
    [ValidateNotNullOrEmpty()]
    [ValidatePattern('^(IP|DNS|URI|RID|otherName|email):[^,]+$', Options='None')]
    [String[]]
    $SubjectAlternative,

    [Parameter(Mandatory=$false, HelpMessage="Overwrite certificate file if exists", ParameterSetName="General")]
    [ValidateNotNullOrEmpty()]
    [Switch]
    $Overwrite,

    [Parameter(Mandatory=$false, HelpMessage="OpenSSL executable file path", ParameterSetName="General")]
    [ValidateNotNullOrEmpty()]
    [String]
    $OpenSslPath
    )

    # OpenSSL executable
    $opensslexe = "openssl.exe"
    if ($OpenSslPath) {
        if (Test-Path -PathType Container $OpenSslPath) { 
            Write-Error "Invalid openssl file name"
            Return
        }
        if (!(Test-Path -PathType Leaf $OpenSslPath)) {
            Write-Error "Openssl file '$OpenSslPath' not found"
            Return
        }
        $opensslexe = $OpenSslPath
    }

    # OpenSSL arguments
    $arguments = @("req")

    # New argument
    $arguments += "-new"

    # Rand argument
    $rand = Join-Path $env:TEMP "opensslrand"
    Get-Random | Set-Content $rand
    $arguments += "-rand"
    $arguments += "`"$rand`""

    # Key argument
    if ($KeyFile) { 
        if (Test-Path -PathType Container $KeyFile) { 
            Write-Error "Invalid input key file name"
            Return
        } elseif (!(Test-Path -PathType Leaf $KeyFile)) {
            Write-Error "Input key file '$KeyFile' not found"
            Return
        }
        $arguments += "-key"
        $arguments += "`"$KeyFile`""
    }

    # Keyform argument
    if (!(Get-Content $KeyFile | Select-String "BEGIN" -SimpleMatch -Quiet)) {
        $arguments += "-keyform DER"
    }
        
    # Passin argument
    $password = ''
    if ($KeyPassword) {
        $password = (New-Object PSCredential "User",$KeyPassword).GetNetworkCredential().Password
    }
    $arguments += "-passin"
    $arguments += "pass:$password"

    # Days argument
    if ($ValidDays) { 
        $arguments += "-days"
        $arguments += $ValidDays
    }

    # Config argument
    $config = Join-Path $env:TEMP "opensslconf"
    "[req]" | Set-Content $config
    "default_md = sha1" | Add-Content $config
    "prompt = no" | Add-Content $config
    "distinguished_name = subject" | Add-Content $config
    "req_extensions = extensions" | Add-Content $config
    $arguments += "-config"
    $arguments += "`"$config`""

    # Config subject
    "[subject]" | Add-Content $config
    foreach ($part in $SubjectName) {
        $parts = $part.Split(':')
        if ($parts[0].ToUpper() -eq 'CN') {
            "commonName = {0}" -f $parts[1] | Add-Content $config
        }
        if ($parts[0] -eq 'E') {
            "emailAddress = {0}" -f $parts[1] | Add-Content $config
        }
        if ($parts[0] -eq 'O') {
            "organizationName = {0}" -f $parts[1] | Add-Content $config
        }
        if ($parts[0] -eq 'OU') {
            "organizationalUnitName = {0}" -f $parts[1] | Add-Content $config
        }
        if ($parts[0] -eq 'C') {
            "countryName = {0}" -f $parts[1] | Add-Content $config
        }
        if ($parts[0] -eq 'ST') {
            "stateOrProvinceName = {0}" -f $parts[1] | Add-Content $config
        }
        if ($parts[0] -eq 'L') {
            "localityName = {0}" -f $parts[1] | Add-Content $config
        }
    }

    # Config extensions
    "[extensions]" | Add-Content $config
    "subjectKeyIdentifier = hash" | Add-Content $config
    if ($BasicUsage) {
        "keyUsage = {0}" -f [String]::Join(', ', $BasicUsage) | Add-Content $config
    }
    if ($ExtendedUsage) {
        "extendedKeyUsage = {0}" -f [String]::Join(', ', $ExtendedUsage) | Add-Content $config
    }
    if ($SubjectAlternative) {
        "subjectAltName = {0}" -f [String]::Join(', ', $SubjectAlternative) | Add-Content $config
    }
  
    # Out argument
    if ($RequestFile) { 
        if (Test-Path -PathType Container $RequestFile) { 
            Write-Error "Invalid output request file name"
            Return
        } elseif ((Test-Path -PathType Leaf $RequestFile) -and (!$Overwrite)) {
            Write-Error "Output request file exists (use -Overwrite to overwrite it)"
            Return
        }
        $arguments += "-out"
        $arguments += "`"$RequestFile`""
    }

    # Verbose output
    Write-Verbose "Command:`n`nopenssl $([RegEx]::Replace($arguments, 'pass:[^\s].* ', 'pass:*** '))`n`n"

    # Run command
    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    $pinfo.FileName = "$opensslexe"
    $pinfo.RedirectStandardError = $true
    $pinfo.RedirectStandardOutput = $true
    $pinfo.UseShellExecute = $false
    $pinfo.Arguments = $arguments
    $pinfo.WorkingDirectory = Convert-Path .
    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $pinfo
    $proc.Start() | Out-Null
    $proc.WaitForExit(10000) | Out-Null
    $stdout = $proc.StandardOutput.ReadToEnd()
    $stderr = $proc.StandardError.ReadToEnd()

    # Check errors
    if ($proc.ExitCode) {
        Write-Error $stderr
    } else {
        Write-Output $stdout
    }

    # Verbose output
    Write-Verbose "Output:`n`n$stdout`n`n"
    Write-Verbose "Errors:`n`n$stderr`n`n"
}

Function Get-CertificateRequest {
    <#
    .SYNOPSIS
        Get certificate signing request details.

    .DESCRIPTION
        The Get-CertificateRequest command gets certificate request details from a request file.

    .PARAMETER RequestFile
        Input request file name.

    .PARAMETER OpenSslPath
        Full path to the OpenSSL executable file. Optional if 'openssl.exe' is already located in the shell's command search path.

    .EXAMPLE
        Get-CertificateRequest csr.pem
        Get certificate signing request from request file 'csr.pem'.

    .EXAMPLE
        Get-CertificateRequest csr.pem -OpenSslPath C:\OpenSSL\bin\openssl.exe
        Get certificate signing request from request file 'csr.pem'. Use OpenSSL execuable file provided.

    .INPUTS
        None

    .OUTPUTS
        System.String
    #>

    [CmdletBinding()]
    Param (
    [Parameter(Mandatory=$true, HelpMessage="Input request file name", ParameterSetName="General", Position=0)]
    [ValidateNotNullOrEmpty()]
    [String]
    $RequestFile,

    [Parameter(Mandatory=$false, HelpMessage="OpenSSL executable file path", ParameterSetName="General")]
    [ValidateNotNullOrEmpty()]
    [String]
    $OpenSslPath
    )

    # OpenSSL executable
    $opensslexe = "openssl.exe"
    if ($OpenSslPath) {
        if (Test-Path -PathType Container $OpenSslPath) { 
            Write-Error "Invalid openssl file name"
            Return
        }
        if (!(Test-Path -PathType Leaf $OpenSslPath)) {
            Write-Error "Openssl file '$OpenSslPath' not found"
            Return
        }
        $opensslexe = $OpenSslPath
    }

    # OpenSSL arguments
    $arguments = @("req")

    # In argument
    if ($RequestFile) { 
        if (Test-Path -PathType Container $RequestFile) { 
            Write-Error "Invalid input request file name"
            Return
        } elseif (!(Test-Path -PathType Leaf $RequestFile)) {
            Write-Error "Input request file '$RequestFile' not found"
            Return
        }
        $arguments += "-in"
        $arguments += "`"$RequestFile`""
    }

    # Inform argument
    if (!(Get-Content $RequestFile | Select-String "BEGIN" -SimpleMatch -Quiet)) {
        $arguments += "-inform DER"
    }

    # Text argument
    $arguments += "-text"

    # Noout argument
    $arguments += "-noout"
 
    # Verbose output
    Write-Verbose "Command:`n`nopenssl $([RegEx]::Replace($arguments, 'pass:[^\s].* ', 'pass:*** '))`n`n"

    # Run command
    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    $pinfo.FileName = "$opensslexe"
    $pinfo.RedirectStandardError = $true
    $pinfo.RedirectStandardOutput = $true
    $pinfo.UseShellExecute = $false
    $pinfo.Arguments = $arguments
    $pinfo.WorkingDirectory = Convert-Path .
    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $pinfo
    $proc.Start() | Out-Null
    $proc.WaitForExit(10000) | Out-Null
    $stdout = $proc.StandardOutput.ReadToEnd()
    $stderr = $proc.StandardError.ReadToEnd()

    # Check errors
    if ($proc.ExitCode) {
        Write-Error $stderr
    } else {
        Write-Output $stdout
    }

    # Verbose output
    Write-Verbose "Output:`n`n$stdout`n`n"
    Write-Verbose "Errors:`n`n$stderr`n`n"
}

Function Convert-CertificateRequest {
    <#
    .SYNOPSIS
        Convert certificate request file format.

    .DESCRIPTION
        The Convert-CertificateRequest command converts a certificate signing request to PEM or DER format

    .PARAMETER RequestFile
        Input request file name.

    .PARAMETER OutputFile
        Output file name

    .PARAMETER OutputFormat
        Output file format (PEM or DER).

    .PARAMETER Overwrite
        Overwrite the output file if it already exists.

    .PARAMETER OpenSslPath
        Full path to the OpenSSL executable file. Optional if 'openssl.exe' is already located in the shell's command search path.

    .EXAMPLE
        Convert-CertificateRequest csr.pem -OutputFile csr.der -OutputFormat DER
        Convert request file 'csr.pem' to DER format. Output to file 'csr.der'.

    .EXAMPLE
        Convert-CertificateRequest csr.pem -OutputFile csr.der -OutputFormat DER -Overwrite
        Convert request file 'csr.pem' to DER format. Output to file 'csr.der'. Overwrite file if exists.

    .INPUTS
        None

    .OUTPUTS
        None
    #>

    [CmdletBinding()]
    Param (
    [Parameter(Mandatory=$true, HelpMessage="Input request file name", ParameterSetName="General", Position=0)]
    [ValidateNotNullOrEmpty()]
    [String]
    $RequestFile,

    [Parameter(Mandatory=$true, HelpMessage="Output certificate file name", ParameterSetName="General")]
    [ValidateNotNullOrEmpty()]
    [String]
    $OutputFile,

    [Parameter(Mandatory=$true, HelpMessage="Output format (PEM or DER)", ParameterSetName="General")]
    [ValidateSet('PEM', 'DER')]
    [ValidateNotNullOrEmpty()]
    [String]
    $OutputFormat,

    [Parameter(Mandatory=$false, HelpMessage="Overwrite output file if exists", ParameterSetName="General")]
    [ValidateNotNullOrEmpty()]
    [Switch]
    $Overwrite,

    [Parameter(Mandatory=$false, HelpMessage="OpenSSL executable file path", ParameterSetName="General")]
    [ValidateNotNullOrEmpty()]
    [String]
    $OpenSslPath
    )

    # OpenSSL executable
    $opensslexe = "openssl.exe"
    if ($OpenSslPath) {
        if (Test-Path -PathType Container $OpenSslPath) { 
            Write-Error "Invalid openssl file name"
            Return
        }
        if (!(Test-Path -PathType Leaf $OpenSslPath)) {
            Write-Error "Openssl file '$OpenSslPath' not found"
            Return
        }
        $opensslexe = $OpenSslPath
    }

    # OpenSSL arguments
    $arguments = @("req")

    # In argument
    if ($RequestFile) { 
        if (Test-Path -PathType Container $RequestFile) { 
            Write-Error "Invalid input request file name"
            Return
        } elseif (!(Test-Path -PathType Leaf $RequestFile)) {
            Write-Error "Input request file '$RequestFile' not found"
            Return
        }
        $arguments += "-in"
        $arguments += "`"$RequestFile`""
    }

    # Inform argument
    if (!(Get-Content $RequestFile | Select-String "BEGIN" -SimpleMatch -Quiet)) {
        $arguments += "-inform DER"
    }

    # Out argument
    if ($OutputFile) { 
        if (Test-Path -PathType Container $OutputFile) { 
            Write-Error "Invalid output file name"
            Return
        } elseif ((Test-Path -PathType Leaf $OutputFile) -and (!$Overwrite)) {
            Write-Error "Output file exists (use -Overwrite to overwrite it)"
            Return
        }
        $arguments += "-out"
        $arguments += "`"$OutputFile`""
    }

    # Outform argument
    $arguments += "-outform"
    $arguments += $OutputFormat
    
    # Verbose output
    Write-Verbose "Command:`n`nopenssl $([RegEx]::Replace($arguments, 'pass:[^\s].* ', 'pass:*** '))`n`n"

    # Run command
    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    $pinfo.FileName = "$opensslexe"
    $pinfo.RedirectStandardError = $true
    $pinfo.RedirectStandardOutput = $true
    $pinfo.UseShellExecute = $false
    $pinfo.Arguments = $arguments
    $pinfo.WorkingDirectory = Convert-Path .
    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $pinfo
    $proc.Start() | Out-Null
    $proc.WaitForExit(10000) | Out-Null
    $stdout = $proc.StandardOutput.ReadToEnd()
    $stderr = $proc.StandardError.ReadToEnd()

    # Check errors
    if ($proc.ExitCode) {
        Write-Error $stderr
    } else {
        Write-Output $stdout
    }

    # Verbose output
    Write-Verbose "Output:`n`n$stdout`n`n"
    Write-Verbose "Errors:`n`n$stderr`n`n"
}

Function Invoke-SignCertificateRequest {
    <#
    .SYNOPSIS
        Generate an authority-signed certificate.

    .DESCRIPTION
        The Invoke-SignCertificateRequest command generates an authority-signed certificate using the certificate signing request provided and the certificate options specified.

    .PARAMETER RequestFile
        Input request file name.

    .PARAMETER AuthorityCertificate
        Input authority certificate file name.

    .PARAMETER AuthorityKey
        Input authority key file name.

    .PARAMETER KeyPassword
        Key encryption password.

    .PARAMETER CertificateFile
        Output signed certificate file name.

    .PARAMETER ValidDays
        Certificate validy in days. Default is 30 days. Minimum is 30 and maximum is 9125 (i.e. 25 years).

    .PARAMETER BasicUsage
        Certificate key usage values. A combination of one or more of the predefined values can be supplied. If omitted the certificate will not have the "Key Usage" field added.

    .PARAMETER ExtendedUsage
        Certificate extended key usage values. A combination of one or more of the predefined values can be supplied. If omitted the certificate will not have the "Enhanced key usage" field added.

    .PARAMETER SubjectAlternative
        Subject alternative name fields. Each field is prefixed with the corresponding identifier (i.e. IP, DNS, URI, RID, email, or otherName). For example "IP:10.1.1.1, DNS:server.net".

    .PARAMETER Authority
        Set certificate authority flag.

    .PARAMETER Overwrite
        Overwrite the certificate file if it already exists.

    .PARAMETER OpenSslPath
        Full path to the OpenSSL executable file. Optional if 'openssl.exe' is already located in the shell's command search path.

    .EXAMPLE
        Invoke-SignCertificateRequest csr.pem cacert.pem cakey.pem cert.pem
        Generate an authority-signed certificate using input request file 'csr.pem' and authority key and certificate provided. Output certificate to file 'cert.pem'.

    .EXAMPLE
        Invoke-SignCertificateRequest csr.pem cacert.pem cakey.pem cert.pem -KeyPassword (Read-Host -Prompt Password -AsSecureString)
        Generate an authority-signed certificate using input request file 'csr.pem' and authority key and certificate provided. Prompt for key encryption password. Output certificate to file 'cert.pem'.

    .EXAMPLE
        Invoke-SignCertificateRequest csr.pem cacert.pem cakey.pem cert.pem -Overwrite
        Generate an authority-signed certificate using input request file 'csr.pem' and authority key and certificate provided. Output certificate to file 'cert.pem'. Overwrite file if exists.

    .INPUTS
        None

    .OUTPUTS
        None
    #>

    [CmdletBinding()]
    Param (
    [Parameter(Mandatory=$true, HelpMessage="Input request file name", ParameterSetName="General", Position=0)]
    [ValidateNotNullOrEmpty()]
    [String]
    $RequestFile,

    [Parameter(Mandatory=$true, HelpMessage="Authority certificate file name", ParameterSetName="General", Position=1)]
    [ValidateNotNullOrEmpty()]
    [String]
    $AuthorityCertificate,

    [Parameter(Mandatory=$true, HelpMessage="Authority key file name", ParameterSetName="General", Position=2)]
    [ValidateNotNullOrEmpty()]
    [String]
    $AuthorityKey,

    [Parameter(Mandatory=$false, HelpMessage="Password for key ", ParameterSetName="General")]
    [ValidateNotNullOrEmpty()]
    [SecureString]
    $KeyPassword,

    [Parameter(Mandatory=$true, HelpMessage="Output certificate file name", ParameterSetName="General", Position=3)]
    [ValidateNotNullOrEmpty()]
    [String]
    $CertificateFile,

    [Parameter(Mandatory=$false, HelpMessage="Certificate validity in days", ParameterSetName="General")]
    [ValidateNotNullOrEmpty()]
    [ValidateRange(30, 9125)]
    [Int]
    $ValidDays,

    [Parameter(Mandatory=$false, HelpMessage="Certificate basic key usage", ParameterSetName="General")]
    [ValidateNotNullOrEmpty()]
    [ValidateSet('digitalSignature', 'nonRepudiation', 'keyEncipherment', 'dataEncipherment', 'keyAgreement', 'keyCertSign', 'cRLSign', 'encipherOnly', 'decipherOnly', IgnoreCase=$false)]
    [String[]]
    $BasicUsage,

    [Parameter(Mandatory=$false, HelpMessage="Certificate extended key usage", ParameterSetName="General")]
    [ValidateNotNullOrEmpty()]
    [ValidateSet('serverAuth', 'clientAuth', 'codeSigning', 'emailProtection', 'timeStamping', 'msCodeInd', 'msCodeCom', 'msCTLSign', 'msSGC', 'msEFS', 'nsSGC', IgnoreCase=$false)]
    [String[]]
    $ExtendedUsage,

    [Parameter(Mandatory=$false, HelpMessage="Subject alternative name fields (e.g. IP:10.1.1.1, DNS:server.net)", ParameterSetName="General")]
    [ValidateNotNullOrEmpty()]
    [ValidatePattern('^(IP|DNS|URI|RID|otherName|email):[^,]+$', Options='None')]
    [String[]]
    $SubjectAlternative,

    [Parameter(Mandatory=$false, HelpMessage="Set certificate authority flag", ParameterSetName="General")]
    [ValidateNotNullOrEmpty()]
    [Switch]
    $Authority,

    [Parameter(Mandatory=$false, HelpMessage="Overwrite certificate file if exists", ParameterSetName="General")]
    [ValidateNotNullOrEmpty()]
    [Switch]
    $Overwrite,

    [Parameter(Mandatory=$false, HelpMessage="OpenSSL executable file path", ParameterSetName="General")]
    [ValidateNotNullOrEmpty()]
    [String]
    $OpenSslPath
    )

    # OpenSSL executable
    $opensslexe = "openssl.exe"
    if ($OpenSslPath) {
        if (Test-Path -PathType Container $OpenSslPath) { 
            Write-Error "Invalid openssl file name"
            Return
        }
        if (!(Test-Path -PathType Leaf $OpenSslPath)) {
            Write-Error "Openssl file '$OpenSslPath' not found"
            Return
        }
        $opensslexe = $OpenSslPath
    }

    # OpenSSL arguments
    $arguments = @("x509")

    # Req argument
    $arguments += "-req"
    
    # In argument
    if ($RequestFile) { 
        if (Test-Path -PathType Container $RequestFile) { 
            Write-Error "Invalid input request file name"
            Return
        } elseif (!(Test-Path -PathType Leaf $RequestFile)) {
            Write-Error "Input request file '$RequestFile' not found"
            Return
        }
        $arguments += "-in"
        $arguments += "`"$RequestFile`""
    }

    # Inform argument
    if (!(Get-Content $RequestFile | Select-String "BEGIN" -SimpleMatch -Quiet)) {
        $arguments += "-inform DER"
    }

    # CA argument
    if ($AuthorityCertificate) { 
        if (Test-Path -PathType Container $AuthorityCertificate) { 
            Write-Error "Invalid input authority certificate file name"
            Return
        } elseif (!(Test-Path -PathType Leaf $AuthorityCertificate)) {
            Write-Error "Input authority certificate file '$AuthorityCertificate' not found"
            Return
        }
        $arguments += "-CA"
        $arguments += "`"$AuthorityCertificate`""
    }

    # CAform argument
    if (!(Get-Content $AuthorityCertificate | Select-String "BEGIN" -SimpleMatch -Quiet)) {
        $arguments += "-CAform DER"
    }

    # CAkey argument
    if ($AuthorityKey) { 
        if (Test-Path -PathType Container $AuthorityKey) { 
            Write-Error "Invalid input authority key file name"
            Return
        } elseif (!(Test-Path -PathType Leaf $AuthorityKey)) {
            Write-Error "Input authority key file '$AuthorityKey' not found"
            Return
        }
        $arguments += "-CAkey"
        $arguments += "`"$AuthorityKey`""
    }

    # CAkeyform argument
    if (!(Get-Content $AuthorityKey | Select-String "BEGIN" -SimpleMatch -Quiet)) {
        $arguments += "-CAkeyform DER"
    }

    # Passin argument
    $password = ''
    if ($KeyPassword) {
        $password = (New-Object PSCredential "User",$KeyPassword).GetNetworkCredential().Password
    }
    $arguments += "-passin"
    $arguments += "pass:$password"

    # CAserial argument
    $serial = Join-Path $env:TEMP "opensslserial"
    $arguments += "-CAcreateserial"
    $arguments += "-CAserial"
    $arguments += "`"$serial`""

    # Days argument
    if ($ValidDays) { 
        $arguments += "-days"
        $arguments += $ValidDays
    }

    # Extfile argument
    $extfile = Join-Path $env:TEMP "opensslconf"
    "basicConstraints = CA:{0}" -f $Authority.ToString().ToUpper() | Set-Content $extfile
    "authorityKeyIdentifier = keyid, issuer" | Add-Content $extfile
    "subjectKeyIdentifier = hash" | Add-Content $extfile
    if ($BasicUsage) {
        "keyUsage = {0}" -f [String]::Join(', ', $BasicUsage) | Add-Content $extfile
    }
    if ($ExtendedUsage) {
        "extendedKeyUsage = {0}" -f [String]::Join(', ', $ExtendedUsage) | Add-Content $extfile
    }
    if ($SubjectAlternative) {
        "subjectAltName = {0}" -f [String]::Join(', ', $SubjectAlternative) | Add-Content $extfile
    }
    $arguments += "-extfile"
    $arguments += "`"$extfile`""

    # Out argument
    if ($CertificateFile) { 
        if (Test-Path -PathType Container $CertificateFile) { 
            Write-Error "Invalid output certificate file name"
            Return
        } elseif ((Test-Path -PathType Leaf $CertificateFile) -and (!$Overwrite)) {
            Write-Error "Output certificate file exists (use -Overwrite to overwrite it)"
            Return
        }
        $arguments += "-out"
        $arguments += "`"$CertificateFile`""
    }

    # Verbose output
    Write-Verbose "Command:`n`nopenssl $([RegEx]::Replace($arguments, 'pass:[^\s].* ', 'pass:*** '))`n`n"

    # Run command
    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    $pinfo.FileName = "$opensslexe"
    $pinfo.RedirectStandardError = $true
    $pinfo.RedirectStandardOutput = $true
    $pinfo.UseShellExecute = $false
    $pinfo.Arguments = $arguments
    $pinfo.WorkingDirectory = Convert-Path .
    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $pinfo
    $proc.Start() | Out-Null
    $proc.WaitForExit(10000) | Out-Null
    $stdout = $proc.StandardOutput.ReadToEnd()
    $stderr = $proc.StandardError.ReadToEnd()

    # Check errors
    if ($proc.ExitCode) {
        Write-Error $stderr
    } else {
        Write-Output $stdout
    }

    # Verbose output
    Write-Verbose "Output:`n`n$stdout`n`n"
    Write-Verbose "Errors:`n`n$stderr`n`n"
}

Function New-CertificateStore {
    <#
    .SYNOPSIS
        Generate a PKCS12 certificate store

    .DESCRIPTION
        The New-CertificateStore command generates a PKCS12 certificate store file. The generated store can be optionally encrypted with a password.

    .PARAMETER KeyFile
        Input key file name.

    .PARAMETER KeyPassword
        Key encryption password.

    .PARAMETER CertificateFile
        Input certificate file name.

    .PARAMETER AuthorityCertificate
        Input authority certificate file name.

    .PARAMETER StoreFile
        Output store file name.

    .PARAMETER StorePassword
        Password for store encryption.

    .PARAMETER Overwrite
        Overwrite the store file if it already exists.

    .PARAMETER OpenSslPath
        Full path to the OpenSSL executable file. Optional if 'openssl.exe' is already located in the shell's command search path.

    .EXAMPLE
        New-CertificateStore key.pem cert.pem certstore.pfx
        Generate a PKCS12 store containing key 'key.pem' and certificate 'cert.pem'. Output the store to file 'certstore.pfx'.

    .EXAMPLE
        New-CertificateStore key.pem cert.pem certstore.pfx -StorePassword (Read-Host -Prompt Password -AsSecureString)
        Generate a PKCS12 store containing key 'key.pem' and certificate 'cert.pem'. Prompt for store encryption password. Output the store to file 'certstore.pfx'.

    .EXAMPLE
        New-CertificateStore key.pem -KeyPassword (Read-Host -Prompt Password -AsSecureString) cert.pem certstore.pfx -AuthorityCertificate cacert.pem
        Generate a PKCS12 store containing key 'key.pem' and certificate 'cert.pem' and authority certificate 'cacert.pem'. Prompt for input key encryption password. Output the store to file 'certstore.pfx'.

    .INPUTS
        None

    .OUTPUTS
        None
    #>

    [CmdletBinding()]
    Param (
    [Parameter(Mandatory=$true, HelpMessage="Input key file name", ParameterSetName="General", Position=0)]
    [ValidateNotNullOrEmpty()]
    [String]
    $KeyFile,

    [Parameter(Mandatory=$false, HelpMessage="Password for key encryption", ParameterSetName="General")]
    [ValidateNotNullOrEmpty()]
    [SecureString]
    $KeyPassword,

    [Parameter(Mandatory=$true, HelpMessage="Input certificate file name", ParameterSetName="General", Position=1)]
    [ValidateNotNullOrEmpty()]
    [String]
    $CertificateFile,

    [Parameter(Mandatory=$false, HelpMessage="Input authority certificate file name", ParameterSetName="General")]
    [ValidateNotNullOrEmpty()]
    [String]
    $AuthorityCertificate,

    [Parameter(Mandatory=$true, HelpMessage="Output store file name", ParameterSetName="General", Position=2)]
    [ValidateNotNullOrEmpty()]
    [String]
    $StoreFile,

    [Parameter(Mandatory=$false, HelpMessage="Password for store encryption", ParameterSetName="General")]
    [ValidateNotNullOrEmpty()]
    [SecureString]
    $StorePassword,

    [Parameter(Mandatory=$false, HelpMessage="Overwrite output store file if exists", ParameterSetName="General")]
    [ValidateNotNullOrEmpty()]
    [Switch]
    $Overwrite,

    [Parameter(Mandatory=$false, HelpMessage="OpenSSL executable file path", ParameterSetName="General")]
    [ValidateNotNullOrEmpty()]
    [String]
    $OpenSslPath
    )

    # OpenSSL executable
    $opensslexe = "openssl.exe"
    if ($OpenSslPath) {
        if (Test-Path -PathType Container $OpenSslPath) { 
            Write-Error "Invalid openssl file name"
            Return
        }
        if (!(Test-Path -PathType Leaf $OpenSslPath)) {
            Write-Error "Openssl file '$OpenSslPath' not found"
            Return
        }
        $opensslexe = $OpenSslPath
    }

    # OpenSSL arguments
    $arguments = @("pkcs12")

    # Export argument
    $arguments += "-export"

    # Inkey argument
    if ($KeyFile) { 
        if (Test-Path -PathType Container $KeyFile) { 
            Write-Error "Invalid input key file name"
            Return
        } elseif (!(Test-Path -PathType Leaf $KeyFile)) {
            Write-Error "Input key file '$KeyFile' not found"
            Return
        }
        $arguments += "-inkey"
        $arguments += "`"$KeyFile`""
    }

    # Passin argument
    $password = ''
    if ($KeyPassword) {
        $password = (New-Object PSCredential "User",$KeyPassword).GetNetworkCredential().Password
    }
    $arguments += "-passin"
    $arguments += "pass:$password"

    # Out argument
    if ($StoreFile) { 
        if (Test-Path -PathType Container $StoreFile) { 
            Write-Error "Invalid output store file name"
            Return
        } elseif ((Test-Path -PathType Leaf $StoreFile) -and (!$Overwrite)) {
            Write-Error "Store file exists (use -Overwrite to overwrite it)"
            Return
        }
        $arguments += "-out"
        $arguments += "`"$StoreFile`""
    }

    # In argument
    if ($CertificateFile) { 
        if (Test-Path -PathType Container $CertificateFile) { 
            Write-Error "Invalid input certificate file name"
            Return
        } elseif (!(Test-Path -PathType Leaf $CertificateFile)) {
            Write-Error "Input certificate file '$CertificateFile' not found"
            Return
        }
        $arguments += "-in"
        $arguments += "`"$CertificateFile`""
    }

    # Certfile argument
    if ($AuthorityCertificate) { 
        if (Test-Path -PathType Container $AuthorityCertificate) { 
            Write-Error "Invalid input authority certificate file name"
            Return
        } elseif (!(Test-Path -PathType Leaf $AuthorityCertificate)) {
            Write-Error "Input authority certificate file '$AuthorityCertificate' not found"
            Return
        }
        $arguments += "-certfile"
        $arguments += "`"$AuthorityCertificate`""
    }

    # Passout argument
    $password = ''
    if ($StorePassword) {
        $password = (New-Object PSCredential "User",$StorePassword).GetNetworkCredential().Password
    }
    $arguments += "-passout"
    $arguments += "pass:$password"

    # Verbose output
    Write-Verbose "Command:`n`nopenssl $([RegEx]::Replace($arguments, 'pass:[^\s].* ', 'pass:*** '))`n`n"

    # Run command
    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    $pinfo.FileName = "$opensslexe"
    $pinfo.RedirectStandardError = $true
    $pinfo.RedirectStandardOutput = $true
    $pinfo.UseShellExecute = $false
    $pinfo.Arguments = $arguments
    $pinfo.WorkingDirectory = Convert-Path .
    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $pinfo
    $proc.Start() | Out-Null
    $proc.WaitForExit(10000) | Out-Null
    $stdout = $proc.StandardOutput.ReadToEnd()
    $stderr = $proc.StandardError.ReadToEnd()

    # Check errors
    if ($proc.ExitCode) {
        Write-Error $stderr
    } else {
        Write-Output $stdout
    }

    # Verbose output
    Write-Verbose "Output:`n`n$stdout`n`n"
    Write-Verbose "Errors:`n`n$stderr`n`n"
}

Function Export-PrivateKey {
    <#
    .SYNOPSIS
        Export private key

    .DESCRIPTION
        The Export-PrivateKey command exports the private key from a PKCS12 input store file.

    .PARAMETER StoreFile
        Input store file name.

    .PARAMETER StorePassword
        Store encryption password.

    .PARAMETER KeyFile
        Output key file name.

    .PARAMETER KeyPassword
        Password for key encryption.

    .PARAMETER Cipher
        Cipher for key encryption (e.g. DES, DES3, IDEA). Default is DES3.

    .PARAMETER Overwrite
        Overwrite the key file if it already exists.

    .PARAMETER OpenSslPath
        Full path to the OpenSSL executable file. Optional if 'openssl.exe' is already located in the shell's command search path.

    .EXAMPLE
        Export-PrivateKey certstore.pfx key.pem
        Export the private key from input store file 'certstore.pfx'. Output the key to file 'key.pem'.

    .EXAMPLE
        Export-PrivateKey certstore.pfx key.pem -KeyPassword (Read-Host -Prompt Password -AsSecureString)
        Export the private key from input store file 'certstore.pfx'. Prompt for key encryption password. Output the key to file 'key.pem'.

    .EXAMPLE
        Export-PrivateKey certstore.pfx -StorePassword (Read-Host -Prompt Password -AsSecureString) key.pem
        Export the private key from input store file 'certstore.pfx'. Prompt for store encryption password. Output the key to file 'key.pem'.

    .INPUTS
        None

    .OUTPUTS
        None
    #>

    [CmdletBinding()]
    Param (
    [Parameter(Mandatory=$true, HelpMessage="Input store file name", ParameterSetName="General", Position=0)]
    [ValidateNotNullOrEmpty()]
    [String]
    $StoreFile,

    [Parameter(Mandatory=$false, HelpMessage="Password for store encryption", ParameterSetName="General")]
    [ValidateNotNullOrEmpty()]
    [SecureString]
    $StorePassword,

    [Parameter(Mandatory=$true, HelpMessage="Output key file name", ParameterSetName="General", Position=1)]
    [ValidateNotNullOrEmpty()]
    [String]
    $KeyFile,

    [Parameter(Mandatory=$false, HelpMessage="Password for key encryption", ParameterSetName="General")]
    [ValidateNotNullOrEmpty()]
    [SecureString]
    $KeyPassword,

    [Parameter(Mandatory=$false, HelpMessage="Cipher for key encryption", ParameterSetName="General")]
    [ValidateSet('DES', 'DES3', 'IDEA', 'AES128', 'AES192', 'AES256', 'CAMELLIA128', 'CAMELLIA192', 'CAMELLIA256')]
    [ValidateNotNullOrEmpty()]
    [String]
    $Cipher="DES3",

    [Parameter(Mandatory=$false, HelpMessage="Overwrite output key file if exists", ParameterSetName="General")]
    [ValidateNotNullOrEmpty()]
    [Switch]
    $Overwrite,

    [Parameter(Mandatory=$false, HelpMessage="OpenSSL executable file path", ParameterSetName="General")]
    [ValidateNotNullOrEmpty()]
    [String]
    $OpenSslPath
    )

    # OpenSSL executable
    $opensslexe = "openssl.exe"
    if ($OpenSslPath) {
        if (Test-Path -PathType Container $OpenSslPath) { 
            Write-Error "Invalid openssl file name"
            Return
        }
        if (!(Test-Path -PathType Leaf $OpenSslPath)) {
            Write-Error "Openssl file '$OpenSslPath' not found"
            Return
        }
        $opensslexe = $OpenSslPath
    }

    # OpenSSL arguments
    $arguments = @("pkcs12")

    # In argument
    if ($StoreFile) { 
        if (Test-Path -PathType Container $StoreFile) { 
            Write-Error "Invalid input store file name"
            Return
        } elseif (!(Test-Path -PathType Leaf $StoreFile)) {
            Write-Error "Input store file '$StoreFile' not found"
            Return
        }
        $arguments += "-in"
        $arguments += "`"$StoreFile`""
    }

    # Passin argument
    $password = ''
    if ($StorePassword) {
        $password = (New-Object PSCredential "User",$StorePassword).GetNetworkCredential().Password
    }
    $arguments += "-passin"
    $arguments += "pass:$password"


    # Nocerts argument
    $arguments += "-nocerts"
    
    # Nodes argument
    if (!$KeyPassword) {
        $arguments += "-nodes"
    }

    # Passout and cipher argument
    if ($KeyPassword) {
        $password = (New-Object PSCredential "User",$KeyPassword).GetNetworkCredential().Password
        if ([string]::IsNullOrEmpty($password.Trim())) {
            $arguments += "-nodes"
        } else {
            $arguments += "-passout"
            $arguments += "pass:$password"
            $arguments += "-$Cipher".ToLower()
        }
    }
  
    # Out argument
    if ($KeyFile) { 
        if (Test-Path -PathType Container $KeyFile) { 
            Write-Error "Invalid output key file name"
            Return
        } elseif ((Test-Path -PathType Leaf $KeyFile) -and (!$Overwrite)) {
            Write-Error "Key file exists (use -Overwrite to overwrite it)"
            Return
        }
        $arguments += "-out"
        $arguments += "`"$KeyFile`""
    }

    # Verbose output
    Write-Verbose "Command:`n`nopenssl $([RegEx]::Replace($arguments, 'pass:[^\s].* ', 'pass:*** '))`n`n"

    # Run command
    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    $pinfo.FileName = "$opensslexe"
    $pinfo.RedirectStandardError = $true
    $pinfo.RedirectStandardOutput = $true
    $pinfo.UseShellExecute = $false
    $pinfo.Arguments = $arguments
    $pinfo.WorkingDirectory = Convert-Path .
    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $pinfo
    $proc.Start() | Out-Null
    $proc.WaitForExit(10000) | Out-Null
    $stdout = $proc.StandardOutput.ReadToEnd()
    $stderr = $proc.StandardError.ReadToEnd()

    # Check errors
    if ($proc.ExitCode) {
        Write-Error $stderr
    } else {
        Write-Output $stdout
    }

    # Verbose output
    Write-Verbose "Output:`n`n$stdout`n`n"
    Write-Verbose "Errors:`n`n$stderr`n`n"
}

Function Export-ClientCertificate {
    <#
    .SYNOPSIS
        Export client certificate

    .DESCRIPTION
        The Export-ClientCertificate command exports the client certificate from a PKCS12 input store file.

    .PARAMETER StoreFile
        Input store file name.

    .PARAMETER StorePassword
        Store encryption password.

    .PARAMETER CertificateFile
        Output certificate file name.

    .PARAMETER Overwrite
        Overwrite the certificate file if it already exists.

    .PARAMETER OpenSslPath
        Full path to the OpenSSL executable file. Optional if 'openssl.exe' is already located in the shell's command search path.

    .EXAMPLE
        Export-ClientCertificate certstore.pfx cert.pem
        Export the client certificate from input store file 'certstore.pfx'. Output the certificate to file 'cert.pem'.


    .EXAMPLE
        Export-ClientCertificate certstore.pfx -StorePassword (Read-Host -Prompt Password -AsSecureString) cert.pem
        Export the client certificate from input store file 'certstore.pfx'. Prompt for store encryption password. Output the certificate to file 'cert.pem'.

    .INPUTS
        None

    .OUTPUTS
        None
    #>

    [CmdletBinding()]
    Param (
    [Parameter(Mandatory=$true, HelpMessage="Input store file name", ParameterSetName="General", Position=0)]
    [ValidateNotNullOrEmpty()]
    [String]
    $StoreFile,

    [Parameter(Mandatory=$false, HelpMessage="Password for store encryption", ParameterSetName="General")]
    [ValidateNotNullOrEmpty()]
    [SecureString]
    $StorePassword,

    [Parameter(Mandatory=$true, HelpMessage="Output certificate file name", ParameterSetName="General", Position=1)]
    [ValidateNotNullOrEmpty()]
    [String]
    $CertificateFile,

    [Parameter(Mandatory=$false, HelpMessage="Overwrite output certificate file if exists", ParameterSetName="General")]
    [ValidateNotNullOrEmpty()]
    [Switch]
    $Overwrite,

    [Parameter(Mandatory=$false, HelpMessage="OpenSSL executable file path", ParameterSetName="General")]
    [ValidateNotNullOrEmpty()]
    [String]
    $OpenSslPath
    )

    # OpenSSL executable
    $opensslexe = "openssl.exe"
    if ($OpenSslPath) {
        if (Test-Path -PathType Container $OpenSslPath) { 
            Write-Error "Invalid openssl file name"
            Return
        }
        if (!(Test-Path -PathType Leaf $OpenSslPath)) {
            Write-Error "Openssl file '$OpenSslPath' not found"
            Return
        }
        $opensslexe = $OpenSslPath
    }

    # OpenSSL arguments
    $arguments = @("pkcs12")

    # In argument
    if ($StoreFile) { 
        if (Test-Path -PathType Container $StoreFile) { 
            Write-Error "Invalid input store file name"
            Return
        } elseif (!(Test-Path -PathType Leaf $StoreFile)) {
            Write-Error "Input store file '$StoreFile' not found"
            Return
        }
        $arguments += "-in"
        $arguments += "`"$StoreFile`""
    }

    # Passin argument
    $password = ''
    if ($StorePassword) {
        $password = (New-Object PSCredential "User",$StorePassword).GetNetworkCredential().Password
    }
    $arguments += "-passin"
    $arguments += "pass:$password"


    # Nokeys argument
    $arguments += "-nokeys"
    
    # Clcerts argument
    $arguments += "-clcerts"
  
    # Out argument
    if ($CertificateFile) { 
        if (Test-Path -PathType Container $CertificateFile) { 
            Write-Error "Invalid output certificate file name"
            Return
        } elseif ((Test-Path -PathType Leaf $CertificateFile) -and (!$Overwrite)) {
            Write-Error "Certificate file exists (use -Overwrite to overwrite it)"
            Return
        }
        $arguments += "-out"
        $arguments += "`"$CertificateFile`""
    }

    # Verbose output
    Write-Verbose "Command:`n`nopenssl $([RegEx]::Replace($arguments, 'pass:[^\s].* ', 'pass:*** '))`n`n"

    # Run command
    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    $pinfo.FileName = "$opensslexe"
    $pinfo.RedirectStandardError = $true
    $pinfo.RedirectStandardOutput = $true
    $pinfo.UseShellExecute = $false
    $pinfo.Arguments = $arguments
    $pinfo.WorkingDirectory = Convert-Path .
    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $pinfo
    $proc.Start() | Out-Null
    $proc.WaitForExit(10000) | Out-Null
    $stdout = $proc.StandardOutput.ReadToEnd()
    $stderr = $proc.StandardError.ReadToEnd()

    # Check errors
    if ($proc.ExitCode) {
        Write-Error $stderr
    } else {
        Write-Output $stdout
    }

    # Verbose output
    Write-Verbose "Output:`n`n$stdout`n`n"
    Write-Verbose "Errors:`n`n$stderr`n`n"
}

Function Export-AuthorityCertificate {
    <#
    .SYNOPSIS
        Export authority certificate

    .DESCRIPTION
        The Export-AuthorityCertificate command exports the authority certificate from a PKCS12 input store file.

    .PARAMETER StoreFile
        Input store file name.

    .PARAMETER StorePassword
        Store encryption password.

    .PARAMETER CertificateFile
        Output certificate file name.

    .PARAMETER Overwrite
        Overwrite the certificate file if it already exists.

    .PARAMETER OpenSslPath
        Full path to the OpenSSL executable file. Optional if 'openssl.exe' is already located in the shell's command search path.

    .EXAMPLE
        Export-AuthorityCertificate certstore.pfx cert.pem
        Export the authority certificate from input store file 'certstore.pfx'. Output the certificate to file 'cert.pem'.

    .EXAMPLE
        Export-AuthorityCertificate certstore.pfx -StorePassword (Read-Host -Prompt Password -AsSecureString) cert.pem
        Export the authority certificate from input store file 'certstore.pfx'. Prompt for store encryption password. Output the certificate to file 'cert.pem'.

    .INPUTS
        None

    .OUTPUTS
        None
    #>

    [CmdletBinding()]
    Param (
    [Parameter(Mandatory=$true, HelpMessage="Input store file name", ParameterSetName="General", Position=0)]
    [ValidateNotNullOrEmpty()]
    [String]
    $StoreFile,

    [Parameter(Mandatory=$false, HelpMessage="Password for store encryption", ParameterSetName="General")]
    [ValidateNotNullOrEmpty()]
    [SecureString]
    $StorePassword,

    [Parameter(Mandatory=$true, HelpMessage="Output certificate file name", ParameterSetName="General", Position=1)]
    [ValidateNotNullOrEmpty()]
    [String]
    $CertificateFile,

    [Parameter(Mandatory=$false, HelpMessage="Overwrite output certificate file if exists", ParameterSetName="General")]
    [ValidateNotNullOrEmpty()]
    [Switch]
    $Overwrite,

    [Parameter(Mandatory=$false, HelpMessage="OpenSSL executable file path", ParameterSetName="General")]
    [ValidateNotNullOrEmpty()]
    [String]
    $OpenSslPath
    )

    # OpenSSL executable
    $opensslexe = "openssl.exe"
    if ($OpenSslPath) {
        if (Test-Path -PathType Container $OpenSslPath) { 
            Write-Error "Invalid openssl file name"
            Return
        }
        if (!(Test-Path -PathType Leaf $OpenSslPath)) {
            Write-Error "Openssl file '$OpenSslPath' not found"
            Return
        }
        $opensslexe = $OpenSslPath
    }

    # OpenSSL arguments
    $arguments = @("pkcs12")

    # In argument
    if ($StoreFile) { 
        if (Test-Path -PathType Container $StoreFile) { 
            Write-Error "Invalid input store file name"
            Return
        } elseif (!(Test-Path -PathType Leaf $StoreFile)) {
            Write-Error "Input store file '$StoreFile' not found"
            Return
        }
        $arguments += "-in"
        $arguments += "`"$StoreFile`""
    }

    # Passin argument
    $password = ''
    if ($StorePassword) {
        $password = (New-Object PSCredential "User",$StorePassword).GetNetworkCredential().Password
    }
    $arguments += "-passin"
    $arguments += "pass:$password"


    # Nokeys argument
    $arguments += "-nokeys"
    
    # Clcerts argument
    $arguments += "-cacerts"
  
    # Output file
    if ($CertificateFile) { 
        if (Test-Path -PathType Container $CertificateFile) { 
            Write-Error "Invalid output certificate file name"
            Return
        } elseif ((Test-Path -PathType Leaf $CertificateFile) -and (!$Overwrite)) {
            Write-Error "Certificate file exists (use -Overwrite to overwrite it)"
            Return
        }
    }

    # Verbose output
    Write-Verbose "Command:`n`nopenssl $([RegEx]::Replace($arguments, 'pass:[^\s].* ', 'pass:*** '))`n`n"

    # Run command
    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    $pinfo.FileName = "$opensslexe"
    $pinfo.RedirectStandardError = $true
    $pinfo.RedirectStandardOutput = $true
    $pinfo.UseShellExecute = $false
    $pinfo.Arguments = $arguments
    $pinfo.WorkingDirectory = Convert-Path .
    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $pinfo
    $proc.Start() | Out-Null
    $proc.WaitForExit(10000) | Out-Null
    $stdout = $proc.StandardOutput.ReadToEnd()
    $stderr = $proc.StandardError.ReadToEnd()

    # Check errors
    if ($proc.ExitCode) {
        Write-Error $stderr
    } elseif (!($stdout | Select-String "BEGIN" -SimpleMatch -Quiet)) {
        Write-Error "Store contains no authority certificate"
    } else {
        Set-Content $CertificateFile $stdout
    }

    # Verbose output
    Write-Verbose "Output:`n`n$stdout`n`n"
    Write-Verbose "Errors:`n`n$stderr`n`n"
}
