# SPPCmdlets

PowerShell wrapper module for common OpenSSL commands

## Description

This is a PowerShell wrapper module for managing keys and certificates using OpenSSL.
It contains commands to create and manage private keys, certificate requests, and certificates.

## Installation

Using the zip file:
- Download the OpenSSL.zip file to a temporary location
- Check the file properties and unblock it if blocked
- To install for the current user, extract the zip file to the user's PowerShell modules folder:
  "%USERPROFILE%\Documents\WindowsPowerShell\Modules\OpenSSL"
- To install for all users, extract the zip file to the system's PowerShell modules folder:
  "%PROGRAMFILES%\WindowsPowerShell\Modules\OpenSSL"

Using the powershell gallery:
- To install for the current user, start a PowerShell session and run:
  PS> Install-Module -Name OpenSSL -Scope CurrentUser
- To install for all users, start a PowerShell session, with admin privileges, and run:
  PS> Install-Module -Name OpenSSL -Scope AllUsers

## Usage

### Create a CA certificate

Start by creating a private key and CA root certificate:

```
PS> New-PrivateKey -KeyFile ca.key -KeySize 2048
PS> New-SelfSignedCertificate -KeyFile ca.key -SubjectName CN:MyCA,O:Lab,C:AU,ST:NSW,L:Sydney -CertificateFile ca.pem -ValidDays 3650 -BasicUsage cRLSign,dataEncipherment,digitalSignature,keyAgreement,keyEncipherment -Authority
```

The command `Get-Certificate` displays certificate properties:

```
PS> Get-Certificate -CertificateFile ca.pem
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            7a:c2:6b:3a:71:7f:f7:b7:54:a3:f1:53:04:1a:72:19:c4:0a:02:db
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN = MyCA, O = Lab, C = AU, ST = NSW, L = Sydney
        Validity
            Not Before: Oct 13 23:35:28 2020 GMT
            Not After : Oct 11 23:35:28 2030 GMT
        Subject: CN = MyCA, O = Lab, C = AU, ST = NSW, L = Sydney
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (2048 bit)
                Modulus:
                    00:c7:1e:f7:d1:fc:22:06:bf:3f:00:7d:84:9c:00:
                    69:8b:0d:a8:b0:03:6f:fe:65:cf:65:9e:22:db:8e:
                    c8:d2:21:5b:51:d4:c9:86:fc:a0:c9:b5:43:7e:a0:
                    00:39:74:bc:bf:2f:07:95:04:dd:f9:78:66:fd:47:
                    46:8e:30:bf:71:45:a5:c9:47:5b:cd:be:00:90:56:
                    0d:cd:1f:24:e7:dd:aa:f9:8f:55:2d:ae:e2:e2:be:
                    39:ad:56:a5:0a:ee:e9:87:4e:e3:6a:98:03:9c:f4:
                    68:ae:5b:2c:ca:9e:e2:49:68:9d:62:fd:bf:68:68:
                    34:aa:e4:67:7b:09:76:65:5b:dd:19:60:4f:4e:eb:
                    d5:64:b9:58:c3:89:7f:14:3e:86:01:28:82:95:a1:
                    5f:03:1d:fc:35:dc:9a:7d:87:65:cf:70:8b:0e:d4:
                    55:d9:79:07:a5:b4:19:f9:56:2b:e3:f4:da:81:75:
                    14:87:14:8c:16:8f:c4:32:d5:ec:fc:04:d8:ae:d1:
                    6f:88:9a:8c:5c:8f:b2:bd:5a:fd:e8:30:ff:7b:69:
                    33:3c:f6:f4:3a:39:26:65:77:64:2e:1d:7c:4b:36:
                    81:0e:5e:7b:cf:3c:e3:ba:37:c2:4e:83:45:e3:f3:
                    ef:30:5d:8f:a2:96:0d:99:d5:1a:a5:0e:ee:e8:68:
                    b4:7f
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints:
                CA:TRUE
            X509v3 Authority Key Identifier:
                DirName:/CN=MyCA/O=Lab/C=AU/ST=NSW/L=Sydney
                serial:7A:C2:6B:3A:71:7F:F7:B7:54:A3:F1:53:04:1A:72:19:C4:0A:02:DB

            X509v3 Subject Key Identifier:
                F3:AD:EE:78:34:DC:23:2F:57:7D:B8:43:EA:88:73:92:AD:54:BD:A4
            X509v3 Key Usage:
                Digital Signature, Key Encipherment, Data Encipherment, Key Agreement, CRL Sign
    Signature Algorithm: sha256WithRSAEncryption
         56:0c:70:2f:6c:99:43:02:76:6d:8e:6d:9b:35:3c:9c:2f:b6:
         55:00:9b:5f:69:99:1a:44:28:c8:1c:3f:2a:d9:30:da:a4:d2:
         a0:37:2f:70:1b:e6:0a:7a:28:37:b9:e3:79:e8:2a:d0:ee:20:
         bf:f5:c4:24:ac:97:e5:d1:70:dc:a8:ed:7d:bb:09:08:b0:dc:
         46:28:36:db:5c:96:97:5d:ff:8a:32:fb:c0:51:49:a5:5b:1e:
         e9:a4:bd:4d:7f:05:f2:64:ae:e7:16:c2:c5:16:38:55:e0:5b:
         cd:6f:fc:23:13:07:65:07:e8:18:25:6c:f5:7f:ec:c6:22:25:
         85:46:36:ec:61:11:61:54:98:4f:a0:06:7e:98:b6:81:a6:96:
         90:91:fe:2c:c0:94:50:d8:b1:f6:c9:ef:49:2a:91:0f:65:89:
         48:5f:86:b8:c0:57:8d:47:f1:d2:02:8e:98:ee:5d:10:56:8b:
         0c:4a:d4:02:cd:c7:d0:55:e4:97:18:fc:98:41:dd:7b:e6:bc:
         f7:d2:26:c1:95:bd:d4:f9:d6:0e:a0:71:c6:f9:f2:d9:1a:ad:
         dd:38:72:8c:84:a5:f2:0a:8e:88:c9:69:f0:60:5d:cb:08:91:
         ee:1a:5d:fa:0e:60:55:a9:e9:6d:21:be:b3:08:c5:02:b2:6d:
         34:0e:8a:27
SHA1 Fingerprint=D2:56:5C:55:C0:70:B9:67:9A:76:5C:88:CC:EE:4E:A7:F1:51:77:C5
```

### Create a certificate request

The command `New-CertificateRequest` generates a certificate request:

```
PS> New-PrivateKey -KeyFile webserver.key
PS> New-CertificateRequest -KeyFile webserver.key -SubjectName CN:MyWeb,O:Lab,C:AU,ST:NSW,L:Sydney -RequestFile webserver.req
```

### Sign a certificate request

Use the command `Invoke-SignCertificateRequest` to sign a certificate request:

```
PS> Invoke-SignCertificateRequest -RequestFile webserver.req -AuthorityCertificate ca.pem -AuthorityKey ca.key -CertificateFile webserver.pem -ValidDays 365 -ExtendedUsage serverAuth -SubjectAlternative DNS:webserver,DNS:webserver.lab.local,IP:10.1.1.1
```
