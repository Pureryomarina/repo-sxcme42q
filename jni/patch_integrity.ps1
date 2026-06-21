param(
    [string]$BinaryPath = "$PSScriptRoot\..\libs\arm64-v8a\safe_bypass"
)

if (-not (Test-Path $BinaryPath)) {
    Write-Host "[ERROR] Binary not found: $BinaryPath"
    exit 1
}

$fs = [System.IO.File]::OpenRead($BinaryPath)
$fileSize = $fs.Length
Write-Host "[INFO] Binary size: $fileSize bytes"

$MAGIC = @(0xDE, 0xAD, 0xBE, 0xEF, 0x12, 0x34, 0x56, 0x78)
$TAIL_SIZE = 44
$MAX_HASH = 0x200000

$hasTail = $false
$payloadSize = $fileSize

if ($fileSize -ge $TAIL_SIZE) {
    $fs.Seek($fileSize - $TAIL_SIZE, [System.IO.SeekOrigin]::Begin) | Out-Null
    $magicBuf = New-Object byte[] 8
    $fs.Read($magicBuf, 0, 8) | Out-Null
    $match = $true
    for ($i = 0; $i -lt 8; $i++) {
        if ($magicBuf[$i] -ne $MAGIC[$i]) { $match = $false; break }
    }
    $hasTail = $match
    if ($hasTail) {
        $payloadSize = $fileSize - $TAIL_SIZE
        Write-Host "[INFO] Tail found, payload size: $payloadSize"
    } else {
        Write-Host "[INFO] No tail, will append"
    }
}

$toHash = $payloadSize
if ($toHash -gt $MAX_HASH) { $toHash = $MAX_HASH }
Write-Host "[INFO] Hashing $toHash bytes..."

$fs.Seek(0, [System.IO.SeekOrigin]::Begin) | Out-Null
$readBuf = New-Object byte[] 8192

$crcTable = [System.Collections.Generic.List[uint32]]::new(256)
for ($i = 0; $i -lt 256; $i++) {
    $c = [uint32]$i
    for ($j = 0; $j -lt 8; $j++) {
        if (($c -band 1) -eq 1) { $c = (0xEDB88320 -bxor ($c -shr 1)) } else { $c = ($c -shr 1) }
    }
    $crcTable.Add($c)
}

$crcVal = [uint32]::MaxValue
$remaining = $toHash
while ($remaining -gt 0) {
    $toRead = [Math]::Min(8192, $remaining)
    $read = $fs.Read($readBuf, 0, $toRead)
    if ($read -eq 0) { break }
    for ($i = 0; $i -lt $read; $i++) {
        $idx = ($crcVal -bxor [uint32]$readBuf[$i]) -band 0xFF
        $crcVal = $crcTable[$idx] -bxor ($crcVal -shr 8)
    }
    $remaining -= $read
}
$actualCrc = $crcVal -bxor 0xFFFFFFFF
Write-Host "[INFO] CRC32: $([string]::Format('0x{0:X8}', $actualCrc))"

$fs.Close()

$allBytes = [System.IO.File]::ReadAllBytes($BinaryPath)
$payload = $allBytes[0..($toHash - 1)]

$use = [System.Security.Cryptography.SHA256]::Create()
$hashBytes = $use.ComputeHash($payload)
$use.Dispose()
$sha256Hex = -join ($hashBytes | ForEach-Object { $_.ToString("X2") })
Write-Host "[INFO] SHA256: $sha256Hex"

if ($hasTail) {
    $tailExpCrcBytes = $allBytes[($payloadSize+8)..($payloadSize+11)]
    $tailExpCrc = [uint32]$tailExpCrcBytes[0] -shl 24 -bor [uint32]$tailExpCrcBytes[1] -shl 16 -bor [uint32]$tailExpCrcBytes[2] -shl 8 -bor [uint32]$tailExpCrcBytes[3]
    $tailExpSha = $allBytes[($payloadSize+12)..($payloadSize+43)]
    $shaMatch = $true
    for ($i = 0; $i -lt 32; $i++) {
        if ($hashBytes[$i] -ne $tailExpSha[$i]) { $shaMatch = $false; break }
    }
    if ($actualCrc -eq $tailExpCrc -and $shaMatch) {
        Write-Host "[OK] Already converged."
        exit 0
    }
    Write-Host "[INFO] Tail invalid, re-converging..."
}

Write-Host "[INFO] Appending 44-byte tail..."

$newTail = [byte[]]::new($TAIL_SIZE)
for ($i = 0; $i -lt 8; $i++) { $newTail[$i] = $MAGIC[$i] }
$newTail[8]  = [byte](($actualCrc -shr 24) -band 0xFF)
$newTail[9]  = [byte](($actualCrc -shr 16) -band 0xFF)
$newTail[10] = [byte](($actualCrc -shr 8) -band 0xFF)
$newTail[11] = [byte]($actualCrc -band 0xFF)
for ($i = 0; $i -lt 32; $i++) { $newTail[12 + $i] = $hashBytes[$i] }

if ($hasTail) {
    $newData = [byte[]]::new($payloadSize + $TAIL_SIZE)
    [Array]::Copy($allBytes, 0, $newData, 0, $payloadSize)
    [Array]::Copy($newTail, 0, $newData, $payloadSize, $TAIL_SIZE)
} else {
    $newData = [byte[]]::new($fileSize + $TAIL_SIZE)
    [Array]::Copy($allBytes, 0, $newData, 0, $fileSize)
    [Array]::Copy($newTail, 0, $newData, $fileSize, $TAIL_SIZE)
}

[System.IO.File]::WriteAllBytes($BinaryPath, $newData)
Write-Host "[OK] Tail appended. New size: $($newData.Length)"

$verifyData = [System.IO.File]::ReadAllBytes($BinaryPath)
$verifyPayload = $verifyData[0..($toHash - 1)]
$verifyCrcTable = [System.Collections.Generic.List[uint32]]::new(256)
for ($i = 0; $i -lt 256; $i++) {
    $c = [uint32]$i
    for ($j = 0; $j -lt 8; $j++) {
        if (($c -band 1) -eq 1) { $c = (0xEDB88320 -bxor ($c -shr 1)) } else { $c = ($c -shr 1) }
    }
    $verifyCrcTable.Add($c)
}
$vcrcVal = [uint32]::MaxValue
for ($i = 0; $i -lt $toHash; $i++) {
    $idx = ($vcrcVal -bxor [uint32]$verifyPayload[$i]) -band 0xFF
    $vcrcVal = $verifyCrcTable[$idx] -bxor ($vcrcVal -shr 8)
}
$verifyCrc = $vcrcVal -bxor 0xFFFFFFFF
Write-Host "[VERIFY] Written CRC: $([string]::Format('0x{0:X8}', $actualCrc))"
Write-Host "[VERIFY] Read CRC:    $([string]::Format('0x{0:X8}', $verifyCrc))"

if ($actualCrc -eq $verifyCrc) {
    Write-Host "[OK] Converged in 1 iteration."
    exit 0
} else {
    Write-Host "[ERROR] CRC mismatch after append!"
    exit 1
}
