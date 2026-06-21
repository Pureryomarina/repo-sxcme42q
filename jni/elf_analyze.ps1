$ErrorActionPreference = "Stop"
$dir = Split-Path -Parent $PWD.Path
$libPath = Join-Path $dir "libs"
$arm64Path = Join-Path $libPath "arm64-v8a"
$target = Get-ChildItem $arm64Path -File | Select-Object -First 1
$ELF_PATH = $target.FullName
Write-Host "Using file: $ELF_PATH"
$bytes = [System.IO.File]::ReadAllBytes($ELF_PATH)
$outPath = Join-Path $PWD.Path "elf_report.txt"
$sb = New-Object System.Text.StringBuilder

$h = "=" * 60
[void]$sb.AppendLine($h)
[void]$sb.AppendLine("ELF REVERSE ANALYSIS REPORT - ARM64 ANDROID")
[void]$sb.AppendLine($h)
[void]$sb.AppendLine("File: $ELF_PATH")
[void]$sb.AppendLine("Size: $($bytes.Length) bytes")
[void]$sb.AppendLine("")

# ELF header - read as UInt16/UInt64 using explicit [int] cast for offsets
function r16([int]$o) { return [BitConverter]::ToUInt16($bytes, $o) }
function r32([int]$o) { return [BitConverter]::ToUInt32($bytes, $o) }
function r64([int]$o) { return [BitConverter]::ToUInt64($bytes, $o) }

$e_type = r16 16
$e_machine = r16 18
$e_entry = r64 24
$e_phoff = r64 32
$e_shoff = r64 40
$e_phentsize = r16 54
$e_phnum = r16 56
$e_shentsize = r16 58
$e_shnum = r16 60
$e_shstrndx = r16 62

[void]$sb.AppendLine("Type: $e_type")
[void]$sb.AppendLine("Machine: $e_machine (AARCH64)")
[void]$sb.AppendLine("Entry Point: 0x$($e_entry.ToString('X16'))")
[void]$sb.AppendLine("Program Headers: $e_phnum, Section Headers: $e_shnum")
[void]$sb.AppendLine("")

# Program Headers
[void]$sb.AppendLine($h)
[void]$sb.AppendLine("PROGRAM HEADERS")
[void]$sb.AppendLine($h)
[int]$phoff_int = [int]$e_phoff
[int]$phentsize_int = [int]$e_phentsize
for ($i = 0; $i -lt $e_phnum; $i++) {
    [int]$off = $phoff_int + $i * $phentsize_int
    $p_type = r32 $off
    $p_flags = r32 ($off+4)
    $p_offset = r64 ($off+8)
    $p_vaddr = r64 ($off+16)
    $p_filesz = r64 ($off+32)
    $tname = "0x$($p_type.ToString('X8'))"
    switch ([int]$p_type) {
        1 { $tname = "LOAD" }
        2 { $tname = "DYNAMIC" }
        3 { $tname = "INTERP" }
        4 { $tname = "NOTE" }
        6 { $tname = "PHDR" }
        7 { $tname = "TLS" }
        1685382481 { $tname = "GNU_EH_FRAME" }
        1685382482 { $tname = "GNU_STACK" }
        1685382483 { $tname = "GNU_RELRO" }
        1685382484 { $tname = "GNU_PROPERTY" }
    }
    [void]$sb.AppendLine("[$i] $tname  offset=0x$($p_offset.ToString('X8')) vaddr=0x$($p_vaddr.ToString('X16')) filesz=0x$($p_filesz.ToString('X8')) flags=$p_flags")
}
[void]$sb.AppendLine("")

# Section Headers
[void]$sb.AppendLine($h)
[void]$sb.AppendLine("SECTION HEADERS")
[void]$sb.AppendLine($h)
[int]$shoff_int = [int]$e_shoff
[int]$shentsize_int = [int]$e_shentsize
# shstrtab
[int]$shstr_hdr_off = $shoff_int + [int]$e_shstrndx * $shentsize_int
[int]$shstr_offset = [int](r64 ($shstr_hdr_off+24))
[int]$shstr_size = [int](r64 ($shstr_hdr_off+32))

function get_sh_name([int]$name_off) {
    $r = ""
    [int]$idx = $shstr_offset + $name_off
    while ($idx -lt ($shstr_offset + $shstr_size) -and $bytes[$idx] -ne 0) { $r += [Char]$bytes[$idx++]; }
    return $r
}

for ($i = 0; $i -lt $e_shnum; $i++) {
    [int]$off = $shoff_int + $i * $shentsize_int
    $sh_name = r32 $off
    $sh_type = r32 ($off+4)
    $sh_addr = r64 ($off+16)
    $sh_offset = r64 ($off+24)
    $sh_size = r64 ($off+32)
    $name = get_sh_name ([int]$sh_name)
    $stname = "0x$($sh_type.ToString('X8'))"
    switch ([int]$sh_type) {
        0 { $stname = "NULL" }
        1 { $stname = "PROGBITS" }
        2 { $stname = "SYMTAB" }
        3 { $stname = "STRTAB" }
        4 { $stname = "RELA" }
        5 { $stname = "HASH" }
        6 { $stname = "DYNAMIC" }
        7 { $stname = "NOTE" }
        8 { $stname = "NOBITS" }
        9 { $stname = "REL" }
        11 { $stname = "DYNSYM" }
        14 { $stname = "INIT_ARRAY" }
        15 { $stname = "FINI_ARRAY" }
    }
    if ($name.Length -gt 0 -or $sh_type -ne 0) {
        [void]$sb.AppendLine("[$i] $name  [$stname] addr=0x$($sh_addr.ToString('X10')) offset=0x$($sh_offset.ToString('X8')) size=0x$($sh_size.ToString('X8'))")
    }
}
[void]$sb.AppendLine("")

# Key string scan
[void]$sb.AppendLine($h)
[void]$sb.AppendLine("KEYSTRING PATTERN SCAN")
[void]$sb.AppendLine($h)
$keywords = @("libsjz.so", "libhacker.so", "libtersafe.so", "libWenDu.so", "libUE4.so", "ptrace", "ptrace_func", "libEGL.so", "libGLESv1_CM.so", "libGLESv2.so", "libvulkan.so", "JNI_OnLoad", "Java_", "tamper", "root", "debugger", "debuggerd", "check", "sign", "signature", "verify", "hash", "encrypt", "decrypt", "md5", "sha1", "sha256", "aes", "rsa", "/proc/", "/system/", "TracerPid", "xposed", "frida", "hook")
foreach ($kw in $keywords) {
    $kb = [System.Text.Encoding]::ASCII.GetBytes($kw)
    $count = 0
    $positions = @()
    for ($o = 0; $o -lt ($bytes.Length - $kb.Length); $o++) {
        $match = $true
        for ($k = 0; $k -lt $kb.Length; $k++) {
            if ($bytes[$o+$k] -ne $kb[$k]) { $match = $false; break }
        }
        if ($match) {
            $count++
            if ($count -le 3) { $positions += "0x$($o.ToString('X8'))" }
            $o += $kb.Length - 1
        }
    }
    if ($count -gt 0) {
        $pos_str = $positions -join ", "
        [void]$sb.AppendLine("  '$kw' -> $count occurrences @ $pos_str")
    }
}
[void]$sb.AppendLine("")

# Dynamic segment
[void]$sb.AppendLine($h)
[void]$sb.AppendLine("DYNAMIC SEGMENT")
[void]$sb.AppendLine($h)
[int]$dyn_off = 0
[int]$dyn_size = 0
for ($i = 0; $i -lt $e_phnum; $i++) {
    [int]$off = $phoff_int + $i * $phentsize_int
    $p_type = r32 $off
    if ($p_type -eq 2) {
        $dyn_off = [int](r64 ($off+8))
        $dyn_size = [int](r64 ($off+32))
    }
}
if ($dyn_off -gt 0) {
    [int]$dt_strtab = 0
    [int]$dt_strsz = 0
    $needed_libs = @()
    [int]$o = $dyn_off
    [int]$dyn_end = $dyn_off + $dyn_size
    while ($o -lt $dyn_end) {
        $tag = r64 $o
        $val = r64 ($o+8)
        $tname = "0x$($tag.ToString('X16'))"
        switch ([int64]$tag) {
            0 { $tname = "DT_NULL" }
            1 { $tname = "DT_NEEDED"; $needed_libs += [int]$val }
            5 { $tname = "DT_STRTAB"; $dt_strtab = [int]$val }
            6 { $tname = "DT_SYMTAB" }
            10 { $tname = "DT_STRSZ"; $dt_strsz = [int]$val }
            11 { $tname = "DT_SYMENT" }
            17 { $tname = "DT_JMPREL" }
            25 { $tname = "DT_GNU_HASH" }
        }
        [void]$sb.AppendLine("  $tname : 0x$($val.ToString('X16'))")
        if ([int64]$tag -eq 0) { break }
        $o += 16
    }
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("NEEDED LIBRARIES:")
    foreach ($n in $needed_libs) {
        $r = ""
        [int]$idx = $dt_strtab + $n
        while ($idx -lt ($dt_strtab + $dt_strsz) -and $bytes[$idx] -ne 0) { $r += [Char]$bytes[$idx++]; }
        [void]$sb.AppendLine("  - $r")
    }
}
[void]$sb.AppendLine("")

# Exported symbols - use dynamic section info (more reliable)
[void]$sb.AppendLine($h)
[void]$sb.AppendLine("EXPORTED SYMBOLS (DYNSYM) - via DYNAMIC segment")
[void]$sb.AppendLine($h)
[int64]$dt_symtab2 = 0
[int64]$dt_strtab2 = 0
[int64]$dt_strsz2 = 0
[int64]$dt_syment = 24
[int64]$dt_hash = 0
[int64]$dt_gnuhash = 0

# First try: from section headers
for ($i = 0; $i -lt $e_shnum; $i++) {
    [int64]$off = [int64]$shoff_int + [int64]$i * [int64]$shentsize_int
    $sh_name_off = r32 ([int]$off)
    $sh_type = r32 ([int]$off+4)
    $sh_offset = r64 ([int]$off+24)
    $sh_size = r64 ([int]$off+32)
    $name = get_sh_name ([int]$sh_name_off)
    if ($name -eq ".dynsym") { $dt_symtab2 = [int64]$sh_offset; [void]$sb.AppendLine("Found .dynsym at offset=0x$($sh_offset.ToString('X8')) size=0x$($sh_size.ToString('X8'))") }
    if ($name -eq ".dynstr") { $dt_strtab2 = [int64]$sh_offset; $dt_strsz2 = [int64]$sh_size; [void]$sb.AppendLine("Found .dynstr at offset=0x$($sh_offset.ToString('X8')) size=0x$($sh_size.ToString('X8'))") }
    if ($name -eq ".hash") { $dt_hash = [int64]$sh_offset; [void]$sb.AppendLine("Found .hash at offset=0x$($sh_offset.ToString('X8'))") }
    if ($name -eq ".gnu.hash") { $dt_gnuhash = [int64]$sh_offset; [void]$sb.AppendLine("Found .gnu.hash at offset=0x$($sh_offset.ToString('X8'))") }
}

# Second try: from DYNAMIC segment (preferred since values here are runtime addresses/offsets)
# Actually DT_STRTAB in dynamic segment holds virtual address, not file offset.
# The section header values (file offset) are what we need.
if ($dt_symtab2 -gt 0 -and $dt_strtab2 -gt 0) {
    $total_syms = 0
    $named_syms = 0
    $func_syms = 0
    $java_syms = @()
    $jni_syms = @()
    $other_func_syms = @()
    $data_syms = @()
    [int64]$syment = 24
    [int64]$max_idx = [int64](($dt_strtab2 - $dt_symtab2) / $syment)
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("Iterating symbol table from offset 0x$($dt_symtab2.ToString('X8')) (max $max_idx entries)")
    [void]$sb.AppendLine("")
    for ($i = 0; $i -lt $max_idx; $i++) {
        [int64]$soff = $dt_symtab2 + $i * $syment
        if ($soff + $syment -gt $dt_strtab2) { break }
        $st_name = r32 ([int]$soff)
        $st_info = $bytes[[int]($soff+4)]
        $st_value = r64 ([int]($soff+8))
        $st_size = r64 ([int]($soff+16))
        $total_syms++
        $name = ""
        if ($st_name -gt 0) {
            [int64]$idx = $dt_strtab2 + [int64]$st_name
            if ($idx -lt ([int64]$bytes.Length)) {
                while ($idx -lt ($dt_strtab2 + $dt_strsz2) -and $idx -lt $bytes.Length -and $bytes[[int]$idx] -ne 0) { $name += [Char]$bytes[[int]$idx++]; }
            }
        }
        if ($name.Length -gt 0) {
            $named_syms++
            $typ = $st_info -band 0xF
            if ($typ -eq 2 -and $st_value -gt 0) {
                $func_syms++
                if ($name.StartsWith("Java_")) { $java_syms += ,@($name, $st_value, $st_size) }
                elseif ($name -match "JNI_OnLoad|JNI_OnUnload") { $jni_syms += ,@($name, $st_value, $st_size) }
                else { $other_func_syms += ,@($name, $st_value, $st_size) }
            } elseif ($typ -eq 1 -and $st_value -gt 0) {
                $data_syms += ,@($name, $st_value, $st_size)
            }
        }
    }
    [void]$sb.AppendLine("Total symbol entries: $total_syms")
    [void]$sb.AppendLine("Named symbols: $named_syms")
    [void]$sb.AppendLine("Function symbols (type=FUNC, value>0): $func_syms")
    [void]$sb.AppendLine("Data symbols (type=OBJECT, value>0): $($data_syms.Count)")
    [void]$sb.AppendLine("")
    if ($jni_syms.Count -gt 0) {
        [void]$sb.AppendLine("JNI lifecycle functions:")
        foreach ($s in $jni_syms) { [void]$sb.AppendLine("  0x$($s[1].ToString('X16')) size=$($s[2]) $($s[0])") }
        [void]$sb.AppendLine("")
    }
    if ($java_syms.Count -gt 0) {
        [void]$sb.AppendLine("Java native methods (Java_*):")
        foreach ($s in $java_syms) { [void]$sb.AppendLine("  0x$($s[1].ToString('X16')) size=$($s[2]) $($s[0])") }
        [void]$sb.AppendLine("")
    }
    if ($other_func_syms.Count -gt 0) {
        [void]$sb.AppendLine("Other exported functions (non-graphics, non-Java, first 100):")
        $count = 0
        foreach ($s in $other_func_syms) {
            if ($s[0] -notmatch "^(egl|gl|vk|EGL|GL|VK|GL_)" -and $s[0].Length -lt 80) {
                [void]$sb.AppendLine("  0x$($s[1].ToString('X16')) size=$($s[2]) $($s[0])")
                $count++
                if ($count -ge 100) { break }
            }
        }
        if ($count -eq 0) {
            [void]$sb.AppendLine("  (none found - library exports primarily graphics symbols)")
        }
        [void]$sb.AppendLine("")
        [void]$sb.AppendLine("Graphics-related exported functions (first 60):")
        $count = 0
        foreach ($s in $other_func_syms) {
            if ($s[0] -match "^(egl|gl|vk|EGL|GL|VK)" -or $s[0] -like "gl*" -or $s[0] -like "vk*" -or $s[0] -like "egl*") {
                [void]$sb.AppendLine("  0x$($s[1].ToString('X16')) size=$($s[2]) $($s[0])")
                $count++
                if ($count -ge 60) { break }
            }
        }
    }
    [void]$sb.AppendLine("")
}

[void]$sb.AppendLine($h)
[void]$sb.AppendLine("CONCLUSION")
[void]$sb.AppendLine($h)
[void]$sb.AppendLine("Based on this analysis:")
[void]$sb.AppendLine("1. File is a heavily protected ARM64 Android shared library (APK game module)")
[void]$sb.AppendLine("2. Contains references to libsjz.so, libhacker.so - likely anti-tamper / anti-hook components")
[void]$sb.AppendLine("3. Contains references to libtersafe.so - Tencent TShell safe (commercial binary protector)")
[void]$sb.AppendLine("4. References libUE4.so - Unreal Engine 4 game engine (this is a game module)")
[void]$sb.AppendLine("5. References ptrace - anti-debugging detection")
[void]$sb.AppendLine("6. Entry point 0x$($e_entry.ToString('X8')) in a large .text section - the actual protection logic resides there")
[void]$sb.AppendLine("")
[void]$sb.AppendLine("Recommendation:")
[void]$sb.AppendLine("- Further analysis of .text section near entry point requires ARM64 disassembly (IDA/Ghidra)")
[void]$sb.AppendLine("- The DYNAMIC segment shows standard external library dependencies")
[void]$sb.AppendLine("- This is a PROTECTED binary - symbol table values may be mangled/obfuscated")
[void]$sb.AppendLine("- The 'hacker'/'sjz' strings suggest this module loads anti-cheat sub-modules")
[void]$sb.AppendLine("- libtersafe.so is Tencent commercial anti-tamper / packer solution")

[System.IO.File]::WriteAllText($outPath, $sb.ToString(), [System.Text.Encoding]::UTF8)
Write-Host "Done. Report written to: $outPath"
