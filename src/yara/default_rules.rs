pub const MALWARE_GENERIC: &str = r#"
rule malware_generic {
    meta:
        description = "Generic malware detection patterns"
        severity = "high"
        author = "CoreEDR"
    strings:
        $s1 = "CreateRemoteThread" ascii
        $s2 = "VirtualAllocEx" ascii
        $s3 = "WriteProcessMemory" ascii
        $s4 = "NtUnmapViewOfSection" ascii
        $s5 = "QueueUserAPC" ascii
        $s6 = "SetWindowsHookExA" ascii
        $s7 = "SetWindowsHookExW" ascii
        $api1 = { 48 89 E5 48 83 EC 20 }
        $api2 = { 48 83 C4 48 5B C3 }
        $enc1 = { 6A 40 68 00 10 00 00 68 00 00 00 00 FF D0 }
        $mutex1 = "Global\\Mutex" ascii wide
        $persistence1 = "CurrentVersion\\Run" ascii
        $persistence2 = "CurrentVersion\\RunOnce" ascii
        $persistence3 = "\\Startup\\" ascii
    condition:
        3 of ($s*) or
        ($api1 and $api2) or
        ($enc1 and 1 of ($persistence*)) or
        (2 of ($s*) and $mutex1)
}

rule packed_executable {
    meta:
        description = "Detects packed or encrypted executables"
        severity = "medium"
        author = "CoreEDR"
    strings:
        $upx1 = "UPX0" ascii
        $upx2 = "UPX1" ascii
        $upx3 = "UPX!" ascii
        $aspack = "ASPack" ascii
        $pecompact = "PECompact" ascii
        $themida = "Themida" ascii
        $vmprotect = ".vmp0" ascii
        $mpress = "MPRESS" ascii
    condition:
        2 of ($upx*) or
        1 of ($aspack, $pecompact, $themida, $vmprotect, $mpress)
}
"#;

pub const SUSPICIOUS_POWERSHELL: &str = r#"
rule suspicious_powershell_encoded {
    meta:
        description = "Detects encoded PowerShell command execution"
        severity = "high"
        author = "CoreEDR"
    strings:
        $ps1 = "powershell" ascii nocase
        $ps2 = "pwsh" ascii nocase
        $enc1 = "-enc" ascii nocase
        $enc2 = "-EncodedCommand" ascii nocase
        $enc3 = "-e " ascii nocase
        $bypass1 = "-ExecutionPolicy" ascii nocase
        $bypass2 = "Bypass" ascii nocase
        $hidden1 = "-WindowStyle" ascii nocase
        $hidden2 = "Hidden" ascii nocase
        $nop1 = "-NoProfile" ascii nocase
        $nop2 = "-NonInteractive" ascii nocase
        $download1 = "DownloadString" ascii nocase
        $download2 = "DownloadFile" ascii nocase
        $download3 = "Invoke-WebRequest" ascii nocase
        $download4 = "Net.WebClient" ascii nocase
        $download5 = "Start-BitsTransfer" ascii nocase
        $invoke1 = "Invoke-Expression" ascii nocase
        $invoke2 = "IEX" ascii nocase
        $invoke3 = "Invoke-Command" ascii nocase
        $invoke4 = "Invoke-Mimikatz" ascii nocase
        $invoke5 = "Invoke-BloodHound" ascii nocase
        $invoke6 = "Invoke-Kerberoast" ascii nocase
    condition:
        ($ps1 or $ps2) and
        (2 of ($enc*, $bypass*, $hidden*)) or
        (($ps1 or $ps2) and 1 of ($download*)) or
        (($ps1 or $ps2) and 1 of ($invoke*))
}

rule powershell_download_cradle {
    meta:
        description = "Detects PowerShell download cradle patterns"
        severity = "critical"
        author = "CoreEDR"
    strings:
        $cradle1 = "IEX (New-Object" ascii nocase
        $cradle2 = "Invoke-Expression" ascii nocase
        $cradle3 = "[Net.WebRequest]::Create" ascii nocase
        $cradle4 = "DownloadString(" ascii nocase
        $cradle5 = "DownloadData(" ascii nocase
        $cradle6 = "DownloadFile(" ascii nocase
        $cradle7 = "DownloadFileTaskAsync(" ascii nocase
        $cradle8 = "DownloadDataTaskAsync(" ascii nocase
        $cradle9 = "DownloadStringTaskAsync(" ascii nocase
        $cradle10 = "System.Net.WebClient" ascii nocase
        $cradle11 = "System.Net.HttpWebRequest" ascii nocase
        $cradle12 = "Invoke-WebRequest" ascii nocase
        $cradle13 = "Start-BitsTransfer" ascii nocase
        $cradle14 = "certutil -urlcache" ascii nocase
        $cradle15 = "certutil -split" ascii nocase
    condition:
        3 of ($cradle*) or
        1 of ($cradle1, $cradle2, $cradle3) and 1 of ($cradle4, $cradle5, $cradle6)
}
"#;

pub const CREDENTIAL_DUMPING: &str = &r#"rule mimikatz_detection {
    meta:
        description = "Detects Mimikatz and credential dumping tools"
        severity = "critical"
        author = "CoreEDR"
    strings:
        $mim1 = "mimikatz" ascii wide nocase
        $mim2 = "mimilib" ascii wide nocase
        $mim3 = "sekurlsa" ascii wide nocase
        $mim4 = "kerberos::list" ascii wide nocase
        $mim5 = "lsadump::sam" ascii wide nocase
        $mim6 = "lsadump::dcsync" ascii wide nocase
        $mim7 = "lsadump::lsa" ascii wide nocase
        $mim8 = "privilege::debug" ascii wide nocase
        $mim9 = "token::elevate" ascii wide nocase
        $mim10 = "dpapi::cred" ascii wide nocase
        $mim11 = "crypto::capi" ascii wide nocase
        $mim12 = "sid::patch" ascii wide nocase
        $mim13 = "misc::skeleton" ascii wide nocase
        $mim14 = " kullmim" ascii wide nocase
        $mim15 = "mimidrv" ascii wide nocase
    condition:
        4 of ($mim*) or
        $mim1 and 2 of ($mim[3-15])
}

rule credential_dumping_tools {
    meta:
        description = "Detects various credential dumping tools"
        severity = "critical"
        author = "CoreEDR"
    strings:
        $tools1 = "lazagne" ascii wide nocase
        $tools2 = "LaZagne" ascii wide
        $tools3 = "procdump" ascii wide nocase
        $tools4 = "sqldumper" ascii wide nocase
        $tools5 = "comsvcs.dll" ascii wide nocase
        $tools6 = "MiniDump" ascii wide
        $tools7 = "ntds.dit" ascii wide nocase
        $tools8 = "SYSTEM\\CurrentControlSet" ascii wide
        $tools9 = "SAM" ascii wide
        $tools10 = "SECURITY" ascii wide
        $access1 = "OpenProcess" ascii
        $access2 = "ReadProcessMemory" ascii
        $access3 = "MiniDumpWriteDump" ascii
        $access4 = "MiniDumpWithFullMemory" ascii
    condition:
        2 of ($tools*) or
        ($tools3 and 1 of ($access*)) or
        ($tools5 and 1 of ($access*)) or
        (1 of ($tools[7-10]) and 2 of ($access*))
}

rule lsass_access {
    meta:
        description = "Detects LSASS process access patterns used in credential theft"
        severity = "critical"
        author = "CoreEDR"
    strings:
        $lsass1 = "lsass" ascii wide nocase
        $proc1 = "procdump" ascii wide nocase
        $proc2 = "procdump64" ascii wide nocase
        $proc3 = "tasklist" ascii wide nocase
        $proc4 = "HandleKace" ascii wide nocase
        $api1 = "OpenProcess" ascii
        $api2 = "ReadProcessMemory" ascii
        $api3 = "MiniDumpWriteDump" ascii
        $dump1 = ".dmp" ascii wide
        $dump2 = "lsass.dmp" ascii wide nocase
        $dump3 = "lsass.exe.dmp" ascii wide nocase
    condition:
        $lsass1 and (1 of ($proc*) or 2 of ($api*) or 1 of ($dump*))
}
"#;

pub const RANSOMWARE: &str = r#"
rule ransomware_behavior {
    meta:
        description = "Detects ransomware behavior patterns"
        severity = "critical"
        author = "CoreEDR"
    strings:
        $note1 = "README_FOR_DECRYPT" ascii wide nocase
        $note2 = "DECRYPT_INSTRUCTIONS" ascii wide nocase
        $note3 = "HOW_TO_DECRYPT" ascii wide nocase
        $note4 = "RESTORE_FILES" ascii wide nocase
        $note5 = "RECOVER_FILES" ascii wide nocase
        $note6 = "your files have been encrypted" ascii wide nocase
        $note7 = "all your files" ascii wide nocase
        $note8 = "decrypt your files" ascii wide nocase
        $note9 = "pay" ascii wide nocase
        $note10 = "bitcoin" ascii wide nocase
        $ext1 = ".locked" ascii wide nocase
        $ext2 = ".encrypted" ascii wide nocase
        $ext3 = ".crypto" ascii wide nocase
        $ext4 = ".crypted" ascii wide nocase
        $ext5 = ".enc" ascii wide nocase
        $ext6 = ".lock" ascii wide nocase
        $ext7 = ".wnry" ascii wide nocase
        $ext8 = ".wcry" ascii wide nocase
        $ext9 = ".wncry" ascii wide nocase
        $ext10 = ".ryk" ascii wide nocase
        $ext11 = ".rhysida" ascii wide nocase
        $crypto1 = "AES" ascii wide
        $crypto2 = "RSA" ascii wide
        $crypto3 = "AES-256" ascii wide
        $crypto4 = "RSA-2048" ascii wide
        $crypto5 = "encrypt" ascii wide nocase
        $crypto6 = "decrypt" ascii wide nocase
        $vss1 = "vssadmin delete shadows" ascii wide nocase
        $vss2 = "wmic shadowcopy delete" ascii wide nocase
        $vss3 = "bcdedit /set {default} recoveryenabled no" ascii wide nocase
        $vss4 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" ascii wide nocase
        $vss5 = "wbadmin delete catalog" ascii wide nocase
    condition:
        (2 of ($note*) and 2 of ($ext*)) or
        (1 of ($vss*) and 2 of ($crypto*)) or
        (3 of ($ext*) and 2 of ($crypto*)) or
        (1 of ($note*) and 3 of ($ext*) and 1 of ($crypto*))
}

rule ransomware_file_operations {
    meta:
        description = "Detects mass file encryption operations"
        severity = "critical"
        author = "CoreEDR"
    strings:
        $find1 = "FindFirstFile" ascii
        $find2 = "FindNextFile" ascii
        $find3 = "ReadDirectoryChanges" ascii
        $find4 = "FindFirstFileW" ascii
        $find5 = "FindNextFileW" ascii
        $crypt1 = "CryptEncrypt" ascii
        $crypt2 = "CryptGenKey" ascii
        $crypt3 = "CryptImportKey" ascii
        $write1 = "WriteFile" ascii
        $write2 = "NtWriteFile" ascii
        $rename1 = "MoveFileEx" ascii
        $rename2 = "MoveFileW" ascii
        $rename3 = "NtSetInformationFile" ascii
    condition:
        (1 of ($find*) and 2 of ($crypt*) and 1 of ($write*)) or
        (1 of ($find*) and $crypt1 and $rename1) or
        (2 of ($find*) and 1 of ($crypt*) and 1 of ($rename*))
}
"#;

pub const WEBSHELL: &str = r#"
rule php_webshell {
    meta:
        description = "Detects PHP web shells"
        severity = "critical"
        author = "CoreEDR"
    strings:
        $php1 = "<?php" ascii
        $php2 = "<?=" ascii
        $shell1 = "eval(" ascii
        $shell2 = "assert(" ascii
        $shell3 = "system(" ascii
        $shell4 = "exec(" ascii
        $shell5 = "passthru(" ascii
        $shell6 = "shell_exec(" ascii
        $shell7 = "popen(" ascii
        $shell8 = "proc_open(" ascii
        $shell9 = "pcntl_exec(" ascii
        $cmd1 = "cmd.exe" ascii
        $cmd2 = "/bin/sh" ascii
        $cmd3 = "/bin/bash" ascii
        $cmd4 = "cmd /c" ascii
        $cmd5 = "command -e" ascii
        $file1 = "fopen(" ascii
        $file2 = "fwrite(" ascii
        $file3 = "file_get_contents(" ascii
        $file4 = "file_put_contents(" ascii
        $file5 = "readfile(" ascii
        $file6 = "file(" ascii
        $upload1 = "move_uploaded_file(" ascii
        $upload2 = "$_FILES" ascii
        $upload3 = "$_POST" ascii
        $upload4 = "$_GET" ascii
        $upload5 = "$_REQUEST" ascii
        $obf1 = "base64_decode(" ascii
        $obf2 = "str_rot13(" ascii
        $obf3 = "gzinflate(" ascii
        $obf4 = "gzuncompress(" ascii
        $obf5 = "gzdecode(" ascii
        $obf6 = "str_replace(" ascii
        $obf7 = "chr(" ascii
        $obf8 = "intval(" ascii
    condition:
        ($php1 or $php2) and
        (2 of ($shell*) or
         (1 of ($shell*) and 2 of ($cmd*)) or
         (1 of ($upload*) and 1 of ($shell*)) or
         (3 of ($obf*) and 1 of ($shell*)))
}

rule asp_webshell {
    meta:
        description = "Detects ASP/ASPX web shells"
        severity = "critical"
        author = "CoreEDR"
    strings:
        $asp1 = "<%" ascii
        $asp2 = "Response.Write" ascii nocase
        $shell1 = "eval(Request" ascii nocase
        $shell2 = "Execute(Request" ascii nocase
        $shell3 = "cmd.exe /c" ascii nocase
        $shell4 = "/bin/sh -c" ascii nocase
        $shell5 = "WScript.Shell" ascii nocase
        $shell6 = "Shell.Application" ascii nocase
        $shell7 = "Process.Start" ascii nocase
        $upload1 = "Request.BinaryRead" ascii nocase
        $upload2 = "SaveAs" ascii nocase
        $upload3 = "Upload" ascii nocase
        $db1 = "Connection" ascii nocase
        $db2 = "ExecuteNonQuery" ascii nocase
        $db3 = "SqlCommand" ascii nocase
        $db4 = "OleDbCommand" ascii nocase
    condition:
        $asp1 and (2 of ($shell*) or
                   (1 of ($shell*) and 1 of ($upload*)) or
                   (2 of ($db*) and 1 of ($shell*)))
}
"#;

pub const ENCODED_EXEC: &str = r#"
rule base64_executable {
    meta:
        description = "Detects base64-encoded executable content"
        severity = "high"
        author = "CoreEDR"
    strings:
        $b64_exe1 = "TVqQAAMAAAAEAAAA" ascii
        $b64_exe2 = "TVpB" ascii
        $b64_exe3 = "TVoA" ascii
        $b64_exe4 = "TVpQ" ascii
        $b64_elf1 = "f0VMRgEBAQ" ascii
        $b64_elf2 = "ELF" ascii
        $b64_dll1 = "TVpTAA" ascii
        $b64_dll2 = "TVpG" ascii
        $decode1 = "base64_decode" ascii
        $decode2 = "FromBase64String" ascii
        $decode3 = "from_base64" ascii
        $decode4 = "atob(" ascii
        $decode5 = "atob =" ascii
        $decode6 = "Buffer.from(" ascii
        $decode7 = "Convert.FromBase64" ascii
        $decode8 = "base64.b64decode" ascii
        $decode9 = "Base64::decode" ascii
        $decode10 = "base64 --decode" ascii
        $decode11 = "openssl enc -d -base64" ascii
        $decode12 = "python -c" ascii
        $decode13 = "perl -e" ascii
    condition:
        1 of ($b64_exe*) and 1 of ($decode*) or
        1 of ($b64_elf*) and 1 of ($decode*) or
        1 of ($b64_dll*) and 1 of ($decode*)
}

rule obfuscated_scripts {
    meta:
        description = "Detects obfuscated script execution patterns"
        severity = "high"
        author = "CoreEDR"
    strings:
        $vbs1 = "Execute(" ascii nocase
        $vbs2 = "ExecuteGlobal(" ascii nocase
        $vbs3 = "Replace(" ascii nocase
        $vbs4 = "Chr(" ascii nocase
        $vbs5 = "ChrW(" ascii nocase
        $vbs6 = "StrReverse(" ascii nocase
        $vbs7 = "Mid(" ascii nocase
        $vbs8 = "StrConv(" ascii nocase
        $js1 = "eval(" ascii
        $js2 = "eval (" ascii
        $js3 = "Function(" ascii
        $js4 = "String.fromCharCode(" ascii
        $js5 = "unescape(" ascii
        $js6 = "decodeURIComponent(" ascii
        $js7 = "atob(" ascii
        $js8 = "document.write(" ascii
        $js9 = "Scripting.FileSystemObject" ascii
        $ps1 = "[Convert]::FromBase64String" ascii nocase
        $ps2 = "-join" ascii nocase
        $ps3 = "[char]" ascii nocase
        $ps4 = '$env:COMSPEC' ascii nocase
        $ps5 = 'iex ' ascii nocase
        $ps6 = 'Invoke-Expression' ascii nocase
        $cmd1 = "cmd /c" ascii nocase
        $cmd2 = "cmd.exe /c" ascii nocase
        $cmd3 = "/bin/sh -c" ascii nocase
        $cmd4 = "bash -c" ascii nocase
    condition:
        (3 of ($vbs*) and 1 of ($cmd*)) or
        (2 of ($js*) and 1 of ($cmd*)) or
        (2 of ($ps*) and 1 of ($cmd*)) or
        (4 of ($vbs*)) or
        (3 of ($js*)) or
        (3 of ($ps*))
}

rule encoded_persistence {
    meta:
        description = "Detects encoded commands used for persistence"
        severity = "critical"
        author = "CoreEDR"
    strings:
        $task1 = "schtasks" ascii wide nocase
        $task2 = "Register-ScheduledTask" ascii wide nocase
        $task3 = "New-ScheduledTask" ascii wide nocase
        $task4 = "schtasks /create" ascii wide nocase
        $reg1 = "reg add" ascii wide nocase
        $reg2 = "New-ItemProperty" ascii wide nocase
        $reg3 = "Set-ItemProperty" ascii wide nocase
        $reg4 = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
        $reg5 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
        $reg6 = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii wide nocase
        $service1 = "New-Service" ascii wide nocase
        $service2 = "sc create" ascii wide nocase
        $service3 = "sc config" ascii wide nocase
        $service4 = "Set-Service" ascii wide nocase
        $encode1 = "-EncodedCommand" ascii wide nocase
        $encode2 = "-enc " ascii wide nocase
        $encode3 = "FromBase64String" ascii wide nocase
        $encode4 = "[Convert]::FromBase64" ascii wide nocase
        $encode5 = "base64_decode" ascii wide nocase
    condition:
        (1 of ($task*, $reg*, $service*) and 1 of ($encode*)) or
        (2 of ($task*)) or
        (2 of ($reg[4-6])) or
        (1 of ($task*) and 1 of ($reg*))
}
"#;
