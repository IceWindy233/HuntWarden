rule HuntWarden_Lab_WebShell_Marker
{
    meta:
        description = "Detects the inert HuntWarden WebShell lab marker"
        scope = "lab-only"
    strings:
        $marker = "HUNTWARDEN_LAB_WEBSHELL" ascii
    condition:
        $marker
}

rule HuntWarden_Suspicious_Server_Script_Combination
{
    meta:
        description = "Behavioral combination requiring analyst correlation"
    strings:
        $php = "<?php" ascii nocase
        $jsp = "<%@ page" ascii nocase
        $eval = /\beval\s*\(/ ascii nocase
        $exec1 = "Runtime.getRuntime().exec" ascii
        $exec2 = /\b(shell_exec|passthru|system)\s*\(/ ascii nocase
        $decode = /\b(base64_decode|gzinflate)\s*\(/ ascii nocase
    condition:
        filesize < 10MB and ($php or $jsp) and 2 of ($eval, $exec1, $exec2, $decode)
}
