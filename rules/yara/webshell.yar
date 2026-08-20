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

rule HuntWarden_PHP_Request_To_Command_Chain
{
    meta:
        description = "PHP request-controlled command execution chain requiring analyst correlation"
        confidence = "high-when-correlated"
    strings:
        $php = "<?php" ascii nocase
        $input = /\$_(GET|POST|REQUEST|COOKIE)\s*\[/ ascii nocase
        $exec = /\b(system|shell_exec|passthru|popen|proc_open)\s*\(/ ascii nocase
    condition:
        filesize < 10MB and $php and $input and $exec
}

rule HuntWarden_JSP_Request_To_Process_Chain
{
    meta:
        description = "JSP request parameter flowing into Java process execution primitives"
        confidence = "high-when-correlated"
    strings:
        $jsp = "<%@ page" ascii nocase
        $request = /request\.getParameter\s*\(/ ascii
        $runtime = "Runtime.getRuntime().exec" ascii
        $builder = "new ProcessBuilder" ascii
    condition:
        filesize < 10MB and $jsp and $request and 1 of ($runtime, $builder)
}

rule HuntWarden_PHP_Obfuscated_Loader_Chain
{
    meta:
        description = "Multiple PHP decoding and dynamic execution primitives"
        confidence = "medium"
    strings:
        $php = "<?php" ascii nocase
        $decode1 = /\bbase64_decode\s*\(/ ascii nocase
        $decode2 = /\b(gzinflate|gzuncompress|str_rot13)\s*\(/ ascii nocase
        $dynamic1 = /\beval\s*\(/ ascii nocase
        $dynamic2 = /\bassert\s*\(/ ascii nocase
    condition:
        filesize < 10MB and $php and 1 of ($decode*) and 1 of ($dynamic*)
}

rule HuntWarden_PHP_Auto_Prepend_Persistence
{
    meta:
        description = "PHP per-directory auto_prepend_file persistence directive"
        confidence = "medium"
    strings:
        $directive = /auto_prepend_file\s*=\s*[^;\r\n]+/ ascii nocase
    condition:
        filesize < 64KB and $directive
}
