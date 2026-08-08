<?php
// False-positive fixture: documents blocked functions but never invokes them.
$blockedFunctions = ["eval", "shell_exec", "base64_decode"];
echo implode(",", $blockedFunctions);
