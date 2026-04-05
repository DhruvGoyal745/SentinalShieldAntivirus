rule Sentinel_Eicar_Test_File
{
    meta:
        description = "Detects the EICAR antivirus test string"
        severity = "high"

    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"

    condition:
        $eicar
}

rule Sentinel_Encoded_PowerShell_Command
{
    meta:
        description = "Detects common encoded PowerShell command patterns"
        severity = "medium"

    strings:
        $encoded = /-enc(odedcommand)?\s+[A-Za-z0-9+\/=]{20,}/ nocase

    condition:
        $encoded
}
