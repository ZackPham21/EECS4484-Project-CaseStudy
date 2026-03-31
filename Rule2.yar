rule Conti_CobaltStrike_Loader {
    meta:
        description = "Detects loader and staging artifacts used in Conti ransomware attacks"
        author = "Pingyu Chen - EECS 4484 Group 8"
        date = "2026-03-01"
        reference = "https://news.sophos.com/en-us/2021/02/16/conti-ransomware-attack-day-by-day/"

    strings:
        // DLL sideloading
        $dll = "oci.dll" ascii wide

        // Memory injection APIs
        $alloc = "VirtualAlloc" ascii
        $write = "WriteProcessMemory" ascii

        // Cobalt Strike named pipe default
        $pipe = "\\\\.\\pipe\\MSSE-" ascii wide

        // Staging and exfiltration
        $stage = "C:\\Windows\\Temp\\" ascii wide
        $exfil1 = "rclone" ascii nocase
        $exfil2 = "mega.nz" ascii nocase

    condition:
        uint16(0) == 0x5A4D and
        (
            ($alloc and $write and $pipe) or
            ($dll and 1 of ($alloc, $write) and $stage) or
            ($exfil1 and $exfil2)
        )
}
