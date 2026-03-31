rule Conti_Ransomware_Encryptor {
    meta:
        description = "Detects Conti ransomware encryptor based on ransom note, file extension, and API usage"
        author = "Quan Phan - EECS 4484 Group 8"
        date = "2026-03-10"
        reference = "https://blogs.vmware.com/security/2020/07/tau-threat-discovery-conti-ransomware.html"

    strings:
        // Conti identity markers
        $mutex = "_CONTI_" ascii wide
        $note = "CONTI_README.txt" ascii wide
        $ext = ".CONTI" ascii wide

        // Encryption and file traversal APIs
        $crypt1 = "CryptGenKey" ascii
        $crypt2 = "CryptAcquireContextA" ascii
        $file1 = "FindFirstFileW" ascii
        $file2 = "FindNextFileW" ascii
        $net = "NetShareEnum" ascii

        // Cleanup behavior
        $vss = "vssadmin delete shadows" ascii nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 2MB and
        $mutex and
        ($note or $ext) and
        2 of ($crypt1, $crypt2, $file1, $file2, $net) and
        $vss
}
