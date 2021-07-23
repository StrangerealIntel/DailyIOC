rule Exp_CVE_2021_36934_July_2021_1
{
    meta:
        description = "Detect CVE_2021_36934 exploit (HiveNightmare)"
        author = "Arkbird_SOLG"
        date = "2021-07-23"
        reference = "https://github.com/GossiTheDog/HiveNightmare"
        hash1 = "7baab69f86b50199456c9208624dd16aeb0d18d8a6f2010ee6501a183476f12f"
    strings:
        $s1 = "\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy" fullword wide
        $s2 = "Windows\\System32\\config\\SECURITY" fullword wide
        $s3 = "Windows\\System32\\config\\SYSTEM" fullword wide
        $s4 = "Windows\\System32\\config\\SAM" fullword wide
        $s5 = "SECURITY-" fullword wide
        $s6 = { 43 6f 75 6c 64 20 6e 6f 74 20 6f 70 65 6e 20 53 45 43 55 52 49 54 59 20 3a 28 20 49 73 20 53 79 73 74 65 6d 20 50 72 6f 74 65 63 74 69 6f 6e 20 6e 6f 74 20 65 6e 61 62 6c 65 64 20 6f 72 20 76 75 6c 6e 65 72 61 62 69 6c 69 74 79 20 66 69 78 65 64 3f 20 20 4e 6f 74 65 20 63 75 72 72 65 6e 74 6c 79 20 68 61 72 64 63 6f 64 65 64 20 74 6f 20 6c 6f 6f 6b 20 66 6f 72 20 66 69 72 73 74 20 34 20 56 53 53 20 73 6e 61 70 73 68 6f 74 73 20 6f 6e 6c 79 20 2d 20 6c 69 73 74 20 73 6e 61 70 73 68 6f 74 73 20 77 69 74 68 20 76 73 73 61 64 6d 69 6e 20 6c 69 73 74 20 73 68 61 64 6f 77 73 }
        $s7 = { 7a d1 3f 99 5c 2d 21 79 f2 21 3d 00 58 ac 30 7a b5 d1 3f 7e 84 ff 62 3e cf 3d 3d }
    condition:
       uint16(0) == 0x5A4D  and filesize > 50KB and 5 of ($s*) 
}  
