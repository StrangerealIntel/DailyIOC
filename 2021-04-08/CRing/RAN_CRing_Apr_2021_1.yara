rule RAN_CRing_Apr_2021_1
{
    meta:
        description = "Detect CRing ransomware"
        author = "Arkbird_SOLG"
        date = "2021-04-08"
        reference = "Internal Research"
        hash1 = "274ef2fba8ba46187f9cf462a02de286ea23ec75d163af01088f6856944817eb"
        hash2 = "f7d270ca0f2b4d21830787431f881cd004b2eb102cc3048c6b4d69cb775511c8"
        level = "Experimental"
    strings:
    // code reuse
        $str1 = { 13 30 02 00 2e 00 00 00 07 00 00 11 72 c6 01 00 70 73 40 00 00 0a 0a 06 6f 41 00 00 0a 0b 12 01 1a 8c 21 00 00 01 fe 16 21 00 00 01 6f 42 00 00 0a 2c 06 06 6f 43 00 00 0a 2a }
        $str2 = { 1b 30 03 00 78 00 00 00 01 00 00 11 28 09 00 00 06 de 03 26 de 00 02 8e 69 17 2e 0b 72 01 00 00 70 28 1a 00 00 0a 2a 72 1b 00 00 70 02 16 9a 28 1b 00 00 0a 2c 4d 7e 02 00 00 04 6f 1c 00 00 0a 0a 2b 13 12 00 28 1d 00 00 0a 0b 07 28 02 00 00 06 de 03 26 de 00 12 00 28 1e 00 00 0a 2d e4 de 0e 12 00 fe 16 04 00 00 1b 6f 12 00 00 0a dc 72 21 00 00 70 28 1a 00 00 0a 28 0a 00 00 06 28 07 00 00 06 2a 01 28 00 00 00 00 00 00 07 07 00 03 13 00 00 01 00 00 3f 00 08 47 00 03 13 00 00 01 02 00 35 00 20 55 00 0e 00 00 00 00 }
        $str3 = { 1b 30 03 00 24 00 00 00 05 00 00 11 73 35 00 00 0a 0a 06 03 6f 36 00 00 0a 06 02 17 6f 37 00 00 0a 0b de 0a 06 2c 06 06 6f 12 00 00 0a dc 07 2a 01 10 00 00 02 00 06 00 12 18 00 0a 00 00 00 00 }
    condition:
        uint16(0) == 0x5a4d and filesize > 5KB and 2 of them
}
