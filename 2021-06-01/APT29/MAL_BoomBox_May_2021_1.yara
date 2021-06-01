rule MAL_BoomBox_May_2021_1 {
   meta:
        description = "Detect BoomBox malware"
        author = "Arkbird_SOLG"
        reference = "Internal Research"
        date = "2021-05-28"
        hash1 = "0acb884f2f4cfa75b726cb8290b20328c8ddbcd49f95a1d761b7d131b95bafec"
        hash2 = "8199f309478e8ed3f03f75e7574a3e9bce09b4423bd7eb08bb5bff03af2b7c27"
        tlp = "White"
        adversary = "APT29"
   strings:      
        $s1 = { 13 30 06 00 90 01 00 00 07 00 00 11 1f 1a 28 53 00 00 0a 25 72 bc 05 00 70 28 1e 00 00 0a 0a 06 28 54 00 00 0a 2d 07 06 28 55 00 00 0a 26 72 ea 05 00 70 28 1e 00 00 0a 0b 07 28 54 00 00 0a 2d 22 07 28 55 00 00 0a 26 07 72 12 06 00 70 28 1e 00 00 0a 0b 07 28 54 00 00 0a 2d 07 07 28 55 00 00 0a 26 73 08 00 00 06 25 7e 08 00 00 04 72 1c 06 00 70 6f 06 00 00 06 0c 08 2c 46 08 8e 69 1f 11 59 8d 2b 00 00 01 13 04 08 1f 0a 11 04 16 11 04 8e 69 28 56 00 00 0a 73 05 00 00 06 11 04 7e 09 00 00 04 7e 0a 00 00 04 6f 03 00 00 06 13 05 06 72 3c 06 00 70 28 1e 00 00 0a 11 05 28 57 00 00 0a 06 72 3c 06 00 70 28 1e 00 00 0a 28 58 00 00 0a 2c 46 7e 59 00 00 0a 72 64 06 00 70 17 6f 5a 00 00 0a 13 06 11 06 72 c0 06 00 70 6f 5b 00 00 0a 2d 26 11 06 72 c0 06 00 70 72 e8 06 00 70 06 72 3c 06 00 70 28 1e 00 00 0a 72 12 07 00 70 28 5c 00 00 0a 6f 5d 00 00 0a 7e 08 00 00 04 72 38 07 00 70 6f 06 00 00 06 0d 09 2c 46 09 8e 69 1f 11 59 8d 2b 00 00 01 13 07 09 1f 0a 11 07 16 11 07 8e 69 28 56 00 00 0a 73 05 00 00 06 11 07 7e 09 00 00 04 7e 0a 00 00 04 6f 03 00 00 06 13 08 07 72 58 07 00 70 28 1e 00 00 0a 11 08 28 57 00 00 0a 06 72 3c 06 00 70 28 1e 00 00 0a 28 58 00 00 0a 2c 16 72 84 07 00 70 06 72 9e 07 00 70 28 1e 00 00 0a 28 5e 00 00 0a 26 2a }
        $s2 = { 13 30 05 00 11 01 00 00 05 00 00 11 02 7b 02 00 00 04 72 0b 03 00 70 28 1e 00 00 0a 28 30 00 00 0a 74 2d 00 00 01 25 20 c0 d4 01 00 6f 31 00 00 0a 25 72 86 01 00 70 6f 32 00 00 0a 25 72 98 01 00 70 6f 34 00 00 0a 25 6f 35 00 00 0a 72 71 02 00 70 72 8d 02 00 70 03 28 1e 00 00 0a 6f 36 00 00 0a 25 72 2b 03 00 70 6f 3f 00 00 0a 72 9d 02 00 70 04 72 5d 03 00 70 28 37 00 00 0a 0a 25 6f 35 00 00 0a 72 bb 02 00 70 06 6f 38 00 00 0a 25 6f 40 00 00 0a 05 16 05 8e 69 6f 2e 00 00 0a 6f 39 00 00 0a 74 1a 00 00 01 0b 07 6f 3a 00 00 0a 20 c8 00 00 00 33 64 07 6f 3e 00 00 0a 73 41 00 00 0a 6f 42 00 00 0a 0c 02 7b 06 00 00 04 08 6f 43 00 00 0a 6f 44 00 00 0a 17 6f 45 00 00 0a 6f 46 00 00 0a 72 02 04 00 70 28 47 00 00 0a 2c 29 02 7b 03 00 00 04 08 6f 43 00 00 0a 26 02 7b 04 00 00 04 08 6f 43 00 00 0a 26 02 7b 05 00 00 04 08 6f 43 00 00 0a 26 17 2a 16 2a 16 2a }
        $s3 = { 13 30 04 00 6d 01 00 00 0a 00 00 11 72 f2 07 00 70 28 54 00 00 0a 39 5d 01 00 00 72 [2] 00 70 72 f2 07 00 70 28 5e 00 00 0a 26 1f 1a 28 53 00 00 0a 72 ?? 08 00 70 28 1e 00 00 0a 28 58 00 00 0a 3a 32 01 00 00 1f 0a 8d 2b 00 00 01 25 d0 0c 00 00 04 28 67 00 00 0a 0a 1d 8d 2b 00 00 01 25 d0 0b 00 00 04 28 67 00 00 0a 0b 28 4b 00 00 0a 6f 4c 00 00 0a 28 0c 00 00 06 26 72 d5 00 00 70 28 49 00 00 0a 6f 4a 00 00 0a 28 0c 00 00 06 0c 73 0a 00 00 06 6f 09 00 00 06 0d 09 2c 56 28 68 00 00 0a 09 6f 61 00 00 0a 13 05 73 05 00 00 06 11 05 7e 09 00 00 04 7e 0a 00 00 04 6f 04 00 00 06 13 06 06 11 06 28 0d 00 00 06 13 07 11 07 07 28 0d 00 00 06 13 07 73 08 00 00 06 7e 08 00 00 04 72 ?? 08 00 70 08 28 10 00 00 0a 11 07 6f 07 00 00 06 26 28 0b 00 00 06 28 4b 00 00 0a 6f 4c 00 00 0a 13 04 11 04 72 d5 00 00 70 28 69 00 00 0a 2c 65 73 02 00 00 06 11 04 6f 01 00 00 06 13 08 11 08 2c 53 73 05 00 00 06 28 68 00 00 0a 11 08 6f 61 00 00 0a 7e 09 00 00 04 7e 0a 00 00 04 6f 04 00 00 06 13 09 06 11 09 28 0d 00 00 06 13 0a 11 0a 07 28 0d 00 00 06 13 0a 73 08 00 00 06 7e 08 00 00 04 72 ?? 08 00 70 08 28 10 00 00 0a 11 0a 6f 07 00 00 06 26 2a }
        $s4 = { 1b 30 05 00 b5 00 00 00 06 00 00 11 72 76 05 00 70 72 d5 00 00 70 28 49 00 00 0a 6f 4a 00 00 0a 28 10 00 00 0a 0a 72 84 05 00 70 28 4b 00 00 0a 6f 4c 00 00 0a 28 10 00 00 0a 0b 72 90 05 00 70 0c 28 4d 00 00 0a 28 49 00 00 0a 6f 4e 00 00 0a 13 04 16 13 05 2b 2a 11 04 11 05 9a 13 06 11 06 6f 4f 00 00 0a 18 33 13 08 11 06 6f 50 00 00 0a 72 98 05 00 70 28 37 00 00 0a 0c 11 05 17 58 13 05 11 05 11 04 8e 69 32 ce 28 51 00 00 0a 6f 52 00 00 0a 0d 72 9c 05 00 70 1a 8d 10 00 00 01 25 16 06 a2 25 17 07 a2 25 18 08 a2 25 19 09 a2 28 1d 00 00 0a 13 07 de 06 26 14 13 07 de 00 11 07 2a 00 00 00 01 10 00 00 00 00 00 00 ac ac 00 06 10 00 00 01 }
   condition:
        filesize > 6KB and 3 of ($s*)
}

