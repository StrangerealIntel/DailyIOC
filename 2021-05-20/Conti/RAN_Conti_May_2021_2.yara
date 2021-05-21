rule RAN_Conti_May_2021_2 {
   meta:
        description = "Detect unpacked Conti ransomware (May 2021)"
        author = "Arkbird_SOLG"
        reference = "Internal Research"
        date = "2021-05-20"
        hash1 = "Redacted"
        hash2 = "a5751a46768149c5ddf318fd75afc66b3db28a5b76254ee0d6ae27b21712e266"
        hash3 = "74b7a1da50ce44b640d84422bb3f99e2f338cc5d5be9ef5f1ad03c8e947296c3"
        tlp = "White"
        adversary = "RAAS"
   strings:      
        $seq1 = { 33 db 3c 2f 74 0a 3c 5c 74 06 3c 3a 8a c3 75 02 b0 01 2b cf 0f b6 c0 41 89 9d 68 fd ff ff f7 d8 89 9d 6c fd ff ff 56 1b c0 89 9d 70 fd ff ff 23 c1 89 9d 74 fd ff ff 89 85 88 fd ff ff 89 9d 78 fd ff ff 88 9d 7c fd ff ff e8 [4] 50 8d 85 68 fd ff ff 50 57 e8 68 fc ff ff 83 c4 0c 8d 8d ac fd ff ff f7 d8 1b c0 53 53 53 51 f7 d0 23 85 70 fd ff ff 53 50 ff 15 [4] 8b f0 83 fe ff 75 18 ff b5 a4 fd ff ff 53 53 57 e8 42 fe ff ff 83 c4 10 8b d8 e9 1c 01 00 00 8b 85 a4 fd ff ff 8b 48 04 2b 08 c1 f9 02 89 8d 84 fd ff ff 89 9d 8c fd ff ff 89 9d 90 fd ff ff 89 9d 94 fd ff ff 89 9d 98 fd ff ff 89 9d 9c fd ff ff 88 9d a0 fd ff ff e8 [4] 50 8d 85 ab fd ff ff 50 8d 85 8c fd ff ff 50 8d 85 d8 fd ff ff 50 e8 01 fb ff ff 83 c4 10 f7 d8 1b c0 f7 d0 23 85 94 fd ff ff 80 }
        $seq2 = { 38 9d a0 fd ff ff 74 0c ff b5 94 fd ff ff e8 [2] ff ff 59 8d 85 ac fd ff ff 50 56 ff 15 [4] 85 c0 0f 85 4d ff ff ff 8b 85 a4 fd ff ff 8b 8d 84 fd ff ff 8b 10 8b 40 04 2b c2 c1 f8 02 3b c8 74 34 68 [4] 2b c1 6a 04 50 8d 04 8a 50 e8 [2] 00 00 83 c4 10 eb 1c 38 9d a0 fd ff ff 74 12 ff b5 94 fd ff ff e8 [2] ff ff 8b 85 80 fd ff ff 59 8b d8 56 ff 15 [4] 80 bd 7c fd ff ff 00 5e 74 0c ff b5 70 fd ff ff e8 [2] ff ff 59 8b }
        $seq3 = { 6a 0c 68 [4] e8 [2] ff ff 33 f6 89 75 e4 8b 45 08 ff 30 e8 [2] ff ff 59 89 75 fc 8b 45 0c 8b 00 8b 38 8b d7 c1 fa 06 8b c7 83 e0 3f 6b c8 38 8b 04 95 [4] f6 44 08 28 01 74 21 57 e8 [2] ff ff 59 50 ff 15 [4] 85 c0 75 1d e8 [2] ff ff 8b f0 ff 15 [4] 89 06 e8 [2] ff ff c7 00 09 00 00 00 83 ce ff 89 75 e4 c7 45 fc fe ff ff ff e8 0d 00 00 00 8b c6 e8 [2] ff }
        $seq4 = { 8b ff 55 8b ec 56 6a 00 ff 75 10 ff 75 0c ff 75 08 ff 35 [4] ff 15 [4] 8b f0 85 f6 75 2d ff 15 [4] 83 f8 06 75 22 e8 b6 ff ff ff e8 73 ff ff ff 56 ff 75 10 ff 75 0c ff 75 08 ff 35 [4] ff 15 [4] 8b f0 8b c6 5e }
    condition:
         uint16(0) == 0x5a4d and filesize > 50KB and all of ($seq*) 
}
