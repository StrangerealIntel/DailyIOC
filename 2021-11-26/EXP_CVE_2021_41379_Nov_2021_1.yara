rule EXP_CVE_2021_41379_Nov_2021_1
{
    meta:
        description = "Detect exploit tool using CVE-2021-41379"
        author = "Arkbird_SOLG"
        date = "2021-11-26"
        reference = "https://twitter.com/JAMESWT_MHT/status/1463414554004709384"
        hash1 = "5d97d3035b2ec1bd16016922899350693cae5f7a3be6cadbe0da34fbfd14b612"
        hash2 = "76fe99189fa84e28dd346b1105da77c4dfd3f7f16478b05bfca4c13a75d9fd07"
	hash3 = "9e4763ddb6ac4377217c382cf6e61221efca0b0254074a3746ee03d3d421dabd"
	hash4 = "a018545b334dc2a0e0c437789a339c608852fa1cedcc88be9713806b0855faea"
        tlp = "white"
        adversary = "-"
    strings:
      $s1 = { 7b 33 32 38 38 32 37 35 34 2d 32 43 44 37 2d 34 36 35 44 2d 39 45 35 37 2d 39 38 30 45 36 35 32 36 45 30 43 36 7d }
      $s2 = { 50 6a 01 50 68 03 00 08 00 68 ?? 75 40 00 ff 15 58 70 40 00 8b f0 83 fe ff 0f 84 [2] 00 00 6a 00 56 ff 15 88 70 40 00 8d 85 d4 fb ff ff c7 85 d4 fb ff ff 00 00 00 00 50 56 ff 15 70 70 40 00 8b 3d c0 70 40 00 56 ff d7 ff 15 78 70 40 00 50 6a 00 68 00 10 10 00 ff 15 60 70 40 00 8b f0 c7 85 dc fb ff ff 00 00 00 00 8d 85 dc fb ff ff 50 68 ff 01 0f 00 56 ff 15 0c 70 40 00 56 ff d7 8d 85 d0 fb ff ff c7 85 d0 fb ff ff 00 00 00 00 50 6a 01 6a 02 6a 00 68 ff 01 0f 00 ff b5 dc fb ff ff ff 15 28 70 40 00 ff b5 dc fb ff ff ff d7 6a 04 8d 85 d4 fb ff ff 50 6a 0c ff b5 d0 fb ff ff ff 15 08 70 40 00 6a 44 8d 85 78 fb ff ff 0f 57 c0 6a 00 50 0f 11 85 bc fb ff ff e8 ?? 24 00 00 83 c4 0c c7 85 78 fb ff ff 44 00 00 00 b8 05 00 00 00 c7 85 80 fb ff ff ?? 75 40 00 66 89 85 a8 fb ff ff 8d 85 e8 fd ff ff 68 04 01 00 00 50 68 ?? 75 40 00 ff 15 e8 70 40 00 8d 85 bc fb ff ff 50 8d 85 78 fb ff ff 50 6a 00 6a 00 6a 10 6a 00 6a 00 6a 00 6a 00 8d 85 e8 fd ff ff 50 ff b5 d0 fb ff ff ff 15 10 70 40 00 ff b5 d0 fb ff ff ff d7 ff b5 bc fb ff ff ff d7 ff b5 c0 fb ff ff ff d7 }
      $s3 = { 6a 00 68 80 00 00 04 6a 04 6a 00 6a 01 68 00 00 01 80 8d 85 e8 fd ff ff 50 ff 15 d8 70 40 00 8b 35 bc 70 40 00 a3 14 96 40 00 8d 85 d8 fb ff ff 50 6a 00 6a 00 68 [2] 40 00 6a 00 6a 00 c7 85 d8 fb ff ff 00 00 00 00 ff d6 8b f8 8b 85 dc fb ff ff 68 08 94 40 00 05 0c 02 00 00 68 04 01 00 00 50 ff 15 ?? 71 40 00 8b 85 dc fb ff ff 83 c4 0c 83 c0 04 c7 85 cc fb ff ff 08 94 40 00 89 85 d0 fb ff ff 8d 85 d4 fb ff ff c7 85 d4 fb ff ff 00 00 00 00 50 6a 00 8d 85 cc fb ff ff 50 68 [2] 40 00 6a 00 6a 00 ff d6 8b b5 dc fb ff ff 6a ff 50 89 06 ff 15 dc 70 40 00 6a ff 57 ff 15 dc 70 40 00 57 8b 3d c0 70 40 00 ff d7 ff 35 28 9a 40 00 ff d7 c7 45 fc 01 00 00 00 8b 06 85 c0 74 21 68 88 13 00 00 50 ff 15 dc 70 40 00 3d 02 01 00 00 75 0a 6a 01 ff 36 ff 15 c8 70 40 00 ff 36 ff d7 8d 46 04 50 ff 15 c4 70 40 00 83 ec 18 8d 8e 0c 02 00 00 8b d4 [3] 89 } 
      $s4 = { 55 8b ec 81 ec 04 08 00 00 a1 04 90 40 00 33 c5 89 45 fc 0f 10 05 ?? 73 40 00 53 8b 5d 08 8d 85 2c f8 ff ff 56 0f 11 85 fc f7 ff ff 57 0f 10 05 ?? 73 40 00 68 d0 07 00 00 6a 00 0f 11 85 0c f8 ff ff 50 0f 10 05 ?? 73 40 00 0f 11 85 1c f8 ff ff e8 [2] 00 00 8b 3b 8d 85 fc f7 ff ff 83 c4 0c b9 00 04 00 00 66 83 38 00 74 08 83 c0 02 83 e9 01 75 f2 ba 00 04 00 00 8b f1 8b c2 2b c1 f7 de 1b f6 23 f0 85 c9 74 3d 8d 8d fc f7 ff ff 8d 0c 71 2b d6 74 23 b8 fe ff ff 7f 2b f9 0f 1f 00 85 c0 74 15 0f b7 34 0f 66 85 f6 74 0c 66 89 31 48 83 c1 02 83 ea 01 75 e7 85 d2 8d 41 fe 0f 45 c1 33 c9 66 89 08 6a 00 6a 02 ff 15 ?? 72 40 00 8d 85 fc f7 ff ff 50 ff 73 04 ff 15 ?? 72 40 00 8b 4d fc 33 c0 5f 5e 33 cd 5b e8 [2] 00 00 8b e5 5d c2 04 00 }
      $s5 = { 50 ff d7 68 04 01 00 00 8d 85 e0 fb ff ff 50 6a 00 ff 15 38 70 40 00 50 ff 15 54 70 40 00 6a 00 e8 ?? ed ff ff 50 8d 85 e0 fb ff ff 50 ff 15 84 70 40 00 6a 00 ff 15 ?? 72 40 00 8d 85 d4 fb ff ff 50 68 ?? 76 40 00 6a 04 6a 00 68 ?? 76 40 00 ff 15 ?? 72 40 00 ff 15 ?? 72 40 00 8b 35 64 70 40 00 8b 3d d8 70 40 00  } 
    condition:
       uint16(0) == 0x5A4D and filesize > 100KB and 4 of ($s*) 
}  
