rule Ran_Egregor_Oct_2020_1 {
 meta:
   description = "Detect Egregor / Maze ransomware by Maze blocks"
   author = "Arkbird_SOLG"
   reference = "Internal Research"
   date = "2020-10-29"
   hash1 = "14e547bebaa738b8605ba4182c4379317d121e268f846c0ed3da171375e65fe4"
   hash2 = "af538ab1b8bdfbf5b7f1548d72c0d042eb14d0011d796cab266f0671720abb4d"
   hash3 = "42ac07c5175d88d6528cfe3dceacd01834323f10c4af98b1a190d5af7a7bb1cb"
   hash4 = "4139c96d16875d1c3d12c27086775437b26d3c0ebdcdc258fb012d23b9ef8345"
strings:
  $x1 = { 45 f4 8b 4d 10 8b 09 0f b7 49 06 39 c8 0f 8d a2 00 00 00 8b 45 e4 83 78 10 00 75 48 8b 45 0c 8b 40 38 89 45 f0 83 7d f0 00 7e 37 31 c0 8b 4d ec 8b 55 e4 03 4a 0c 89 4d e8 8b 4d e8 8b 55 e4 89 4a 08 8b 4d f0 8b 55 e8 89 14 24 c7 44 24 04 00 00 00 00 89 4c 24 08 89 45 d4 e8 9e c6 ff ff 89 45 d0 eb 3a 8b 45 ec 8b 4d e4 03 41 0c 89 45 e8 8b 45 e4 8b 40 10 8b 4d 08 8b 55 e4 03 4a 14 8b 55 e8 89 14 24 89 4c 24 04 89 44 24 08 e8 77 a1 ff ff 8b 4d e8 8b 55 e4 89 4a 08 89 45 cc 8b 45 f4 83 c0 01 89 45 f4 8b 45 e4 83 c0 28 89 45 e4 }
  $x2 = { 8b 45 f0 83 38 00 0f 86 a0 00 00 00 8b 45 f8 8b 4d f0 03 01 89 45 ec 8b 45 f0 83 c0 08 89 45 e8 c7 45 fc 00 00 00 00 8b 45 fc 8b 4d f0 8b 49 04 83 e9 08 d1 e9 39 c8 73 62 8b 45 e8 0f b7 00 c1 e8 0c 89 45 e0 8b 45 e8 0f b7 00 25 ff 0f 00 00 89 45 dc 8b 45 e0 85 c0 89 45 d0 74 0f eb 00 8b 45 d0 83 e8 03 89 45 cc 74 04 eb 17 eb 17 8b 45 ec 03 45 dc 89 45 e4 8b 45 0c 8b 4d e4 03 01 89 01 eb 02 eb 00 eb 00 8b 45 fc 83 c0 01 89 45 fc 8b 45 e8 83 c0 02 89 45 e8 eb 8c 8b 45 f0 8b 4d f0 03 41 04 89 45 f0 }
  $x3 = { 8b 45 f0 8b 4d ec 03 01 89 45 e8 8b 45 e8 89 04 24 c7 44 24 04 14 00 00 00 ff 15 38 f0 0b 10 83 ec 08 31 c9 88 ca 83 f8 00 88 55 cf 75 0d 8b 45 e8 83 78 0c 00 0f 95 c1 88 4d cf 8a 45 cf a8 01 75 05 e9 6e 01 00 00 8b 45 f0 8b 4d e8 03 41 0c 89 04 24 ff 15 3c f0 0b 10 83 ec 04 89 45 dc 8b 45 dc b9 ff ff ff ff 39 c8 }
  $op1 = { 60 8b 7d 08 8b 4d 10 8b 45 0c f3 aa 61 89 45 f0 }
  $op2 = { 83 7d 08 00 89 45 ec 89 4d e8 89 55 e4 }
  $op3 = { 89 4d e8 89 55 e4 75 09 c7 45 f0 00 00 00 00 }
  $op4 = { 75 09 c7 45 f0 00 00 00 00 eb 17 60 }
condition: 
   uint16(0) == 0x5a4d and filesize > 350KB and (3 of ($op*) or 2 of ($x*)) 
}
