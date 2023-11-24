rule Mal_Loader_Sload_Sep-2020-1 {
   meta:
      description = "Detect SLoad loader"
      author = "Arkbird_SOLG"
      reference = "https://twitter.com/JAMESWT_MHT/status/1305480728684232704"
      date = "2020-09-14"
      modified = "2023-11-22"
      hash1 = "06e5575f67113906effb3cdb8ea2f021f3bc5fad8d278d80eb3da943dc743c2d"
      hash2 = "147e1d26153de7bd5033968d64104bb9df597d1913f237f4f5b172f06414b775"
      hash3 = "15a61df21dc514fc4e935bb1e267134265f2c70aa167f03389c4f1a5b5a750d9"
      hash4 = "1dba2064e7290c1896d560ff266a18cb6bd9b7e82aad50ddcbe2afde3e43c53e"
      hash5 = "28b811e737ec718f5c36cf05df89da00f48e4e088756e11564c15fe683702964"
      hash6 = "2cc33394a01bb3af0e48d0ccb71037c39f142fb22a7ed2ac40bc0860147da1a8"
      hash7 = "49904fa43dc24c2cbfe64c7089edc9805ce6ce93e4ff240663a6308ec5efe462"
      hash8 = "698cd771502d967e9921d2b0c2d3bb7787554f3b056c967991965270e9707e25"
      hash9 = "96bd66aedb565c6d29e60d7e7880047749abcd1cfa2d7b27f612b7b32038ede5"
      hash10 = "9b4dc4c27bbba4e9215b17cddfc80ee3581f76c8d8010ddee4c978fd2922c4f7"
      hash11 = "9f1d77dacee045731ee5ff9539060528ce01c5db3f7b99b4f7ac68687beab966"
      hash12 = "a1bfd39eb6057b5797ca04c30d5ca65641585e72ecdfdd8e0c1ac24d126b4056"
      hash13 = "d1064ee3b5c35e19a703373e2e6554ba598a0b9d647d9c4da08331fe5964cba6"
      hash14 = "f6cb2ffe73e87a5d0053ca599d203d3dbc187d65b434d4c7c649c51ba2689505"
   strings:
      $s1 = "([\\?\\?\\?\\?\\?\\?\\?\\?\\?])" fullword ascii
      $s2 = "CreateObject(\"Scripting.FileSystemObject\")" fullword ascii
      $s3 = "WScript.CreateObject (\"WScript.Shell\")" fullword ascii
      $s4 = "Array(" fullword ascii
      $s5 = ".Pattern" fullword ascii
      $s6 = ".Global = True" fullword ascii
      $s7 = "New RegExp" fullword ascii
      $s8 = ".[run]" fullword ascii
      $s9 = "fso.FolderExists(" fullword ascii
      $s10 = { [4-5] 3D [4-5] 66 }
   condition:
       filesize > 2KB and 7 of them
}
