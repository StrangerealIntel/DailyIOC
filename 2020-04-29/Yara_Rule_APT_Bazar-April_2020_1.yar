import "pe"

rule Backdoor_APT_Nazar_April_2020_1 {
   meta:
      description = "Detect strings used by APT Nazar"
      author = "Arkbird_SOLG"
      reference = "Internal research"
      date = "2020-04-29"
      hash1 = "2fe9b76496a9480273357b6d35c012809bfa3ae8976813a7f5f4959402e3fbb6"
   strings:
      $s1 = "101;0000;" fullword ascii // string used on ping sended
      $s2 = "hodll.dll" fullword ascii  // dll used for the hook
      $s3 = { 70 73 73 64 6B ?? ?? 2E 73 79 73 } // pssdkxx.sys PSSDK Driver Protocol vx.x 32bit from microOLAP Technologies LTD.
      $s4 = { 70 73 73 64 6B ?? ?? 2E 76 78 64 } // pssdkxx.vxd vxd profile
      $s5 = "##$$%%&&''(())**++,,--..//0123456789:;<=>?" fullword ascii // base characters
      $s6 = "SYSTEM\\CurrentControlSet\\Services\\VxD\\MSTCP" fullword ascii  // Microsoft TCP/IP stack settings
      $s7 = "removehook" fullword ascii // stop keylogger
      $s8 = "installhook" fullword ascii // start keylogger
      $s9 = "_crt_debugger_hook" fullword ascii // start hook for keylogger
      $s10 = "\\Files.txt" fullword ascii // List of files found
      $s11 = "\\report.txt" fullword ascii // Data of the keystrokes captured
      $s12 = "\\Programs.txt" fullword ascii // List of programs found
      $s13 = "\\Devices.txt" fullword ascii // List of devices found
      $s14 = "\\music.mp3" fullword ascii // name of audio file capture
      $s15 = "\\z.png" fullword ascii // name of screenshot file 
   condition:
     12 of them and filesize > 120KB 
}
