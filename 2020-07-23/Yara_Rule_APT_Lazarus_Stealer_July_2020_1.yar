import "pe"

rule APT_Lazarus_Stealer_Unpacked_July_2020_1 {
   meta:
      description = " Detected Lazarus stealer unpacked from Thermida - July 2020"
      author = "Arkbird_SOLG"
      reference = "https://twitter.com/DeadlyLynn/status/1286233135751995397"
      date = "2020-07-23"
      hash1 = "78e2cdd8234749e2199d15900779443a8332422a8ac08462a0a50e7816d877dc"
      hash2 = "ae1726cf17da5beaf1e5a4c68ffbb010d0ad6fb754e1168d9700ca7629211dd5"
   strings:
      $s1 = "C:\\Windows\\system32\\ntdll.dll" fullword ascii
      $s2 = "C:\\Windows\\System32\\rundll32.exe \"%s\", BZ2_bzZip %s 0 0 %s 1" fullword ascii
      $s3 = "C:\\Users\\admin1\\AppData\\Local\\Temp" fullword ascii
      $s4 = "%userappdata%\\RestartApp.exe" fullword ascii
      $s5 = "DOMAIN error\r\n" fullword wide
      $s6 = "Exit Status = %d" fullword ascii
      $s7 = "%s\\system32\\drivers\\oreans32.sys" fullword ascii /* Themida packer string reference */
      $s8 = "HARDWARE\\ACPI\\DSDT\\VBOX__" fullword ascii /* Anti-VM method of Virtualbox*/
      $s9 = "oreansx64.sys" fullword ascii /* Themida packer string reference */
      $s10 = "oreans32.sys" fullword ascii /* Themida packer string reference */
      $s11 = "#Tntdll.dll" fullword ascii
      $s12 = "C:\\Windows\\System32" fullword wide
      $s13 = "%s\\system32\\drivers\\%s" fullword ascii
      $s14 = ":USER32.8dl" fullword ascii
      $s15 = "ZLib.DLL" fullword wide /* Reference Zlib */
      $s16 = "????.lnk" fullword ascii /* lnk persistence reference */
      $s17 = "\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\" fullword wide
      $s18 = "(C) 1995-2017 Jean-loup Gailly & Mark Adler" fullword ascii /* Reference Copyright Zlib authors */
      $s19 = "DLL support by Alessandro Iacopetti & Gilles Vollant" fullword ascii /* Reference Copyright Zlib authors */
      $s20 = "Dn64.dll" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1500KB and pe.imphash() == "baa93d47220682c04d92f7797d9224ce" and pe.exports("BZ2_bzInit") and pe.exports("BZ2_bzZip") and pe.exports("BZ2_bzZipW") and pe.exports("adler32_z") and pe.exports("crc32_z") and pe.exports("deflateGetDictionary") and 15 of them
}

rule APT_Lazarus_Stealer_Packed_July_2020_1 {
   meta:
      description = "Detected Lazarus Strealer Packed by Thermida - July 2020"
      author = "Arkbird_SOLG"
      reference = "https://twitter.com/DeadlyLynn/status/1286233135751995397"
      date = "2020-07-23"
      hash1 = "431e6784ef33f2b3963464458e73915875947b11348533544cc16c53af64740f"
      hash2 = "70f45a7bbddda140695b953254650486733d8039c63e4eaeb454c1189a97989b"
   strings:
      $s1 = "fill_win32_filefunc64" fullword ascii /* Reference Zlib */
      $s2 = "gzfread" fullword ascii
      $s3 = "deflateGetDictionary" fullword ascii
      $s4 = "gzfwrite" fullword ascii
      $s5 = "adler32_z" fullword ascii
      $s6 = "@AJ<LxwBMDNCIFE}#SRV" fullword ascii
      $s7 = "uncompress2" fullword ascii
      $s8 = "zxyakauj" fullword ascii
      $s9 = "gzfwrite" fullword ascii
      $s10 = "tphfpzvy" fullword ascii
      $s11 = "Dn.dll" fullword ascii
      $s12 = ":USER32.8dl" fullword ascii
      $s13 = "zlib data compression and ZIP file I/O library" fullword wide /* Reference Zlib */
      $s14 = "Dn64.dll" fullword ascii
      $s15 = "zlibwapi.dll" fullword ascii /* Reference Zlib */
      $s16 = "CTRL+_" fullword ascii /* Themida packer string reference */
      $s17 = "ZLib.DLL" fullword ascii /* Reference Zlib */
      $s18 = "(C) 1995-2017 Jean-loup Gailly & Mark Adler-" fullword ascii /* Reference Copyright Zlib authors */
      $s19 = "zlib data compression and ZIP file I/O library" fullword ascii /* Reference Copyright Zlib authors */
      $s20 = "DLL support by Alessandro Iacopetti & Gilles Vollant" fullword ascii /* Reference Copyright Zlib authors */
   condition:
      uint16(0) == 0x5a4d and filesize < 550KB and pe.imphash() == "baa93d47220682c04d92f7797d9224ce" and pe.exports("BZ2_bzInit") and pe.exports("BZ2_bzZip") and pe.exports("BZ2_bzZipW") and pe.exports("adler32_z") and pe.exports("crc32_z") and pe.exports("deflateGetDictionary") and 15 of them}
