rule HijackLoader{
meta:
 description = "HijackLoader (Andorra Hotel campaign)"
 author = "@BorjaMerino (Alpine Security)"
 version = "1.0"
 date = "2023-09-18"
strings:
 $x1 = {4? 39 ?? 89 ?? 74 ?? 0F B6 ?? ?? 18 30 ?? ?? 4? 83 ?? ?? B? 00 00 00 00 74 ?? 89 ?? EB ??}
 $x2 = {64 8B ?? 30 00 00 00 8B ?? 0C 83 ?? 0C}
 $x3 = {90 90 0F B7 ?? 01 ?? 0F B7 ?? 83 C? 02 66 85 ?? 74 ??}
 $x4 = {39 ?? 74 14 8D ?? 01 8B ?? 24 0C 8B ?? 24 39 ?? ?? 01 89 ?? 75 EA}
 $x5 = {90 90 31 ?? ?? 83 C? 04 39 ?? 72 f6}

condition:
 uint16(0) == 0x5A4D
 and uint16(uint32(0x3C)+0x18) == 0x010B 
 and (pe.number_of_signatures > 0)
 and (filesize > 1MB and filesize < 5MB) 
 and 2 of ($x*)
}
