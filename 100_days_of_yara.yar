/*
Goals for #100DaysofYARA:
better understanding of bitwise operators
use math module beyond general entropy of a section / resource
position specific things beyond what PE module tells us
do some funky stuff with hashing
*/
import "pe"
import "hash"
import "math"
import "console"

rule SUSP_PE_Header_Oddity_More_Chars
{
  meta:
    description = "check for PE headers where the prevalence of 0x0 bytes are less than 50%. While this may be indicative of Win32/Win64 samples not having a This Program Cannot Be Run in DOS Mode string, it can also find potentially suspicious things lurking in the header"
    DaysofYARA_day = "64/100"
  condition:
    uint16be(0x0) == 0x4d5a and
    (math.percentage(0x0, 0x0, 0x40)) < 0.5
}

rule SUSP_Empty_Section
{
  meta:
    DaysofYARA_day = "63/100"
    description = "check across PE for evidence of multiple zero length sections"
  condition:
    for 2 section in pe.sections:  (section.raw_data_size == 0)
}

rule SUSP_Empty_Section_Logger
{
  meta:
    DaysofYARA_day = "63/100"
    description = "check across PE for evidence of multiple zero length sections"
  condition:
    for 2 section in pe.sections:  (section.raw_data_size == 0
      and console.log("empty section: ", section.name)
    )
}

rule SUSP_TINY_Section
{
  meta:
    DaysofYARA_day = "63/100"
    description = "check across PE for evidence of multiple zero length sections"
  condition:
    for any section in pe.sections:  (section.raw_data_size < 100 and section.raw_data_size != 0)
}

rule Reference_DOS_Path_Pipe
{
  meta:
    description = "Find reference to named pipes or blank DOS path strings "
    DaysofYARA_day = "62/100"
  strings:
    $pipe = "\\\\.\\pipe\\" nocase ascii wide
    $fullword = "\\\\.\\pipe\\" fullword ascii wide
  condition:
    $pipe and not $fullword

}

rule Reference_DOS_Path_Hd1
{
  meta:
    description = "Find reference to DOS Path \\.\\Hd1"
    DaysofYARA_day = "61/100"
  strings:
    $ = "\\\\.\\Hd1\\" nocase ascii wide
  condition:
    all of them
}

rule Reference_DOS_Path_Vd1
{
  meta:
    description = "Find reference to DOS Path \\.\\Vd1 as found in COmRAT"
    DaysofYARA_day = "61/100"
  strings:
    $ = "\\\\.\\Vd1" nocase ascii wide
  condition:
    all of them
}

private rule Reference_DOS_Path_PhysicalDrive
{
  meta:
    description = "Find reference to DOS Path to PhysicalDrive as found in lots of stuff"
    DaysofYARA_day = "61/100"
  strings:
    $ = "\\\\.\\PhysicalDrive" nocase ascii wide
  condition:
    all of them

}

private rule Reference_DOS_Path_NamedPipe
{
  meta:
    description = "Find reference to named pipes or blank DOS path strings "
    DaysofYARA_day = "61/100"
  strings:
    $pipe = "\\\\.\\pipe\\" nocase ascii wide
    $fullword = "\\\\.\\pipe\\" fullword ascii wide
    $blank = "\\\\.\\" fullword ascii wide
  condition:
    1 of them

}

private rule Reference_DOS_Path_winmgmts_root
{
  meta:
    description = "Find reference to DOS Path \\.\\root as found in FinFisher and In_ter_ception and Sidewider"
    DaysofYARA_day = "61/100"
  strings:
    $ = "\\\\.\\root" ascii wide
  condition:
    all of them
}

rule Reference_DOS_Path_LCD
{
  meta:
    description = "Find reference to DOS Path \\.\\LCD as found in xHunt"
    DaysofYARA_day = "61/100"
  strings:
    $ = "\\\\.\\LCD" ascii wide
  condition:
    all of them
}

rule Reference_DOS_Path_DISPLAY
{
  meta:
    description = "Find reference to DOS Path \\.\\DISPLAY"
    DaysofYARA_day = "61/100"
  strings:
    $ = "\\\\.\\DISPLAY" ascii wide
  condition:
    all of them
}

rule Reference_DOS_Path_Global
{
  meta:
    description = "Find reference to DOS Path \\.\\Global as found in DTrack and Carbon and HyperStack"
    DaysofYARA_day = "61/100"
  strings:
    $ = "\\\\.\\Global" ascii wide
  condition:
    all of them
}

rule Reference_DOS_Path_mailslot
{
  meta:
    description = "Find reference to DOS Path \\.\\mailslot as found in Ramsay"
    DaysofYARA_day = "61/100"
  strings:
    $ = "\\\\.\\mailslot" ascii wide
  condition:
    all of them
}

rule Reference_DOS_Path_RESS_DTDOS
{
  meta:
    description = "Find reference to DOS Path \\.\\RESS_DTDOS as found in likely SIG31 samples"
    DaysofYARA_day = "61/100"
  strings:
    $ = "\\\\.\\RESS_DTDOS" ascii wide
    $ = "\\\\.\\RESSDTDOS" ascii wide
  condition:
    any of them
}

rule Reference_DOS_Path_Netfilter
{
  meta:
    description = "Find reference to DOS Path \\.\\netfil as found in rootkit samples"
    DaysofYARA_day = "61/100"
  strings:
    $ = "\\\\.\\netfil" ascii wide
  condition:
    all of them
}

rule Reference_DOS_Path_WMIDataDevice
{
  meta:
    description = "Find reference to DOS Path \\.\\WMIDataDevice as found in a BlackGear sample"
    DaysofYARA_day = "61/100"
  strings:
    $ = "\\\\.\\WMIDataDevice" ascii wide
  condition:
    all of them
}


rule Reference_DOS_Path_EfiMon
{
  meta:
    description = "Find reference to DOS Path \\.\\EfiMon as found in an Exforel sample"
    DaysofYARA_day = "61/100"
  strings:
    $ = "\\\\.\\EfiMon" ascii wide
  condition:
    all of them
}

rule Reference_DOS_Path_Unknown
{
  meta:
    description = "Find reference to uncategorized DOS Paths"
    DaysofYARA_day = "61/100"
  strings:
    $DOSPATH = {5c 5c 2e 5c}
  condition:
	all of them
	and not Reference_DOS_Path_Hd1
	and not Reference_DOS_Path_PhysicalDrive
	and not Reference_DOS_Path_Pipe
	and not Reference_DOS_Path_winmgmts_root
	and not Reference_DOS_Path_LCD
	and not Reference_DOS_Path_DISPLAY
	and not Reference_DOS_Path_Drive
	and not Reference_DOS_Path_Vd1
	and not Reference_DOS_Path_mailslot
	and not Reference_DOS_Path_RESS_DTDOS
	and not Reference_DOS_Path_Netfilter
	and not Reference_DOS_Path_Global
	and not Reference_DOS_Path_WMIDataDevice
	and not Reference_DOS_Path_EfiMon

}


rule MetaData_RTF_Author_Template
{
  meta:
    description = "Template file for RTF meta data - just add your characters from exiftool and throw a curly bracket on the end!"
    DaysofYARA_day = "60/100"
  strings:
    $ = "\\info{\\author " ascii wide //add meta characters and end with } inside the quotes!
  condition:
    uint32be(0) == 0x7B5C7274 and uint8(4)== 0x66 and 1 of them
}

rule MetaData_RTF_Keywords_Template
{
  meta:
    description = "Template file for RTF meta data - just add your characters from exiftool and throw a curly bracket on the end!"
    DaysofYARA_day = "60/100"
  strings:
    $ = "{\\keywords " ascii wide //add meta characters and end with } inside the quotes!
  condition:
    uint32be(0) == 0x7B5C7274 and uint8(4)== 0x66 and 1 of them
}
rule MetaData_RTF_Comments_Template
{
  meta:
    description = "Template file for RTF meta data - just add your characters from exiftool and throw a curly bracket on the end!"
    DaysofYARA_day = "60/100"
  strings:
        $ = "{\\doccomm " ascii wide //add meta characters and end with } inside the quotes!
  condition:
    uint32be(0) == 0x7B5C7274 and uint8(4)== 0x66 and 1 of them
}
rule MetaData_RTF_LastModified_Template
{
  meta:
    description = "Template file for RTF meta data - just add your characters from exiftool and throw a curly bracket on the end!"
    DaysofYARA_day = "60/100"
  strings:
    $ = "{\\operator " ascii wide //add meta characters and end with } inside the quotes!
  condition:
    uint32be(0) == 0x7B5C7274 and uint8(4)== 0x66 and 1 of them
}

rule MetaData_RTF_LastModified_test_xpcn
{
  meta:
    description = "check for test_xpcn in the last modified field of RTF"
    DaysofYARA_day = "60/100"
    hash = "322bb640d1326b7048174e5cb9cbbcf12cf676dc942e08221556df592287bac4"
    hash = "4f6b8f51fdaf708bb4fa0dbbc72da50d24f694bce2996eff3df7eeb3c1592e62"
  strings:
    $ = "{\\operator test_xpcn}" ascii wide 
  condition:
    uint32be(0) == 0x7B5C7274 and uint8(4)== 0x66 and 1 of them
}

rule SUSP_Scripting_in_Doc_MetaData_PowerShell
{
  meta:
    description = "Check for any case of powershell that starts a Word Doc metadata field"
    DaysofYARA_day = "59/100"
    reference = "https://www.varonis.com/blog/detecting-malware-payloads-in-office-document-metadata"
    hash = "494d681a0a9ac6da891efa26b5e523084ce36a97c9aeefc882be598e35b4ed62"
  strings:
    $ = {1E 00 00 00 ?? ?? 00 00 (50|70) (4f|6f) (57|77) (45|65) (52|72) (53|73) (48|68) (45|65) (4c|6c) (4c|6c) }
  condition:
    uint16be(0) == 0xD0CF and
    filesize < 5MB and
    1 of them
}

rule SUSP_Scripting_in_Doc_MetaData_MSHTA
{
  meta:
    description = "Check for any case of mshta that starts a Word Doc metadata field"
    DaysofYARA_day = "59/100"
    reference = "https://www.varonis.com/blog/detecting-malware-payloads-in-office-document-metadata"
  strings:
    $ = {1E 00 00 00 ?? ?? 00 00 (6d|4d) (73|53) (68|48) (74|54) (61|41) }
  condition:
    uint16be(0) == 0xD0CF and
    filesize < 5MB and
    1 of them
}

rule SUSP_Scripting_in_Doc_MetaData_WScript
{
  meta:
    description = "Check for any case of WScript that starts a Word Doc metadata field"
    DaysofYARA_day = "59/100"
    reference = "https://www.varonis.com/blog/detecting-malware-payloads-in-office-document-metadata"
  strings:
    $ = {1E 00 00 00 ?? 00 00 00 (77|57) (73|53) (63|43) (72|52) (69|49) (70|50) (74|54)}// looking for wscript in metadata fields
  condition:
    uint16be(0) == 0xD0CF and
    filesize < 5MB and
    1 of them
}

rule PE_Feature_DLL_BIOS
{
  meta:
    description = "check for the term BIOS left in the DLL Name"
    DaysofYARA_day = "58/100"
  condition:
    pe.dll_name icontains "BIOS"
}

rule PE_Feature_OriginalFileName_BIOS
{
  meta:
    description = "check for the term BIOS left in the OriginalFileName"
    DaysofYARA_day = "58/100"
  condition:
    pe.version_info["OriginalFilename"] icontains "BIOS"
}
rule PE_Feature_PBD_BIOS
{
  meta:
    description = "check for the term BIOS left in the PDB path"
    DaysofYARA_day = "58/100"
  condition:
    pe.pdb_path icontains "BIOS"
}

rule PE_Feature_DLL_UEFI
{
  meta:
    description = "check for the term UEFI left in the DLL Name"
    DaysofYARA_day = "58/100"
  condition:
    pe.dll_name icontains "UEFI"
}

rule PE_Feature_OriginalFileName_UEFI
{
  meta:
    description = "check for the term UEFI left in the OriginalFileName"
    DaysofYARA_day = "58/100"
  condition:
    pe.version_info["OriginalFilename"] icontains "UEFI"
}
rule PE_Feature_PBD_UEFI
{
  meta:
    description = "check for the term UEFI left in the PDB path"
    DaysofYARA_day = "58/100"
  condition:
    pe.pdb_path icontains "UEFI"
}

rule PE_Feature_DLL_NTFS
{
  meta:
    description = "check for the term NTFS left in the DLL Name"
    DaysofYARA_day = "58/100"
  condition:
    pe.dll_name icontains "NTFS"
}

rule PE_Feature_OriginalFileName_NTFS
{
  meta:
    description = "check for the term NTFS left in the OriginalFileName"
    DaysofYARA_day = "58/100"
  condition:
    pe.version_info["OriginalFilename"] icontains "NTFS"
}
rule PE_Feature_PBD_NTFS
{
  meta:
    description = "check for the term NTFS left in the PDB path"
    DaysofYARA_day = "58/100"
  condition:
    pe.pdb_path icontains "NTFS"
}

rule PE_Feature_DLL_Boot
{
  meta:
    description = "check for the term Boot left in the DLL Name"
    DaysofYARA_day = "57/100"
  condition:
    pe.dll_name icontains "Boot"
}

rule PE_Feature_OriginalFileName_Boot
{
  meta:
    description = "check for the term Boot left in the OriginalFileName"
    DaysofYARA_day = "57/100"
  condition:
    pe.version_info["OriginalFilename"] icontains "Boot"
}
rule PE_Feature_PBD_Boot
{
  meta:
    description = "check for the term Boot left in the PDB path"
    DaysofYARA_day = "57/100"
  condition:
    pe.pdb_path icontains "Boot"
}


rule SUSP_HTTP_HexEncoded
{
  meta:
    description = "check for HTTP strings encoded as hex"
    DaysofYARA_day = "56/100"
  strings:
    $http_hex_enc_str = "68747470" nocase ascii wide
    $HTTP_caps_hex_enc_str = "48545450" nocase ascii wide
    $http_colon_hex_enc_str = "687474703a2f2f" nocase ascii wide
    $https_hex_enc_str = "48747470733a2f2f" nocase ascii wide
  condition:
    any of them
}

rule SUSP_HTTP_Reverse
{
  meta:
    description = "check for HTTP strings encoded as hex"
    DaysofYARA_day = "56/100"
  strings:
    $ = "//:ptth" ascii wide nocase
    $ = "//:sptth" ascii wide nocase
    $ = "ptth" ascii wide nocase
    $ = "sptth" ascii wide nocase
  condition:
    any of them
}

rule MetaData_Doc_Name_James {
  meta: 
    DaysofYARA_day = "55/100"
  strings: 
    $ = {1E000000??000000 4a 61 6d 65 73 00 00 00 1E 00}
  condition: 
    uint16be(0) == 0xD0CF and 
    1 of them 
}
rule MetaData_Doc_Name_Robert {
  meta: 
    DaysofYARA_day = "55/100"
  strings: 
    $ = {1E000000??000000 52 6f 62 65 72 74 00 00 1E 00}
  condition: 
    uint16be(0) == 0xD0CF and 
    1 of them 
}

rule MetaData_Doc_Name_John_WIDE {
  meta: 
    DaysofYARA_day = "55/100"
  strings: 
    $ = {1E000000??000000 4a 00 6f 00 68 00 6e}
  condition: 
    uint16be(0) == 0xD0CF and 
    1 of them 
}
rule MetaData_Doc_Name_Michael {
  meta: 
    DaysofYARA_day = "55/100"
  strings: 
    $ = {1E000000??000000 4d 69 63 68 61 65 6c 00 1E 00}
  condition: 
    uint16be(0) == 0xD0CF and 
    1 of them 
}
rule MetaData_Doc_Name_William {
  meta: 
    DaysofYARA_day = "55/100"
  strings: 
  $ = {1E000000??000000 57 69 6c 6c 69 61 6d 00 1E 00}
  condition: 
    uint16be(0) == 0xD0CF and 
    1 of them 
}
rule MetaData_Doc_Name_David {
  meta: 
    DaysofYARA_day = "55/100"
  strings: 
    $ = {1E000000??000000 44 61 76 69 64 00 00 00 1E 00}
  condition: 
    uint16be(0) == 0xD0CF and 
    1 of them 
}
rule MetaData_Doc_Name_Richard {
  meta: 
    DaysofYARA_day = "55/100"
  strings: 
    $ = {1E000000??000000 52 69 63 68 61 72 64 00 1E 00}
  condition: 
    uint16be(0) == 0xD0CF and 
    1 of them 
}
rule MetaData_Doc_Name_Joseph {
  meta: 
    DaysofYARA_day = "55/100"
  strings: 
    $ = {1E000000??000000 4a 6f 73 65 70 68 00 00 1E 00}
  condition: 
    uint16be(0) == 0xD0CF and 
    1 of them 
}
rule MetaData_Doc_Name_Thomas {
  meta: 
    DaysofYARA_day = "55/100"
  strings: 
    $ = {1E000000??000000 54 68 6f 6d 61 73 00 00 1E 00}
  condition: 
    uint16be(0) == 0xD0CF and 
    1 of them 
}
rule MetaData_Doc_Name_Charles {
  meta: 
    DaysofYARA_day = "55/100"
  strings: 
    $ = {1E000000??000000 43 68 61 72 6c 65 73 001E00}
  condition: 
    uint16be(0) == 0xD0CF and 
    1 of them 
}


rule MetaData_Doc_Meta_Padding
{
  meta:
    description = "Check for a evidence of blank space padding in metadata of lure documents"
    DaysofYARA_day = "54/100"
  strings:
    $admin = {1E 00 00 00 [0-2] 00 00 20 20 20 20 20 20 20 20 20 20 20 20 20 20 }
  condition:
    uint16be(0) == 0xD0CF and
    1 of them

}

rule MetaData_Doc_Artifact_Adminstrator
{
  meta:
    description = "Check for the term Administrator as part of meta data artifacts"
    DaysofYARA_day = "53/100"
  strings:
    $admin = {1E 00 00 00 ?? 00 00 00 (41|61) 64 6D 69 6E 69 73 74 72 61 74 6F 72 }
  condition:
    uint16be(0) == 0xD0CF and
    1 of them

}

rule MetaData_Doc_Author_x
{
  meta:
    description = "Use metadata markers to detect a single character author field in meta data"
    disclaimer = "this is imperfect and will false positive! "
    DaysofYARA_day = "52/100"
  strings:
    $x_byte_marker = {1E 00 00 00 ?? 00 00 00 78 00 00 00 1E }
  condition:
    uint16be(0) == 0xD0CF and 1 of them
}

rule MetaData_Doc_Author_z
{
  meta:
    description = "Use metadata markers to detect a single character author field in meta data"
    disclaimer = "this is imperfect and will false positive! "
    DaysofYARA_day = "52/100"
  strings:
    $x_byte_marker = {1E 00 00 00 ?? 00 00 00 7a 00 00 00 1E }
  condition:
    uint16be(0) == 0xD0CF and 1 of them
}


rule MetaData_Doc_Artifact_CommandoVM
{
  meta:
    description = "Check for the term CommandoVM, a common red teaming VM, as part of meta data artifacts"
    DaysofYARA_day = "51/100"
  strings:
    $byte_marker = {1E 00 00 00 ?? 00 00 00 43 6F 6D 6D 61 6E 64 6F 56 4D 00 00 1E 00 00 00 }
  condition:
    uint16be(0) == 0xD0CF and 1 of them
}


rule SUSP_ReconCommands_HexEncode
{
  meta:
    description = "check for various recon commands as a hex-encoded string"
    DaysofYARA_day = "50/100"
  strings:
    $tracert_hex_enc_str = "74726163657274" nocase
    $tasklist_hex_enc_str = "7461736b6c697374" nocase
    $systeminfo_hex_enc_str = "73797374656d696e666f" nocase
    $ipconfig_hex_enc_str = "6970636f6e666967" nocase
    $netstat_hex_enc_str = "6e657473746174" nocase
    $nbtstat_hex_enc_str = "6e627473746174" nocase
    $route_hex_enc_str = "726f757465" nocase
    $netsh_hex_enc_str = "6e65747368" nocase
  condition:
    any of them
}


rule SUSP_Powershell_HexEncode
{
  meta:
    description = "check for powershell as a hex-encoded string"
    DaysofYARA_day = "49/100"
  strings:
    $powershell_hex_enc_str = "706f7765727368656c6c" nocase ascii wide
    $Powershell_hex_enc_str = "506f7765727368656c6c" nocase ascii wide
    $POWERSHELL_hex_enc_str = "504f5745525348454c4c" nocase ascii wide
  condition:
    any of them
}


rule SUSP_PE_File_Hex_Encoded
{
  meta:
    description = "Check for the bytes typically associated with a PE header, but as strings to detect hex encoding"
    DaysofYARA_day = "48/100"
    tool_used = "https://github.com/stairwell-inc/threat-research/pull/7"
  strings:
    $ThisProgramCannotBeRuninDOSMode_hexencode = "546869732050726f6772616d2043616e6e6f742042652052756e20696e20444f53204d6f6465"  ascii wide nocase
    $Program_hexencode = "50726f6772616d" nocase ascii wide
    $program_hexencode = "70726f6772616d" nocase ascii wide
    $MZ_HEader_hexencode = "4D5A90000300" nocase ascii wide
  condition:
    any of them
}

rule SUSP_ScriptTerms_String_Mutations_StackPush
{
  meta:
    description = " detect a mutation of CScript, WScript, or CreateObject"
    DaysofYARA_day = "47/100"
    tool_used = "https://github.com/stairwell-inc/threat-research/tree/main/cerebro-string-mutations"
  strings:
    $WScript_stackpush = "hipthWScr" nocase ascii wide
    $CreateObject_stackpush = "hjecthteObhCrea" nocase ascii wide
    $CScript_stackpush = "hipthCScr" nocase ascii wide
  condition:
    1 of them
}

rule SUSP_ScriptTerms_String_Mutations_Reverse
{
  meta:
    description = " detect a mutation of CScript, WScript, or CreateObject"
    DaysofYARA_day = "47/100"
    tool_used = "https://github.com/stairwell-inc/threat-research/tree/main/cerebro-string-mutations"
  strings:
    $WScript_reverse = "tpircSW" nocase ascii wide
    $CreateObject_reverse = "tcejbOetaerC" nocase ascii wide
    $CScript_reverse = "tpircSC" nocase ascii wide
  condition:
    1 of them
}

rule SUSP_ScriptTerms_String_Mutations_FlipFlop
{
  meta:
    description = " detect a mutation of CScript, WScript, or CreateObject"
    DaysofYARA_day = "47/100"
    tool_used = "https://github.com/stairwell-inc/threat-research/tree/main/cerebro-string-mutations"
  strings:
    $WScript_flipflop = "SWrcpit" nocase ascii wide
    $CreateObject_flipflop = "rCaeetbOejtc" nocase ascii wide
    $CScript_flipflop = "SCrcpit" nocase ascii wide
  condition:
    1 of them
}

rule SUSP_ScriptTerms_Obfuscation_Base64
{
  meta:
    description = " detect obfuscation of CScript, WScript, or CreateObject"
    DaysofYARA_day = "47/100"
  strings:
    $WScript = "WScript" base64 base64wide
    $CreateObject = "CreateObject" base64 base64wide
    $CScript = "CScript" base64 base64wide
  condition:
    1 of them
}


rule SUSP_ScriptTerms_Obfuscation_XOR
{
  meta:
    description = " detect obfuscation of CScript, WScript, or CreateObject"
    DaysofYARA_day = "47/100"
  strings:
    $WScript = "WScript" xor(0x01-0xff)
    $CreateObject = "CreateObject" xor(0x01-0xff)
    $CScript = "CScript" xor(0x01-0xff)
  condition:
    1 of them
}

rule SUSP_ScriptTerms_Obfuscation_HexEncoded
{
  meta:
    description = "check for script-related strings encoded as hex"
    DaysofYARA_day = "47/100"
    tool_used = "https://github.com/stairwell-inc/threat-research/tree/main/cerebro-string-mutations"
  strings:
    $wscript_hex_enc_str = "77736372697074" nocase
    $cscript_hex_enc_str = "63736372697074" nocase
    $WScript_camel_hex_enc_str = "57536372697074" nocase
    $CScript_camel_hex_enc_str = "43536372697074" nocase
    $WSCRIPT_caps_hex_enc_str = "57534352495054" nocase
    $CSCRIPT_caps_hex_enc_str = "43534352495054" nocase
    $CreateObject_hex_enc_str = "4372656174654f626a656374" nocase
  condition:
    any of them
}

rule SUSP_ScriptTerms_stackstring_WScript
{
  meta:
    description = "detect WScript being referenced via stack strings"
    DaysofYARA_day = "47/100"
  strings:
    $smallStack = {c645??57 c645??53 c645??63 c645??72 c645??69 c645??70 c645??74}
    $largeStack = {c7(45|85)[1-4]57000000 c7(45|85)[1-4]53000000 c7(45|85)[1-4]63000000 c7(45|85)[1-4]72000000 c7(45|85)[1-4]69000000 c7(45|85)[1-4]70000000 c7(45|85)[1-4]74000000}
    $register = {b?57000000 6689???? b?53000000 6689???? b?63000000 6689???? b?72000000 6689???? b?69000000 6689???? b?70000000 6689???? b?74000000 6689????}
    $dword = {c7(45|85)[1-4]72635357 [0-1]c7(45|85)[1-4]7069 [0-1]c6(45|85)[1-4]74}
    $pushpop = {6a575? 6a53 6689????5? 6a63 6689????5? 6a72 6689????5? 6a69 6689????5? 6a70 6689????5?}
    $callOverString = {e807000000575363726970745? }
  condition:
    any of them
}

rule SUSP_ScriptTerms_stackstring_CScript
{
  meta:
    description = "detect CScript being referenced via stack strings"
    DaysofYARA_day = "46/100"
  strings:
    $smallStack = {c645??43 c645??53 c645??63 c645??72 c645??69 c645??70 c645??74}
    $largeStack = {c7(45|85)[1-4]43000000 c7(45|85)[1-4]53000000 c7(45|85)[1-4]63000000 c7(45|85)[1-4]72000000 c7(45|85)[1-4]69000000 c7(45|85)[1-4]70000000 c7(45|85)[1-4]74000000}
    $register = {b?43000000 6689???? b?53000000 6689???? b?63000000 6689???? b?72000000 6689???? b?69000000 6689???? b?70000000 6689???? b?74000000 6689????}
    $dword = {c7(45|85)[1-4]72635343 [0-1]c7(45|85)[1-4]7069 [0-1]c6(45|85)[1-4]74}
    $pushpop = {6a435? 6a53 6689????5? 6a63 6689????5? 6a72 6689????5? 6a69 6689????5? 6a70 6689????5?}
    $callOverString = {e807000000435363726970745? }

  condition:
    any of them
}

rule SUSP_ScriptTerms_stackstring_CreateObject
{
  meta:
    description = "detect CreatObject being referenced via stack strings"
    DaysofYARA_day = "46/100"
    tool_used = "https://gist.github.com/notareverser/4f6b9c644d4fe517889b3fbb0b4271ca"
  strings:
    $smallStack = {c645??43 c645??72 c645??65 c645??61 c645??74 c645??65 c645??4f c645??62 c645??6a c645??65 c645??63 c645??74}
    $largeStack = {c7(45|85)[1-4]43000000 c7(45|85)[1-4]72000000 c7(45|85)[1-4]65000000 c7(45|85)[1-4]61000000 c7(45|85)[1-4]74000000 c7(45|85)[1-4]65000000 c7(45|85)[1-4]4f000000 c7(45|85)[1-4]62000000 c7(45|85)[1-4]6a000000 c7(45|85)[1-4]65000000 c7(45|85)[1-4]63000000 c7(45|85)[1-4]74000000}
    $register = {b?43000000 6689???? b?72000000 6689???? b?65000000 6689???? b?61000000 6689???? b?74000000 6689???? b?65000000 6689???? b?4f000000 6689???? b?62000000 6689???? b?6a000000 6689???? b?65000000 6689???? b?63000000 6689???? b?74000000 6689????}
    $dword = {c7(45|85)[1-4]61657243 c7(45|85)[1-4]624f6574 c7(45|85)[1-4]7463656a}
    $pushpop = {6a435? 6a72 6689????5? 6a65 6689????5? 6a61 6689????5? 6a74 6689????5? 6a65 6689????5? 6a4f 6689????5? 6a62 6689????5? 6a6a 6689????5? 6a65 6689????5? 6a63 6689????5?}
    $callOverString = {e80c0000004372656174654f626a6563745? }
  condition:
    any of them
}


rule SUSP_Schtasks_Clear
{
  meta:
    description = "detect a plaintext scheduled task string"
    DaysofYARA_day = "46/100"
  strings:
    $schtasks = "schtasks" nocase ascii wide
  condition:
    1 of them
}

rule SUSP_Schtasks_Base64
{
  meta:
    description = "detect a modified scheduled task string"
    DaysofYARA_day = "46/100"
  strings:
    $schtasks = "schtasks" base64 base64wide
  condition:
    1 of them
}


rule SUSP_Schtasks_XOR
{
  meta:
    description = "detect a modified scheduled task string"
    DaysofYARA_day = "46/100"
  strings:
    $schtasks = "schtasks" xor(0x01-0xff)
  condition:
    1 of them
}

rule SUSP_Schtasks_String_Mutations_Reverse
{
  meta:
    description = "detect a modified scheduled task string"
    DaysofYARA_day = "46/100"
    tool_used = "https://github.com/stairwell-inc/threat-research/tree/main/cerebro-string-mutations"
  strings:
    $schtasks_reverse = "sksathcs" nocase ascii wide
  condition:
    1 of them
}

rule SUSP_Schtasks_String_Mutations_FlipFlop
{
  meta:
    description = "detect a modified scheduled task string"
    DaysofYARA_day = "46/100"
    tool_used = "https://github.com/stairwell-inc/threat-research/tree/main/cerebro-string-mutations"
  strings:
    $schtasks_flipflop = "csthsask" nocase ascii wide
  condition:
    1 of them
}

rule SUSP_Schtasks_String_Mutations_StackPush
{
  meta:
    description = "detect a modified scheduled task string"
    DaysofYARA_day = "46/100"
    tool_used = "https://github.com/stairwell-inc/threat-research/tree/main/cerebro-string-mutations"
  strings:
    $schtasks_stackpush = "haskshscht" nocase ascii wide
  condition:
    1 of them
}

rule SUSP_Schtasks_String_Mutations_StackStrings
{
  meta:
    description = "detect a modified scheduled task string"
    DaysofYARA_day = "46/100"
    tool_used = "https://gist.github.com/notareverser/4f6b9c644d4fe517889b3fbb0b4271ca"
  strings:
    $smallStack = {c645??73 c645??63 c645??68 c645??74 c645??61 c645??73 c645??6b c645??73}
    $largeStack = {c7(45|85)[1-4]73000000 c7(45|85)[1-4]63000000 c7(45|85)[1-4]68000000 c7(45|85)[1-4]74000000 c7(45|85)[1-4]61000000 c7(45|85)[1-4]73000000 c7(45|85)[1-4]6b000000 c7(45|85)[1-4]73000000}
    $register = {b?73000000 6689???? b?63000000 6689???? b?68000000 6689???? b?74000000 6689???? b?61000000 6689???? b?73000000 6689???? b?6b000000 6689???? b?73000000 6689????}
    $dword = {c7(45|85)[1-4]74686373 c7(45|85)[1-4]736b7361}
    $pushpop = {6a735? 6a63 6689????5? 6a68 6689????5? 6a74 6689????5? 6a61 6689????5? 6a73 6689????5? 6a6b 6689????5?}
    $callOverString = {e8080000007363687461736b735? }
  condition:
    any of them
}

rule MAL_WinDealer_PayloadDecode
{
  meta:
    description = "Detect Steganography technique used by WinDealer to embed & XOR decrypt in an BITMAP resource"
    DaysofYARA_day = "45/100"
    hash = "28df5c75a2f78120ff96d4a72a3c23cee97c9b46c96410cf591af38cb4aed0fa"
    hash = "4a9b37ca2f90bfa90b0b8db8cc80fe01d154ba88e3bc25b00a7f8ff6c509a76f"
    hash = "b9f526eea625eec1ddab25a0fc9bd847f37c9189750499c446471b7a52204d5a"
    reference = "https://jsac.jpcert.or.jp/archive/2022/pdf/JSAC2022_7_leon-niwa-ishimaru_en.pdf"
  condition:
    uint16(0) == 0x5a4d and filesize < 500KB and
    for any resource in pe.resources:(
      resource.id == 129 and
      for 1 i in (resource.offset + 0x1000 .. resource.offset + 0x1200) :
        (
        (uint32be(i) == 0x00600300 or uint32be(i) == 0x00700300) and
        (uint16be(i+4) ^ uint16be(i+14)) == 0x4d5a
        )
    )
}

rule SUSP_SvcHost_Start
{
  meta:
    description = "Check for the launching of the generic Svchost to run the a task under the 'normal' netsvcs group in the svchost registry key"
    reference = "https://nasbench.medium.com/a-deep-dive-into-windows-scheduled-tasks-and-the-processes-running-them-218d1eed4cce"
    DaysofYARA_day = "44/100"
  strings:
    $ = "svchost.exe -k netsvcs" ascii wide nocase
  condition:
    all of them
}

rule SUSP_SvcHost_Start_b64
{
  meta:
    description = "Check for the launching of the generic Svchost to run the a task under the 'normal' netsvcs group in the svchost registry key"
    reference = "https://nasbench.medium.com/a-deep-dive-into-windows-scheduled-tasks-and-the-processes-running-them-218d1eed4cce"
    DaysofYARA_day = "44/100"
  strings:
    $ = "svchost.exe -k netsvcs" base64 base64wide
  condition:
    all of them
}

rule SUSP_SvcHost_Start_xor
{
  meta:
    description = "Check for the launching of the generic Svchost to run the a task under the 'normal' netsvcs group in the svchost registry key"
    reference = "https://nasbench.medium.com/a-deep-dive-into-windows-scheduled-tasks-and-the-processes-running-them-218d1eed4cce"
    DaysofYARA_day = "44/100"
  strings:
    $ = "svchost.exe -k netsvcs" xor(0x01-0xff)
  condition:
    all of them
}

rule SUSP_SvcHost_String_Mutations
{
  meta:
    description = "Check for the launching of the generic Svchost to run the a task under the 'normal' netsvcs group in the svchost registry key"
    reference = "https://nasbench.medium.com/a-deep-dive-into-windows-scheduled-tasks-and-the-processes-running-them-218d1eed4cce"
    tool = "https://github.com/stairwell-inc/threat-research/tree/main/cerebro-string-mutations"
    DaysofYARA_day = "44/100"
  strings:
    $svchostexe_reverse = "exe.tsohcvs" nocase ascii wide
    $svchostexeknetsvcs_reverse = "scvsten k- exe.tsohcvs" nocase ascii wide

    $svchostexe_stackpush = "hexehost.hsvch" nocase ascii wide
    $svchostexeknetsvcs_stackpush = "hcshetsvh-k nhexe host.hsvch" nocase ascii wide

    $svchostexe_flipflop = "vshcso.txee" nocase ascii wide
    $svchostexeknetsvcs_flipflop = "vshcso.txe ek-n tevssc" nocase ascii wide
  condition:
    1 of them
}

rule SUSP_stackstring_svchost
{
  meta:
    reference = "https://gist.github.com/notareverser/4f6b9c644d4fe517889b3fbb0b4271ca"
    description = "Check for the reference of svchost via stack strings"
    reference = "https://nasbench.medium.com/a-deep-dive-into-windows-scheduled-tasks-and-the-processes-running-them-218d1eed4cce"
    DaysofYARA_day = "44/100"
  strings:
    $smallStack = {c645??73 c645??76 c645??63 c645??68 c645??6f c645??73 c645??74}
    $largeStack = {c7(45|85)[1-4]73000000 c7(45|85)[1-4]76000000 c7(45|85)[1-4]63000000 c7(45|85)[1-4]68000000 c7(45|85)[1-4]6f000000 c7(45|85)[1-4]73000000 c7(45|85)[1-4]74000000}
    $register = {b?73000000 6689???? b?76000000 6689???? b?63000000 6689???? b?68000000 6689???? b?6f000000 6689???? b?73000000 6689???? b?74000000 6689????}
    $dword = {c7(45|85)[1-4]68637673 [0-1]c7(45|85)[1-4]736f [0-1]c6(45|85)[1-4]74}
    $pushpop = {6a735? 6a76 6689????5? 6a63 6689????5? 6a68 6689????5? 6a6f 6689????5? 6a73 6689????5?}
    $callOverString = {e807000000737663686f73745? }
  condition:
    any of them
}

rule SUSP_Mozilla_Proxy_Check
{
  meta:
    description = "check for references to proxy and profile settings used by Mozilla - may indicate a sample is proxy aware"
    DaysofYARA_day = "43/100"
  strings:
    $ = "profiles.ini" ascii wide
    $ = "network.proxy.http" ascii wide
  condition:
    uint16(0) == 0x5A4D and
    filesize < 5MB and
    all of them
}

rule SUSP_Query_HTTPProxy_Data
{
  meta:
    description = "check for references to proxy settings used by Mozilla - may indicate a sample is proxy aware"
    DaysofYARA_day = "43/100"
  strings:
    $ = "network.proxy.http" ascii wide
  condition:
    uint16(0) == 0x5A4D and
    filesize < 5MB and
    all of them
}

rule SUSP_Mozilla_Profile_Check
{
  meta:
    description = "check for references to profile settings used by Mozilla"
    DaysofYARA_day = "43/100"
  strings:
    $ = "profiles.ini" ascii wide
  condition:
    uint16(0) == 0x5A4D and
    filesize < 5MB and
    all of them
}


rule SUSP_Query_HTTPProxy_Data_b64
{
  meta:
    description = "check for references to proxy settings used by Mozilla - may indicate a sample is proxy aware"
    DaysofYARA_day = "43/100"
  strings:
    $ = "network.proxy.http" base64 base64wide
  condition:
    uint16(0) == 0x5A4D and
    filesize < 5MB and
    all of them
}

rule SUSP_Query_HTTPProxy_Data_xor
{
  meta:
    description = "check for references to proxy settings used by Mozilla - may indicate a sample is proxy aware"
    DaysofYARA_day = "43/100"
  strings:
    $ = "network.proxy.http" xor(0x01 - 0xff)
  condition:
    uint16(0) == 0x5A4D and
    filesize < 5MB and
    all of them
}


rule SUSP_Mozilla_Profile_Check
{
  meta:
    description = "check for references to profile settings used by Mozilla"
    DaysofYARA_day = "43/100"
  strings:
    $ = "profiles.ini" ascii wide
  condition:
    uint16(0) == 0x5A4D and
    filesize < 5MB and
    all of them
}

rule SUSP_Mozilla_Profile_Check_b64
{
  meta:
    description = "check for references to profile settings used by Mozilla"
    DaysofYARA_day = "43/100"
  strings:
    $ = "profiles.ini" base64 base64wide
  condition:
    uint16(0) == 0x5A4D and
    filesize < 5MB and
    all of them
}


rule SUSP_Mozilla_Profile_Check__xor
{
  meta:
    description = "check for references to profile settings used by Mozilla"
    DaysofYARA_day = "43/100"
  strings:
    $ = "profiles.ini" xor(0x01 - 0xff)
  condition:
    uint16(0) == 0x5A4D and
    filesize < 5MB and
    all of them
}

/*
Day 42 did not include a shared rule! 
*/

rule SUSP_Embedded_PE_at_Section
{
  meta:
    description = "look for sections inside of a PE file that have an MZ header at the start! "
    DaysofYARA_day = "41/100"
    reference = "https://twitter.com/ochsenmeier/status/1491445641306062848/photo/1"
  condition:
    for any section in pe.sections:
      (
      section.raw_data_offset != 0x0 and  // make sure this rule doesn't FP on a section header that doesn't have a raw offset (aka points to 0x0)
      uint16be(section.raw_data_offset) == 0x4d5a
      )
}

rule SUSP_Embedded_Shellcode_at_Section
{
  meta:
    description = "look for sections inside of a PE file that maybe start with shellcode"
    disclaimer = "NO idea if this will work as expected"
    DaysofYARA_day = "41/100"
    reference = "https://twitter.com/ochsenmeier/status/1491445641306062848/photo/1"
  condition:
    for any section in pe.sections:
      (
      section.raw_data_offset != 0x0 and  // make sure this rule doesn't FP on a section header that is nulled and
        (
        uint16(section.raw_data_offset) == 0xE8FC or
        uint16(section.raw_data_offset) == 0xE800 or
        uint16(section.raw_data_offset) == 0x00E8
        )
      )
}

rule PE_Feature_DLL_Git
{
  meta:
    description = "check for the term git left in the DLL Name"
    DaysofYARA_day = "40/100"
  condition:
    pe.dll_name icontains "git"
}

rule PE_Feature_OriginalFileName_Git
{
  meta:
    description = "check for the term git left in the OriginalFileName"
    DaysofYARA_day = "40/100"
  condition:
    pe.version_info["OriginalFilename"] icontains "git"
}
rule PE_Feature_PBD_Git
{
  meta:
    description = "check for the term git left in the PDB path"
    DaysofYARA_day = "40/100"
  condition:
    pe.pdb_path icontains "git"
}

rule PE_Feature_DLL_CVE
{
  meta:
    description = "check for the term CVE left in the DLL Name"
    DaysofYARA_day = "39/100"
  condition:
    pe.dll_name icontains "cve"
}

rule PE_Feature_OriginalFileName_CVE
{
  meta:
    description = "check for the term CVE left in the OriginalFileName"
    DaysofYARA_day = "39/100"
  condition:
    pe.version_info["OriginalFilename"] icontains "cve"
}

rule PE_Feature_PBD_CVE
{
  meta:
    description = "check for the term CVE left in the PDB path"
    DaysofYARA_day = "39/100"
  condition:
    pe.pdb_path icontains "cve"
}

rule SUSP_StringRef_NoImport_VirtualAlloc
{
  meta:
    description = "check if an interesting API name is referenced as a string but not imported: VirtualAlloc"
    DaysofYARA_day = "38/100"
  strings:
    $ = "VirtualAlloc" ascii wide
  condition:
    all of them and
    not pe.imports("KERNEL32.dll", "VirtualAlloc")
}

rule SUSP_StringRef_NoImport_CryptDecrypt
{
  meta:
    description = "check if an interesting API name is referenced as a string but not imported: CryptDecrypt"
    DaysofYARA_day = "38/100"
  strings:
    $ = "CryptDecrypt" ascii wide
  condition:
    all of them and
    not pe.imports("advapi32.dll", "CryptDecrypt")
}

rule SUSP_StringRef_NoImport_VirtualAlloc_b64
{
  meta:
    description = "check if an interesting API name is referenced as a string but not imported: VirtualAlloc"
    DaysofYARA_day = "38/100"
  strings:
    $ = "VirtualAlloc" base64 base64wide
  condition:
    all of them and
    not pe.imports("KERNEL32.dll", "VirtualAlloc")
}

rule SUSP_StringRef_NoImport_CryptDecrypt_b64
{
  meta:
    description = "check if an interesting API name is referenced as a string but not imported: CryptDecrypt"
    DaysofYARA_day = "38/100"
  strings:
    $ = "CryptDecrypt" base64 base64wide
  condition:
    all of them and
    not pe.imports("advapi32.dll", "CryptDecrypt")
}


rule SUSP_StringRef_NoImport_VirtualAlloc_xor
{
  meta:
    description = "check if an interesting API name is referenced as a string but not imported: VirtualAlloc"
    DaysofYARA_day = "38/100"
  strings:
    $ = "VirtualAlloc" xor(0x01-0xff)
  condition:
    all of them and
    not pe.imports("KERNEL32.dll", "VirtualAlloc")
}


rule SUSP_StringRef_NoImport_CryptDecrypt_xor
{
  meta:
    description = "check if an interesting API name is referenced as a string but not imported: CryptDecrypt"
    DaysofYARA_day = "38/100"
  strings:
    $ = "CryptDecrypt" xor(0x01-0xff)
  condition:
    all of them and
    not pe.imports("advapi32.dll", "CryptDecrypt")
}

rule SUSP_PE_Shellcode_Call_MZ_Header
{
  meta:
    description = "checking for a likely call to a relative offset (E8) just after the MZ header for a cheeky hiding place for shellcode"
    reference = "https://malware.news/t/cobaltstrike-beacon-dll-your-no-ordinary-mz-header/34458"
    DaysofYARA_day = "37/100"
  condition:
    uint32be(0x0) == 0x4D5AE800
}

rule SUSP_PE_MZER_Header_Oddity
{
  meta:
    description = "check variations of MZER / MZAR / MZRE as a PE header followed by a call to a relative offset (E8) to check for PE's that can be executed as shellcode"
    reference = "https://trial.cobaltstrike.com/help-malleable-postex"
    reference = "https://www.sentinelone.com/labs/wading-through-muddy-waters-recent-activity-of-an-iranian-state-sponsored-threat-actor/"
    DaysofYARA_day = "36/100"
  condition:
    uint16be(0x0) == 0x4d5a and
    (
        uint16be(0x2) == 0x4552 or // MZER
        uint16be(0x2) == 0x5245 or // MZRE
        uint16be(0x2) == 0x4152    // MZAR
    ) and
    uint16be(0x4) == 0xe800

}


rule PE_Feature_Empty_RCDATA
{
  meta:
    description = "check for files that have RCDATA resources but don't name them using the new defined keyword"
    DaysofYARA_day = "35/100"
    note = "requires YARA v.4.2: https://github.com/VirusTotal/yara/releases/tag/v4.2.0-rc1"
  condition:
    for any resource in pe.resources:(
      resource.type == 10 and
      not defined resource.name_string and
      not defined resource.type_string
    )
}

rule PE_Feature_Undefined_DLL_Name
{
  meta:
    description = "check for files that have exports but the dll_name field is not there using the new defined keyword"
    DaysofYARA_day = "34/100"
    note = "requires YARA v.4.2: https://github.com/VirusTotal/yara/releases/tag/v4.2.0-rc1"
  condition:
    pe.number_of_exports > 0 and
    not defined pe.dll_name
}

rule PE_Feature_Blank_DLL_Name
{
  meta:
    description = "check for files that have exports but the dll_name field is blank"
    DaysofYARA_day = "34/100"
  condition:
    pe.number_of_exports > 0 and
    pe.dll_name == ""
}

rule PE_Feature_Empty_ExportName {
  meta:
    description = "check for exported functions that are not named using the new defined keyword"
    DaysofYARA_day = "33/100"
    note = "requires YARA v.4.2: https://github.com/VirusTotal/yara/releases/tag/v4.2.0-rc1"
  condition:
    for any exp in pe.export_details:
      (not defined exp.name and defined exp.offset)
}

rule PE_Feature_RAR_Overlay_not_WinRAR  {
  meta:
    description = "check for a RAR file in the overlay (which is normally found in WinRAR PE files) but ignore the WinRAR files to find smuggled RAR's"
    DaysofYARA_day = "31/100"
  condition:
    uint32be(pe.overlay.offset) == 0x52617221
    and not pe.pdb_path contains "WinRAR"
}

rule PE_Feature_RAR_RSRC {
  meta:
    description = "check for a RAR file in the resources"
    DaysofYARA_day = "31/100"
  condition:
    for any resource in pe.resources : (
      uint32be(resource.offset) == 0x52617221
    )
}


rule PE_Feature_DLL_Name_Slash {
  meta:
    description = "check for a slash character left in the DLL Name portion of the export table - for funsies"
    DaysofYARA_day = "30/100"
  condition:
    pe.dll_name contains "\\"
}

rule PE_Feature_OriginalFilename_Slash {
  meta:
    description = "check for a slash character left in the OriginalFileName portion of version info - for funsies"
    DaysofYARA_day = "30/100"
  condition:
    pe.version_info["OriginalFilename"] contains "\\"
 }

rule PE_Feature_SectionName_Slash
 {
  meta:
    description = "check for a slash character left in any of the section names - for funsies"
    DaysofYARA_day = "30/100"
  condition:
    for any section in pe.sections: ( section.name contains "\\" )
 }


rule SUSP_5_PEs_in_rsrcs
{ 
  meta:
    description = "check if at least five of the resources for a given PE are also PE's"
    DaysofYARA_day = "29/100"
  condition:
    for 5 resource in pe.resources: (
    uint16(resource.offset) == 0x5a4d )
}

rule SUSP_4_PEs_in_rsrcs
{ 
  meta:
    description = "check if at least four of the resources for a given PE are also PE's"
    DaysofYARA_day = "29/100"
  condition:
    for 4 resource in pe.resources: (
    uint16(resource.offset) == 0x5a4d )
}


rule SUSP_3_PEs_in_rsrcs
{ 
  meta:
    description = "check if at least three of the resources for a given PE are also PE's"
    DaysofYARA_day = "29/100"
  condition:
    for 3 resource in pe.resources: (
    uint16(resource.offset) == 0x5a4d )
}

rule SUSP_2_PEs_in_rsrcs
{ 
  meta:
    description = "check if at least two of the resources for a given PE are also PE's"
    DaysofYARA_day = "29/100"
  condition:
    for 2 resource in pe.resources: (
    uint16(resource.offset) == 0x5a4d )
}


rule SUSP_NOP_Sled_PE_RSRC
{
  meta:
    DaysofYARA_day = "28/100"
    desc = "check for NOP'd bytes at the start of a given resource"
    reference = "https://community.carbonblack.com/t5/Threat-Advisories-Documents/ROKrat-Technical-Analysis/ta-p/62549"
  condition:
    for any resource in pe.resources:
    (uint32be(resource.offset) == 0x90909090)
}


rule SUSP_NOP_Sled_PE_Overlay
{
  meta:
    DaysofYARA_day = "28/100"
    desc = "check for NOP'd bytes at the start of the overlay"
    reference = "https://community.carbonblack.com/t5/Threat-Advisories-Documents/ROKrat-Technical-Analysis/ta-p/62549"
  condition:
    pe.overlay.offset != 0 and
    uint32be(pe.overlay.offset) == 0x90909090
}


rule SUSP_AutoFun
{
  meta:
    DaysofYARA_day = "27/100"
    desc = "another one based off the ESET paper, checking for references to an autorun file (potentially found on USB-borne malware)"
    reference = "https://www.welivesecurity.com/wp-content/uploads/2021/12/eset_jumping_the_air_gap_wp.pdf"
  strings:
    $= "autorun.inf" nocase ascii wide
  condition:
    uint16(0) == 0x5a4d and all of them
}


rule SUSP_AutoFun_b64
{
  meta:
    DaysofYARA_day = "27/100"
    desc = "another one based off the ESET paper, checking for references to an autorun file (potentially found on USB-borne malware)"
    reference = "https://www.welivesecurity.com/wp-content/uploads/2021/12/eset_jumping_the_air_gap_wp.pdf"
  strings:
    $= "autorun.inf" base64 base64wide
  condition:
    uint16(0) == 0x5a4d and all of them
}

rule SUSP_AutoFun_xor
{
  meta:
    DaysofYARA_day = "27/100"
    desc = "another one based off the ESET paper, checking for references to an autorun file (potentially found on USB-borne malware)"
    reference = "https://www.welivesecurity.com/wp-content/uploads/2021/12/eset_jumping_the_air_gap_wp.pdf"
  strings:
    $= "autorun.inf" xor(0x01-0xff)
  condition:
    uint16(0) == 0x5a4d and all of them
}

rule SUSP_Network_Recon
{
  meta:
    DaysofYARA_day = "26/100"
    desc = "check for some reconnaissance commands"
    reference = "https://www.welivesecurity.com/wp-content/uploads/2021/12/eset_jumping_the_air_gap_wp.pdf"
  strings:
    $ = "tracert" ascii wide
    $ = "tasklist" ascii wide
    $ = "systeminfo" ascii wide
    $ = "ipconfig" ascii wide
    $ = "netstat" ascii wide
    $ = "nbtstat" ascii wide
    $ = "route" ascii wide
    $ = "netsh" ascii wide
  condition:
    uint16(0) == 0x5a4d and 3 of them
}

rule SUSP_Network_Recon_b64
{
  meta:
    DaysofYARA_day = "26/100"
    desc = "check for some reconnaissance commands"
    reference = "https://www.welivesecurity.com/wp-content/uploads/2021/12/eset_jumping_the_air_gap_wp.pdf"
  strings:
    $ = "tracert" base64 base64wide
    $ = "tasklist" base64 base64wide
    $ = "systeminfo" base64 base64wide
    $ = "ipconfig" base64 base64wide
    $ = "netstat" base64 base64wide
    $ = "nbtstat" base64 base64wide
    $ = "route" base64 base64wide
    $ = "netsh" base64 base64wide
  condition:
    uint16(0) == 0x5a4d and 3 of them
}

rule SUSP_Network_Recon_xor
{
  meta:
    DaysofYARA_day = "26/100"
    desc = "check for some reconnaissance commands"
    reference = "https://www.welivesecurity.com/wp-content/uploads/2021/12/eset_jumping_the_air_gap_wp.pdf"
  strings:
    $ = "tracert" xor(0x01-0xff)
    $ = "tasklist" xor(0x01-0xff)
    $ = "systeminfo" xor(0x01-0xff)
    $ = "ipconfig" xor(0x01-0xff)
    $ = "netstat" xor(0x01-0xff)
    $ = "nbtstat" xor(0x01-0xff)
    $ = "route" xor(0x01-0xff)
    $ = "netsh" xor(0x01-0xff)
  condition:
    uint16(0) == 0x5a4d and 3 of them
}

rule MAL_Winnti_Rolling_XOR_BruteForce
{
  meta:
    DaysofYARA_day = "25/100"
    desc = "brute force the configurtion contained in known Winnti samples' overlays for the encoded ports listed after each C2"
    ref = "Heavily based on analysis from Novetta and tooling built by Moritz Contag, Silas Cutler, and BR Data"
    reference = "https://www.novetta.com/wp-content/uploads/2015/04/novetta_winntianalysis.pdf"
    reference = "https://github.com/br-data/2019-winnti-analyse"
    reference = "https://medium.com/chronicle-blog/winnti-more-than-just-windows-and-gates-e4f03436031a"
    hash = "7566558469ede04efc665212b45786a730055770f6ea8f924d8c1e324cae8691"
    hash = "7cd17fc948eb5fa398b8554fea036bdb3c0045880e03acbe532f4082c271e3c5"
    hash = "63e8ed9692810d562adb80f27bb1aeaf48849e468bf5fd157bc83ca83139b6d7"
  hash = "79190925bd1c3fae65b0d11db40ac8e61fb9326ccfed9b7e09084b891089602d"
  condition:
    pe.overlay.size < 600 and  //look for a moderate sized overlay
    pe.overlay.size >= 200 and //look for a moderate sized overlay
    pe.number_of_sections == 6 and  // common Winnti PE feature to narrow our pool
    pe.number_of_resources == 1 and // common Winnti PE feature to narrow our pool
    pe.overlay.offset != 0x0 and // verify the overlay does not start at 0x0 (sometimes this happens, unclear why)
    (
      for any byte in (pe.overlay.offset .. pe.overlay.offset+40):  //loop over only the first 40 bytes of the overlay
        (
    	for any key in (153 .. 255):(  //the key is in the range of 0xa0 to 0xff so check all dems
    	  ((uint8(byte) ^ key == 0x3a) and (uint8(byte + 1) ^ (key + 1) == 0x38) and (uint8(byte + 2) ^ (key + 2) == 0x30)) or // check that 3 sequential bytes xor'd by 3 incremented keys decode to :80
    	  ((uint8(byte) ^ key == 0x3a) and (uint8(byte + 1) ^ (key + 1) == 0x35) and (uint8(byte + 2) ^ (key + 2) == 0x33)) or  // check that 3 sequential bytes xor'd by 3 incremented keys decode to :53
    	  ((uint8(byte) ^ key == 0x3a) and (uint8(byte + 1) ^ (key + 1) == 0x34) and (uint8(byte + 2) ^ (key + 2) == 0x34) and (uint8(byte + 3) ^ (key + 3) == 0x33)) // check that 3 sequential bytes xor'd by 3 incremented keys decode to :443
    	)
      )
    )
}

rule SUSP_ExchangeTransport_Service_Assembly
{
  meta:
    DaysofYARA_day = "24/100"
    description = "Track references to Microsoft.Exchange.Data.Transport assemblies and other aspects of exchange transport agents, as used by the passive NETTRANS backdoor"
    reference = "https://docs.microsoft.com/en-us/previous-versions/office/exchange-server-api/aa564119(v=exchg.150)"
  strings:
  
    //Microsoft.Exchange.Data.Transport.Smtp
    $ = "SmtpReceiveAgentFactory" ascii
    $ = "SmtpReceiveAgent" ascii
      
    //Microsoft.Exchange.Data.Transport.Routing
    $ = "RoutingAgentFactory"
    $ = "RoutingAgent"
      
    //Microsoft.Exchange.Data.Transport
    $ = "SmtpServer" ascii
    $ = "ReceiveMessageEventSource" ascii
    $ = "EndOfDataEventArgs" ascii
    $ = "EndOfDataEventHandler" ascii
    $ = "add_OnEndOfData" ascii
    $ = "RejectEventSource" ascii
    $ = "RejectEventArgs" ascii
    $ = "RejectEventHandler" ascii
    $ = "add_OnReject" ascii
    $ = "EnvelopeRecipientCollection" ascii
    $ = "MailItem" ascii
    $ = "get_MailItem" ascii
      
    //Microsoft.Exchange.Data.Transport.Email
    $ = "EmailMessage" ascii
    $ = "get_Message" ascii
      
    //Microsoft.Exchange.Data.Common
    $ = "DotfuscatorAttribute"
    $ = "TransportRuleAgentFactory"
    $ = "TransportRuleAgent"
    $ = "RedirectionAgentFactory"
    $ = "RedirectionAgent"
    $ = "CreateAgent"
  condition:
    uint16(0) == 0x5a4d and
    filesize < 250KB and
    5 of them
}

rule SUSP_WSM_Service_Assembly
{
  meta:
    DaysofYARA_day = "23/100"
    description = "Track references to System.ServiceModel.Web assemblies and WCF service contracts, as used in the passive NEPTUN backdoor"
    reference = "https://docs.microsoft.com/en-us/dotnet/framework/wcf/feature-details/"
    reference = "https://docs.microsoft.com/en-us/dotnet/framework/wcf/migrating-from-net-remoting-to-wcf"
    reference = "https://norfolkinfosec.com/http-listener/"
  strings:
    $assembly_ref = "System.ServiceModel.Web" ascii wide
    $class1 = "ServiceHost" ascii wide
    $class2 = "DataContractAttribute" ascii wide
    $class3 = "ServiceContractAttribute" ascii wide
    $class4 = "OperationContractAttribute" ascii wide
    $localhost = "localhost" ascii wide
  condition:
    uint16(0) == 0x5a4d and
    filesize < 250KB and
    all of them
}

rule MAL_PlugX_Encoded_DAT_Loop
{
  meta:
    description = "track PlugX variants based on encoding mechanism of DAT file a bit differently than the homies at DTCERT"
    DaysofYARA_day = "22/100"
    reference = "https://github.com/telekom-security/malware_analysis/blob/main/plugx/plugx_mustang_panda.yar"
    reference = "https://twitter.com/DTCERT/status/1454022175254618114"
    reference = "https://unit42.paloaltonetworks.com/thor-plugx-variant/"
  condition:
    filesize > 80KB and filesize < 200KB and //make sure the file the right size
    uint16(0) != 0x5A4D and uint16(0) != 0x4b50 and // ignore some common file types
    uint32be(0) != 0x6465780a and uint16(0) != 0x534d and // ignore some common file types
    uint16be(0) != 0x504B and uint16be(0) != 0xD0CF and // ignore some common file types
    uint16be(0) != 0x5261 and uint16be(0) != 0x4C5A and  // ignore some common file types
      for 1 byte in (0 .. 15): //loop across the first 15 bytes bytes of a file
      (
        uint8(byte) == 0x00 and // find that only 1 of the first 15 bytes is 00
        (uint8(byte + 1) ^ uint8(0x0) == 0x4d) and // and the byte after the 00 anchor, XOR'd by the byte at 0x0 will be M
        (uint8(byte + 2) ^ uint8(0x1) == 0x5a) and // and the byte 2 bytes after the 00 anchor, XOR'd by the byte at 0x1 will be Z
        math.count(0x00, 0, 15) == 1 //make sure null byte only occurs once in the first 15 bytes
        // programming note - cannot pass the byte variable to math.count() to process
      )
}

rule MAL_CACHEMONEY_Config
{
  meta:
    DaysofYARA_day = "21/100"
    reference = "https://twitter.com/int2e_/status/1148711362853515265?s=21"
    description = "inspired by Adrien to detect CACHEMONEY configs based on decoded values and expected first bytes"

  condition:
    filesize < 200KB and 
    ((uint8(0x0) ^ 0xEF) ^ uint8(0x32)) == 0x54 and 
      // first byte of config is always 0xef, so xor that with the value at 0x0 to get first byte of xor key and verify it decoded as expected
    ((uint8(0x1) ^ 0xBB) ^ uint8(0x33)) == 0x69 and 
      // 2nd byte of config is always 0xbb, xor that with int at 0x1 to check byte of the XOR key, and verify it decoded the cleartext byte
    ((uint8(0x2) ^ 0xBF) ^ uint8(0x34)) == 0x6D  
      // 3rd byte of config is always 0xbf, so xor that with the value at 0x2 to get third byte of xor key
}

rule SUSP_Shellcode_PE_Overlay_Offset
{
  meta:
    description = "checking for probable shellcode bytes at PE Overlay"
    DaysofYARA_day = "20/100"
    hash = "47a49caaa6bd9bb4014f311369a610bdd0405eb36b19ed5f88ef232b0ac43483" //BLACKMIRROR
    hash = "9d9697509adfd039f214b036497c16c21395f97eb8a58847ae46e7f37846414a" //BLACKMIRROR
    hash = "cdcb5144c36c3aee7604fbafa191c51475ff11eaf7e2fba1bdf4f836edc4cda5" //BLACKMIRROR
    hash = "ce363e58b8654642fee57ea84e9b3ca82393bb621d4822b964487912e1cf3f53" //BLACKMIRROR
    hash = "e9dd6420aa2db28ae5eeb3963d020e1873de8e3109bfcb38e9116b9e51377969" //BLACKMIRROR
    hash = "300519fa1af5c36371ab438405eb641f184bd2f491bdf24f04e5ca9b86d1b39c" //CROSSWALK
    hash = "db866ef07dc1f2e1df1e6542323bc672dd245d88c0ee91ce0bd3da2c95aedf68" //CROSSWALK
  condition:
    uint16(pe.overlay.offset) == 0xE8FC or
    uint16(pe.overlay.offset) == 0x48FC or
    uint16(pe.overlay.offset) == 0xE800 or
    uint16(pe.overlay.offset) == 0x4800 or
    uint16(pe.overlay.offset) == 0x00E8 or
    uint16(pe.overlay.offset) == 0x0048
}

rule SUSP_Shellcode_PE_rsrc
{
meta:
    description = "checking for probable shellcode bytes at PE resource"
    DaysofYARA_day = "20/100"
  condition:
    for any resource in pe.resources: ( resource.type == 10 and // ensure its RCDATA and not an icon
      (
      uint16(resource.offset) == 0xE8FC or
      uint16(resource.offset) == 0x48FC or
      uint16(resource.offset) == 0xE800 or
      uint16(resource.offset) == 0x4800 or
      uint16(resource.offset) == 0x00E8 or
      uint16(resource.offset) == 0x0048 ))
}

rule SUSP_CLSID_Imports
{
  meta:
    description = "look for imports that may indicate CLSID and COM object interest"
    DaysofYARA_day = "19/100"
  condition:
    pe.imports("ole32.dll", "StringFromCLSID")
}

rule MAL_SquirrelWaffle_Blocklist_Section_Start
{
  meta:
    description = "check for sequence used by SquirrelWaffle (now defunct malware) to find and load its blocklist blob, which is XOR encoded. The blob is pretty big, terminated with some null bytes, and is followed by the XOR key to decode it. This rule will look for the reference to the blob, then use the address of the blob as a starting point for a loop that tries to find the first 4 bytes of the XOR key, and decode the first four bytes of the blob, to make sure it properly decodes to the expected value "
    hash = "20bf38b377868f4a617011fd9b39790824d0afd1d1ca089083913ebd62bb747f"
    hash = "1d8efc7665bc83f1d7fe443ef4ce6c52eb4829769de0f7fb890b5b12bbcb92bd"
    hash = "c88f8d086be8dd345babad15c76490ef889af7eaecb015f3107ff039f0ed5f2d"
    DaysofYARA_day = "18/100"
  strings:
    $data_blob = { 8d 8d 7c fd fe ff 68 ?? 0? 00 00 68 }
      //8d 8d 7c fd fe ff  LEA        ECX,[EBP + 0xfffefd7c]
      //68 9c 08 00 00     PUSH       0x89c                 changes each loop
      //68 f0 a5 5c 00     PUSH       blocklist_location
  condition:
    for 1 i in (
    pe.rva_to_offset(uint32(@data_blob+12) - pe.image_base) .. 
    math.min(pe.rva_to_offset(uint32(@data_blob+12) - pe.image_base) + 3000, 
      //loop through the 3k bytes following the offset we found pointed to at the end of the $data_blob string, 
      //stopping at the start of the next section 
        
	(pe.sections[2].raw_data_offset))): 
        // use the start of the next section as the upper bound
          (
          (uint16(i) == 0x0000 and //set an anchor for the end of the data blob, where the XOR key starts
            (
            uint32be(i+2) ^ uint32be(pe.rva_to_offset(uint32(@data_blob+12) - pe.image_base) 
            //xor the dword 2 bytes after the 00's with the first dword of the blocklist
            ) == 0x39342e34))) // and verify that it decodes to the first IP address listed
}

rule MAL_SquirrelWaffle_Blocklist_Next_Section_Offset
{
  meta:
    description = "check for sequence used by SquirrelWaffle (now defunct malware) to find and load its blocklist blob, which is XOR encoded. The blob is pretty big, terminated with some null bytes, and is followed by the XOR key to decode it. This rule will look for the reference to the blob, then use the address of the blob as a starting point for a loop that tries to find the first 4 bytes of the XOR key, and decode the first four bytes of the blob, to make sure it properly decodes to the expected value. This version of the rule attempts to use the section sizes as guardrails for the loop"
    hash = "20bf38b377868f4a617011fd9b39790824d0afd1d1ca089083913ebd62bb747f"
    hash = "1d8efc7665bc83f1d7fe443ef4ce6c52eb4829769de0f7fb890b5b12bbcb92bd"
    hash = "c88f8d086be8dd345babad15c76490ef889af7eaecb015f3107ff039f0ed5f2d"
    DaysofYARA_day = "18/100"
  strings:
    $data_blob = { 8d 8d 7c fd fe ff 68 ?? 0? 00 00 68 }
      //8d 8d 7c fd fe ff  LEA        ECX,[EBP + 0xfffefd7c]
      //68 9c 08 00 00     PUSH       0x89c                 changes each loop
      //68 f0 a5 5c 00     PUSH       blocklist_loc
  condition:
    for any i in (pe.rva_to_offset(uint32(@data_blob+12) - pe.image_base) .. 
    math.min(pe.sections[1].raw_data_offset + pe.sections[1].raw_data_size, pe.rva_to_offset(uint32(@data_blob+12) - pe.image_base) + 3000)): 
      // use the 2nd section (index 1) as a guardrail for the loop
        (
        (uint16(i) == 0x0000 and //set an anchor for the end of the data blob, where the XOR key starts
          (
          uint32be(i+2) ^ uint32be(pe.rva_to_offset(uint32(@data_blob+12) - pe.image_base) //xor the dword 2 bytes after the 00's with the first dword of the blocklist
          ) == 0x39342e34))) // and verify that it decodes to the first IP address listed

}

rule Method_InternalComm_InterProcessCommunication
{
  meta:
    description = "check for the presence of a Inter Process Communication (umbrella over named pipes) string. IPC can be bidirectional, typically used by connecting to the IPC share (IPC$) via named pipe or - while a bunch of malware families reference named pipes, only your favorite actor's favorite actor reference these."
    reference = "https://docs.microsoft.com/en-us/troubleshoot/windows-server/networking/inter-process-communication-share-null-session"
    DaysofYARA_day = "17/100"
  strings:
    $ = "\\ipc$" nocase ascii wide
    $ = "\\\\%s\\ipc$" nocase ascii wide
    $ = "\\\\%s\\ipc" nocase ascii wide
  condition:
    1 of them
}

rule Method_InternalComm_InterProcessCommunication_b64
{
  meta:
    description = "check for the presence of a Inter Process Communication (umbrella over named pipes) string. IPC can be bidirectional, typically used by connecting to the IPC share (IPC$) via named pipe or - while a bunch of malware families reference named pipes, only your favorite actor's favorite actor reference these."
    reference = "https://docs.microsoft.com/en-us/troubleshoot/windows-server/networking/inter-process-communication-share-null-session"
    DaysofYARA_day = "17/100"
  strings:
    $ = "\\ipc$" base64 base64wide
    $ = "\\\\%s\\ipc$" base64 base64wide
    $ = "\\\\%s\\ipc" base64 base64wide
  condition:
    1 of them
}

rule Method_InternalComm_InterProcessCommunication_xor
{
  meta:
    description = "check for the presence of a Inter Process Communication (umbrella over named pipes) string. IPC can be bidirectional, typically used by connecting to the IPC share (IPC$) via named pipe or - while a bunch of malware families reference named pipes, only your favorite actor's favorite actor reference these."
    reference = "https://docs.microsoft.com/en-us/troubleshoot/windows-server/networking/inter-process-communication-share-null-session"
    DaysofYARA_day = "17/100"
  strings:
    $ = "\\ipc$" xor(0x01-0xff)
    $ = "\\\\%s\\ipc$" xor(0x01-0xff)
    $ = "\\\\%s\\ipc" xor(0x01-0xff)
  condition:
    1 of them
}

rule Method_InternalComm_RPC_NamedPipe
{
  meta:
    description = "check for a string required in a Remote Procedure Call (a type of IPC) that uses a named pipe"
    reference = "https://docs.microsoft.com/en-us/windows/win32/api/rpcdce/nf-rpcdce-rpcstringbindingcomposew"
    reference = "https://specterops.io/assets/resources/RPC_for_Detection_Engineers.pdf"
    DaysofYARA_day = "16/100"
  strings:
    $ = "ncacn_np" ascii wide
  condition:
    all of them
}


rule Method_InternalComm_RPC_NamedPipe_b64
{
  meta:
    description = "check for a string required in a Remote Procedure Call (a type of IPC) that uses a named pipe"
    reference = "https://docs.microsoft.com/en-us/windows/win32/api/rpcdce/nf-rpcdce-rpcstringbindingcomposew"
    reference = "https://specterops.io/assets/resources/RPC_for_Detection_Engineers.pdf"
    DaysofYARA_day = "16/100"
  strings:
    $ = "ncacn_np" base64 base64wide
  condition:
    all of them
}

rule Method_InternalComm_RPC_NamedPipe_XOR
{
  meta:
    description = "check for a string required in a Remote Procedure Call (a type of IPC) that uses a named pipe"
    reference = "https://docs.microsoft.com/en-us/windows/win32/api/rpcdce/nf-rpcdce-rpcstringbindingcomposew"
    reference = "https://specterops.io/assets/resources/RPC_for_Detection_Engineers.pdf"
    DaysofYARA_day = "16/100"
  strings:
    $ = "ncacn_np" xor(0x01-0xff)
  condition:
    all of them
}

rule Method_InternalComm_RPC_Protocols
{
  meta:
    description = "check for a strings used by Remote Procedure Calls to implement other protocols that aren't named pipes"
    reference = "https://docs.microsoft.com/en-us/windows/win32/api/rpcdce/nf-rpcdce-rpcstringbindingcomposew"
    reference = "https://specterops.io/assets/resources/RPC_for_Detection_Engineers.pdf"
    DaysofYARA_day = "16/100"
  strings:
    $ = "ncacn_http" ascii wide
    $ = "ncacn_ip_udp" ascii wide
    $ = "ncacn_ip_tcp" ascii wide
    $ = "ncalrpc" ascii wide
    $ = "upnprpc" ascii wide
  condition:
    any of them
}

rule Method_InternalComm_RPC_Protocols_b64
{
  meta:
    description = "check for a strings used by Remote Procedure Calls to implement other protocols that aren't named pipes"
    reference = "https://docs.microsoft.com/en-us/windows/win32/api/rpcdce/nf-rpcdce-rpcstringbindingcomposew"
    reference = "https://specterops.io/assets/resources/RPC_for_Detection_Engineers.pdf"
    DaysofYARA_day = "16/100"
  strings:
    $ = "ncacn_http" base64 base64wide
    $ = "ncacn_ip_udp" base64 base64wide
    $ = "ncacn_ip_tcp" base64 base64wide
    $ = "ncalrpc" base64 base64wide
    $ = "upnprpc" base64 base64wide
  condition:
    any of them
}

rule Method_InternalComm_RPC_Protocols_XOR
{
  meta:
    description = "check for a strings used by Remote Procedure Calls to implement other protocols that aren't named pipes"
    reference = "https://docs.microsoft.com/en-us/windows/win32/api/rpcdce/nf-rpcdce-rpcstringbindingcomposew"
    reference = "https://specterops.io/assets/resources/RPC_for_Detection_Engineers.pdf"
    DaysofYARA_day = "16/100"
  strings:
    $ = "ncacn_http" xor(0x01-0xff)
    $ = "ncacn_ip_udp" xor(0x01-0xff)
    $ = "ncacn_ip_tcp" xor(0x01-0xff)
    $ = "ncalrpc" xor(0x01-0xff)
    $ = "upnprpc" xor(0x01-0xff)
  condition:
    any of them
}

rule Method_InternalComm_RPC_MIDL_Lang_GUID
{
  meta:
    description = "check for other strings related to RPC according to MSFT's links below"
    reference = "https://docs.microsoft.com/en-us/windows/win32/midl/midl-language-reference"
    DaysofYARA_day = "16/100"
  strings:
    $ = "ncacn_at_dsp" ascii wide
    $ = "ncacn_dnet_nsp" ascii wide
    $ = "ncacn_nb_ipx" ascii wide
    $ = "ncacn_spx" ascii wide
    $ = "ncacn_nb_nb" ascii wide
    $ = "ncacn_nb_tcp" ascii wide
    $ = "ncacn_vns_spp" ascii wide
    $ = "ncadg_ip_udp" ascii wide
    $ = "ncadg_ipx" ascii wide
    $ = "E3514235-4B06-11D1-AB04-00C04FC2DCD2" ascii wide
  condition:
    any of them
}




rule Method_InternalComm_NamedPipe
{
  meta:
    description = "check for a reference to the start of a named pipe to send data across servers / hosts using SMB for one-way communication."
    reference = "https://docs.microsoft.com/en-us/windows/win32/ipc/named-pipes"
    DaysofYARA_day = "15/100"
  strings:
    $ = "\\pipe\\" ascii wide
    $ = "\\\\.\\pipe\\" ascii wide
  condition:
    1 of them
}

rule Method_InternalComm_NamedPipe_b64
{
  meta:
    description = "check for a reference to the start of a named pipe to send data across servers / hosts using SMB for one-way communication"
    reference = "https://docs.microsoft.com/en-us/windows/win32/ipc/named-pipes"
    DaysofYARA_day = "15/100"
  strings:
    $ = "\\pipe\\" base64 base64wide
    $ = "\\\\.\\pipe\\" base64 base64wide
  condition:
    1 of them
}

rule Method_InternalComm_NamedPipe_xor
{
  meta:
    description = "check for a reference to the start of a named pipe to send data across servers / hosts using SMB for one-way communication. This XOR flavor catches a lotta Beacon"
    reference = "https://docs.microsoft.com/en-us/windows/win32/ipc/named-pipes"
    DaysofYARA_day = "15/100"
  strings:
    $ = "\\pipe\\" xor(0x01-0xff)
    $ = "\\\\.\\pipe\\" xor(0x01-0xff)
  condition:
    1 of them
}

rule Method_InternalComm_NamedPipe_References
{
  meta:
    description = "look for references to the System.IO.Pipes namespace that indicate interest in named pipes. Have seen use by both .NET and Powershell Tooling"
    reference = "https://svch0st.medium.com/guide-to-named-pipes-and-hunting-for-cobalt-strike-pipes-dc46b2c5f575"
    reference = "https://docs.microsoft.com/en-us/dotnet/api/system.io.pipes.namedpipeserverstream?view=net-6.0"
    reference = "https://docs.microsoft.com/en-us/dotnet/api/system.io.pipes?view=net-6.0"
    DaysofYARA_day = "15/100"
  strings:
    $ = "system.IO.Pipes" ascii wide
    $ = "NamedPipeServerStream" ascii wide
    $ = "NamedPipeClientStream" ascii wide
    $ = "NamedPipeServerStreamAcl" ascii wide
  condition:
    1 of them
}

rule Method_InternalComm_AnonPipe_References
{
  meta:
    description = "look for references to the System.IO.Pipes namespace that indicate interest in anonymous pipes. No hits in my visibility"
    reference = "https://svch0st.medium.com/guide-to-named-pipes-and-hunting-for-cobalt-strike-pipes-dc46b2c5f575"
    reference = "https://docs.microsoft.com/en-us/dotnet/api/system.io.pipes.namedpipeserverstream?view=net-6.0"
    reference = "https://docs.microsoft.com/en-us/dotnet/api/system.io.pipes?view=net-6.0"
    DaysofYARA_day = "15/100"
  strings:
    $ = "AnonymousPipeClientStream" ascii wide
    $ = "AnonymousPipeServerStream" ascii wide
    $ = "AnonymousPipeServerStreamAcl" ascii wide
  condition:
    1 of them
}

rule Method_InternalComm_PipeRights_References
{
  meta:
    description = "look for references to the System.IO.Pipes namespace that indicate interest in named pipes. Have seen use by both .NET and Powershell Tooling"
    reference = "https://svch0st.medium.com/guide-to-named-pipes-and-hunting-for-cobalt-strike-pipes-dc46b2c5f575"
    reference = "https://docs.microsoft.com/en-us/dotnet/api/system.io.pipes.namedpipeserverstream?view=net-6.0"
    reference = "https://docs.microsoft.com/en-us/dotnet/api/system.io.pipes?view=net-6.0"
    DaysofYARA_day = "15/100"
  strings:
    $ = "PipeAccessRights" ascii wide
    $ = "PipeAccessRule" ascii wide
    $ = "PipeAuditRule" ascii wide
    $ = "PipeDirection" ascii wide
    $ = "PipeOptions" ascii wide
    $ = "PipesAclExtensions" ascii wide
    $ = "PipeSecurity" ascii wide
    $ = "PipeStream" ascii wide
    $ = "PipeStreamImpersonationWorker" ascii wide
    $ = "PipeTransmissionMode" ascii wide
  condition:
    1 of them
}

rule Method_InternalComm_NamedPipe_References_b64
{
  meta:
    description = "look for references to the System.IO.Pipes namespace that indicate interest in named pipes. Have seen use by both .NET and Powershell Tooling"
    reference = "https://svch0st.medium.com/guide-to-named-pipes-and-hunting-for-cobalt-strike-pipes-dc46b2c5f575"
    reference = "https://docs.microsoft.com/en-us/dotnet/api/system.io.pipes.namedpipeserverstream?view=net-6.0"
    reference = "https://docs.microsoft.com/en-us/dotnet/api/system.io.pipes?view=net-6.0"
    DaysofYARA_day = "15/100"
  strings:
    $ = "system.IO.Pipes" base64 base64wide
    $ = "NamedPipeServerStream" base64 base64wide
    $ = "NamedPipeClientStream" base64 base64wide
    $ = "NamedPipeServerStreamAcl" base64 base64wide
  condition:
    1 of them
}

rule Method_InternalComm_AnonPipe_References_b64
{
  meta:
    description = "look for references to the System.IO.Pipes namespace that indicate interest in anonymous pipes. No hits in my visibility"
    reference = "https://svch0st.medium.com/guide-to-named-pipes-and-hunting-for-cobalt-strike-pipes-dc46b2c5f575"
    reference = "https://docs.microsoft.com/en-us/dotnet/api/system.io.pipes.namedpipeserverstream?view=net-6.0"
    reference = "https://docs.microsoft.com/en-us/dotnet/api/system.io.pipes?view=net-6.0"
    DaysofYARA_day = "15/100"
  strings:
    $ = "AnonymousPipeClientStream" base64 base64wide
    $ = "AnonymousPipeServerStream" base64 base64wide
    $ = "AnonymousPipeServerStreamAcl" base64 base64wide
  condition:
    1 of them
}

rule Method_InternalComm_PipeRights_References_b64
{
  meta:
    description = "look for references to the System.IO.Pipes namespace that indicate interest in named pipes. Have seen use by both .NET and Powershell Tooling"
    reference = "https://svch0st.medium.com/guide-to-named-pipes-and-hunting-for-cobalt-strike-pipes-dc46b2c5f575"
    reference = "https://docs.microsoft.com/en-us/dotnet/api/system.io.pipes.namedpipeserverstream?view=net-6.0"
    reference = "https://docs.microsoft.com/en-us/dotnet/api/system.io.pipes?view=net-6.0"
    DaysofYARA_day = "15/100"
  strings:
    $ = "PipeAccessRights" base64 base64wide
    $ = "PipeAccessRule" base64 base64wide
    $ = "PipeAuditRule" base64 base64wide
    $ = "PipeDirection" base64 base64wide
    $ = "PipeOptions" base64 base64wide
    $ = "PipesAclExtensions" base64 base64wide
    $ = "PipeSecurity" base64 base64wide
    $ = "PipeStream" base64 base64wide
    $ = "PipeStreamImpersonationWorker" base64 base64wide
    $ = "PipeTransmissionMode" base64 base64wide
  condition:
    1 of them
}

rule Method_InternalComm_NamedPipe_References_XOR
{
  meta:
    description = "look for references to the System.IO.Pipes namespace that indicate interest in named pipes. Have seen use by both .NET and Powershell Tooling"
    reference = "https://svch0st.medium.com/guide-to-named-pipes-and-hunting-for-cobalt-strike-pipes-dc46b2c5f575"
    reference = "https://docs.microsoft.com/en-us/dotnet/api/system.io.pipes.namedpipeserverstream?view=net-6.0"
    reference = "https://docs.microsoft.com/en-us/dotnet/api/system.io.pipes?view=net-6.0"
    DaysofYARA_day = "15/100"
  strings:
    $ = "system.IO.Pipes" xor(0x01-0xff)
    $ = "NamedPipeServerStream" xor(0x01-0xff)
    $ = "NamedPipeClientStream" xor(0x01-0xff)
    $ = "NamedPipeServerStreamAcl" xor(0x01-0xff)
  condition:
    1 of them
}

rule Method_InternalComm_AnonPipe_References_XOR
{
  meta:
    description = "look for references to the System.IO.Pipes namespace that indicate interest in anonymous pipes. No hits in my visibility"
    reference = "https://svch0st.medium.com/guide-to-named-pipes-and-hunting-for-cobalt-strike-pipes-dc46b2c5f575"
    reference = "https://docs.microsoft.com/en-us/dotnet/api/system.io.pipes.namedpipeserverstream?view=net-6.0"
    reference = "https://docs.microsoft.com/en-us/dotnet/api/system.io.pipes?view=net-6.0"
    DaysofYARA_day = "15/100"
  strings:
    $ = "AnonymousPipeClientStream" xor(0x01-0xff)
    $ = "AnonymousPipeServerStream" xor(0x01-0xff)
    $ = "AnonymousPipeServerStreamAcl" xor(0x01-0xff)
  condition:
    1 of them
}

rule Method_InternalComm_PipeRights_References_XOR
{
  meta:
    description = "look for references to the System.IO.Pipes namespace that indicate interest in named pipes. Have seen use by both .NET and Powershell Tooling"
    reference = "https://svch0st.medium.com/guide-to-named-pipes-and-hunting-for-cobalt-strike-pipes-dc46b2c5f575"
    reference = "https://docs.microsoft.com/en-us/dotnet/api/system.io.pipes.namedpipeserverstream?view=net-6.0"
    reference = "https://docs.microsoft.com/en-us/dotnet/api/system.io.pipes?view=net-6.0"
    DaysofYARA_day = "15/100"
  strings:
    $ = "PipeAccessRights" xor(0x01-0xff)
    $ = "PipeAccessRule" xor(0x01-0xff)
    $ = "PipeAuditRule" xor(0x01-0xff)
    $ = "PipeDirection" xor(0x01-0xff)
    $ = "PipeOptions" xor(0x01-0xff)
    $ = "PipesAclExtensions" xor(0x01-0xff)
    $ = "PipeSecurity" xor(0x01-0xff)
    $ = "PipeStream" xor(0x01-0xff)
    $ = "PipeStreamImpersonationWorker" xor(0x01-0xff)
    $ = "PipeTransmissionMode" xor(0x01-0xff)
  condition:
    1 of them
}

rule SUSP_Credstore_GUID_CryptUnprotectData
{
  meta:
    description = "check for references to the credstore GUID that can decrypt credential pairs with CryptUnprotectData import to decrypt them"
    reference = "https://vblocalhost.com/uploads/VB2021-50.pdf"
    reference = "https://twitter.com/gentilkiwi/status/1193139734240989184"
    DaysofYARA_day = "14/100"
  strings:
    $ = "abe2869f-9b47-4cd9-a358-c22904dba7f7" ascii wide
  condition:
    all of them and pe.imports("Crypt32.dll", "CryptUnprotectData")
}

rule SUSP_Credstore_GUID
{
  meta:
    description = "check for references to the credstore GUID that can decrypt credential pairs without CryptUnprotectData import to decrypt them"
    reference = "https://vblocalhost.com/uploads/VB2021-50.pdf"
    reference = "https://twitter.com/gentilkiwi/status/1193139734240989184"
    DaysofYARA_day = "14/100"
  strings:
    $ = "abe2869f-9b47-4cd9-a358-c22904dba7f7" ascii wide
  condition:
    all of them and not SUSP_Credstore_GUID_CryptUnprotectData
}

rule SUSP_ICMP_Imports
{
  meta:
    description = "looking for imports related to ICMP protocol usage!"
    DaysofYARA_day = "13/100"
  condition:
    pe.imports(/IPHLPAPI.dll/i, /Icmp/i)
}

rule SUSP_PE_Rsrc_PrevalentByte_Not_0
{
  meta:
    description = "using a forthcoming feature in math module, look for RCDATA resources where the most common byte (mode) is NOT zero. Plaintext PE's do have a mode of zero, so this might be a nice subsitution for measuring entropy"
    DaysofYARA_day = "12/100"
    WARNING = "REQUIRES YARA 4.2.0-rc1 !!"
  condition:
    for any resource in pe.resources:(
    resource.type == 10 and // ensure its RCDATA and not an icon
    resource.length > 300 and //check the length homie, not the size, to find things that might be encrypted payloads?
    math.mode(resource.offset, resource.length) != 0x0 //check if the most seen byte is not a zero, which is common for plaintext files
          )
}

rule SUSP_PE_Overlay_PrevalentByte_Not_0
{
  meta:
    description = "using a forthcoming feature in math module, look for PE overlays where the most common byte (mode) is NOT zero. Plaintext PE's do have a mode of zero, so this might be a nice subsitution for measuring entropy"
    DaysofYARA_day = "12/100"
    WARNING = "REQUIRES YARA 4.2.0-rc1 !!"
  condition:
    math.mode(pe.overlay.offset, pe.overlay.size) != 0x0 //check if the most seen byte is not a zero, which is common for plaintext files
    and pe.overlay.offset != 0x0 // make sure the overlay isn't at 0
    and pe.overlay.size > 300 // arbitrary size to find things that might be encrypted payloads?
}

rule SUSP_b64d_PE_at_Overlay
{
  meta:
    description = "looking for probable base64 encoded PE headers in the overlay of a PE!"
    DaysofYARA_day = "11/100"

  condition:
    pe.overlay.offset != 0x0 and
    uint32be(pe.overlay.offset) == 0x54567151 and  //byes are TVqQAAMAAAAEAAAA
    uint32be(pe.overlay.offset + 4) == 0x41414D41 //byes are TVqQAAMAAAAEAAAA

}

rule SUSP_b64d_PE_at_Rsrc
{
  meta:
    description = "looking for probable base64 encoded PE headers in the resources of a PE!"
    DaysofYARA_day = "11/100"

  condition:
    for any resource in pe.resources: (
      resource.type == 10 and //check that its a data resource
      uint32be(resource.offset) == 0x54567151 and //byes are TVqQAAMAAAAEAAAA
      uint32be(resource.offset + 4) == 0x41414D41
    )
}

rule SUSP_Single_Byte_XOR_Encoded_PE_rsrc
{ 
  meta:
    description = "inspired by Jesko (@huettenhain) and binary Refinery using the byte from position 3 as a XOR key to decode multiple executables. Typically that byte is zero, meaning in encoded form it will contain our XOR key! Unlike SUSP_XORd_PE_at_RSRC, this rule also catches a sample from WildNeutron/Morpho's toolset, dbb0ea0436f70f2a178a60c4d8b791b3 because it removed the !This Program string (same in the normal header). Final note that Morpho sample's PE in the resources is called BIN and id = 666 :thinking-emoji:"
    DaysofYARA_day = "10/100"
    reference = "https://www.youtube.com/watch?v=4gTaGfFyMK4&t=1189s&ab_channel=OALabs"
  condition:
    for any resource in pe.resources: (
    (uint8(resource.offset) ^ uint8(resource.offset + 3) == 0x4d and
    uint8(resource.offset+1) ^ uint8(resource.offset + 3) == 0x5a ) and
    uint16(resource.offset) != 0x5a4d )
}

rule SUSP_Single_Byte_XOR_Encoded_PE_overlay
{ 
  meta:
    description = "inspired by Jesko (@huettenhain) and binary Refinery using the byte from position 3 as a XOR key to decode multiple executables. Typically that byte is zero, meaning in encoded form it will contain our XOR key!"
    DaysofYARA_day = "10/100"
    reference = "https://www.youtube.com/watch?v=4gTaGfFyMK4&t=1189s&ab_channel=OALabs"
  condition:
    uint8(pe.overlay.offset) ^ uint8(pe.overlay.offset + 3) == 0x4d and
    uint8(pe.overlay.offset+1) ^ uint8(pe.overlay.offset + 3) == 0x5a and
    uint16(pe.overlay.offset) != 0x5a4d and pe.overlay.offset != 0x0
}

rule SUSP_Single_Byte_XOR_Encoded_PE
{ 
  meta:
    description = "inspired by Jesko (@huettenhain) and binary Refinery using the byte from position 3 as a XOR key to decode multiple executables. Typically that byte is zero, meaning in encoded form it will contain our XOR key! Less useful in YARA for looking directly at the files but a decent test for overlays and resources."
    DaysofYARA_day = "10/100"
    reference = "https://www.youtube.com/watch?v=4gTaGfFyMK4&t=1189s&ab_channel=OALabs"
  condition:
    uint8(0x0) ^ uint8(0x3) == 0x4d and
    uint8(0x1) ^ uint8(0x3) == 0x5a and
    uint16(0) != 0x5a4d
}


rule SUSP_XORd_PE_at_Overlay
{
  meta:
    description = "Another MZ header hunt xor'ing the first two bytes of the MZ header together (4d 5a) == 23 (0x17). This is probably a silly thing to do, as any number of other legit headers could have this, but theoretically any PE xor'd with a single byte key should keep this relationship between the first two bytes. We can also check that the first two bytes of !This Program cannot be ... (which are always 77 bytes into the PE) also have the same xor'd relationship within the overlay of the PE"
    DaysofYARA_day = "9/100"
    reference = "https://github.com/tillmannw/yara-rules/blob/main/xored_pefile_mini.yara"
  condition:
    uint8(pe.overlay.offset) ^ uint8(pe.overlay.offset + 1) == 0x17 and
    uint8(pe.overlay.offset + 0x4d) ^ uint8(pe.overlay.offset + 0x4e) == 0x75 and
    uint16(pe.overlay.offset) != 0x5a4d and
    pe.overlay.offset != 0x0
}

rule SUSP_XORd_PE_at_RSRC
{ 
  meta:
    description = "Another MZ header hunt xor'ing the first two bytes of the MZ header together (4d 5a) == 23 (0x17). This is probably a silly thing to do, as any number of other legit headers could have this, but theoretically any PE xor'd with a single byte key should keep this relationship between the first two bytes. We can also check that the first two bytes of !This Program cannot be ... (which are always 77 bytes into the PE) also have the same xor'd relationship within a resource of the PE"
    DaysofYARA_day = "9/100"
    reference = "https://github.com/tillmannw/yara-rules/blob/main/xored_pefile_mini.yara"
  condition:
    for any resource in pe.resources: (
    uint8(resource.offset) ^ uint8(resource.offset + 1) == 0x17 and
    uint8(resource.offset + 0x4d) ^ uint8(resource.offset + 0x4e) == 0x75 and
    uint16(resource.offset) != 0x5a4d )
}


rule SUSP_XORd_PE
{
  meta:
	description = "Another MZ header hunt xor'ing the first two bytes of the MZ header together (4d 5a) == 23 (0x17). This is probably a silly thing to do, as any number of other legit headers could have this, but theoretically any PE xor'd with a single byte key should keep this relationship between the first two bytes. We can also check that the first two bytes of !This Program cannot be ... (which are always 77 bytes into the PE) also have the same xor'd relationship"
	DaysofYARA_day = "8/100"
  condition:
	uint8(0x0) ^ uint8(0x1) == 0x17 and
 	uint8(0x4d) ^ uint8(0x4e) == 0x75 and
	uint16(0) != 0x5a4d
}


rule SUSP_space_in_section_name
{
  meta:
    description = "look for a space character in a section name (which is pretty unusual)"
    DaysofYARA_day = "7/100"
  condition:
    for any section in pe.sections: (section.name contains " ")
}

rule SUSP_PE_at_Overlay
{ 
  meta:
	description = "check for an additional PE header found at the overlay offset"
        reference_inspiration = "https://twitter.com/notareverser/status/1477661404085866500"
        DaysofYARA_day = "6/100"
	version = "1.0"
  condition:
        uint16be(pe.overlay.offset) == 0x4d5a //check for the MZ header at the overlay offset, using BE for ease of reading
        and pe.overlay.offset != 0x0 //check that the overlay doesn't start at 0x0
}

rule Example_Overlay_Offsets
{
  meta:
    description = "if two files have the same offset & sizes for odd attributes, methinks might be decent detection! in this case, the shellcode in the overlay changed, but the size and offset were identical so hashing the whole overlay only caught one of the samples "
    DaysofYARA_day = "5/100"
    hash = "300519fa1af5c36371ab438405eb641f184bd2f491bdf24f04e5ca9b86d1b39c"
    hash = "db866ef07dc1f2e1df1e6542323bc672dd245d88c0ee91ce0bd3da2c95aedf68"
  condition:
    pe.overlay.size == 16957 and
    pe.overlay.offset == 99328
}

rule Example_ExpHash
{
  meta:
    description = "yara can hash any part of a file. this is a dumb attempt to hash the export table (like imphash). I don't think the export address table is a PERFECT measure or detection but if the DLL name and export names are the same, we can roll them into a single measure (even though its probably more lines of condition than just looking for both features. I failed a bunch of times trying stuff like for any dir in pe.data_directories: (hash.md5(dir.virtual_address, dir.size) == \"c8789e010163226dc559d4ffed4301c1\" or hash.md5(pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_EXPORT].virtual_address, pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_EXPORT].size) == \"c8789e010163226dc559d4ffed4301c1\" until an old Steve Miller tweet (and guidance from @xorhex) helped me realize I need to use rva_to_offset. For complete transparency, I tried to hash every single 68 byte chunk around this sample's export table and spent 5-6 hours bashing my head against the wall (don't worry boss this was a weekend thing). Don't give up! "
    DaysofYARA_day = "4/100"
    version = "1.1"
    update = "cleaned up with guidance from Adrien and Wes"
    reference = "https://gist.github.com/stvemillertime/6abaab1146c9b71e486c24113cd47304"
    hash = "2a5788d0c609f5dbefeb9f0538c0e4a53ef1f9f1e757ed5bd7b338554c09baef"
    hash = "521533fe8439f70f3e4446312df30bec85326767b02f76af4bec39b251e15c81"
  condition:
    hash.md5(
	pe.rva_to_offset(
		pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_EXPORT].virtual_address),        // use the offset of our directory
		pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_EXPORT].size)  //as Adrien pointed out, don't need this offset, just using its size field as the length to hash
		== "c8789e010163226dc559d4ffed4301c1" 
  //  hash.md5(0x55c0,0x44) == "c8789e010163226dc559d4ffed4301c1" also catches this bull
}

rule Export_Table_VirtualAddress
{
  meta:
    description = "malware families can share odd things, including the virtual address of the export table! Partly highlighting this so that there is a record of its usage publicly"
    DaysofYARA_day = "3/100"
    hash = "2a5788d0c609f5dbefeb9f0538c0e4a53ef1f9f1e757ed5bd7b338554c09baef"
    hash = "521533fe8439f70f3e4446312df30bec85326767b02f76af4bec39b251e15c81"
  condition:
    pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_EXPORT].virtual_address == 28096
}

rule SUSP_Very_High_Entropy_Text_Section
{
  meta:
    description = "check for a section of the PE called .text that has a very high entropy. Why .text? It is commonly the section where code is stored"
    DaysofYARA_day = "2/100"
  condition:
    for any var_sect in pe.sections: ( //iterate across all of the sections of the PE and for each one (we're using variable named var_sect to make it clear)
	var_sect.name == ".text" //check that the name equals .text
	and
	math.in_range( //set a range
		math.entropy( //calculate entropy
		var_sect.raw_data_offset, var_sect.raw_data_size), // between the start (offset) of the section
		7.8, 8.0) //entropy caps at 8, so lets set a value close to that
		)
}

rule MZ_Header_MD5_Hash
{
  meta:
    description = "yara can hash any part of a file. md5 of 1st two bytes of PE file (4d 5a) == ac6ad5d9b99757c3a878f2d275ace198. This rule checks for that hash in first 2 bytes. This is effectively the same as using uint16(0) == 0x5a4d"
    DaysofYARA_day = "1/100"
  condition:
    hash.md5(0,2) == "ac6ad5d9b99757c3a878f2d275ace198"
}
