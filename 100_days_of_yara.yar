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
