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

rule SUSP_PE_at_Overlay
{ meta:
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
