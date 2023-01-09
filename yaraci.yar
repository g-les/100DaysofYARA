rule yara_ci_test
{
		meta:
				author = "Greg Lesnewich"
				description = ""
				date = ""
				version = "1.0"
				hash = ""

		strings:
				$ = "baddomain" ascii wide
		condition:
				uint16(0) == 0x5a4d and all of them
}
