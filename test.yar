rule APT_NK_Andariel_DTrack_Unpacked_floss2yar_fcn_004e1ee0 {
meta:
	author = "Greg Lesnewich"
	date = "2022-10-04"
	version = "1.0"
	hash = "c17ab2c713ac2315a75412454be6ecddfb9ef39dbc629f73799bbfe154f6f381"

strings:
	$fcn_004e1ee0 = {55 8B EC 83 EC 0C 8B 45 18 89 45 F8 C7 45 FC ?? ?? ?? ?? EB ?? 8B 4D FC 83 C1 01 89 4D FC 8B 55 FC 3B 55 14 7D ?? 8B 45 F8 C1 E8 08 8B 4D F8 C1 E9 02 33 4D F8 8B 55 F8 C1 EA 03 33 CA 8B 55 F8 C1 EA 07 33 CA C1 E1 18 0B C1 03 45 F8 89 45 F8 8B 45 10 03 45 FC 8A 4D F8 88 08 EB ?? C7 45 FC ?? ?? ?? ?? EB ?? 8B 55 FC 83 C2 01 89 55 FC 8B 45 FC 3B 45 0C 0F 8D ?? ?? ?? ?? 8B 4D 08 03 4D FC 0F B6 11 03 55 F8 89 55 F8 C7 45 F4 ?? ?? ?? ?? EB ?? 8B 45 F4 83 C0 01 89 45 F4 83 7D F4 20 7D ?? 8B 4D F8 C1 E9 08 8B 55 F8 C1 EA 02 33 55 F8 8B 45 F8 C1 E8 03 33 D0 8B 45 F8 C1 E8 07 33 D0 C1 E2 18 0B CA 03 4D F8 89 4D F8 EB ?? C7 45 F4 ?? ?? ?? ?? EB ?? 8B 4D F4 83 C1 01 89 4D F4 8B 55 F4 3B 55 14 7D ?? 8B 45 F8 C1 E8 08 8B 4D F8 C1 E9 02 33 4D F8 8B 55 F8 C1 EA 03 33 CA 8B 55 F8 C1 EA 07 33 CA C1 E1 18 0B C1 03 45 F8 89 45 F8 0F B6 45 F8 8B 4D 10 03 4D F4 0F B6 11 03 D0 8B 45 10 03 45 F4 88 10 EB ?? E9 ?? ?? ?? ?? 8B E5 5D C3}
 /*
            ; CALL XREFS from fcn.004e3a40 @ 0x4e40b4, 0x4e44a5
            ; CALL XREF from fcn.004e4930 @ 0x4e4aec
            ; CALL XREF from fcn.004e6aa0 @ 0x4e706e
┌ fcn.004e1ee0 (LPSTR arg_8h, int32_t arg_ch, int32_t arg_10h, int32_t arg_14h, int32_t arg_18h);
│           ; var int32_t var_ch  { } @ ebp-0xc
│           ; var int32_t var_8h @ ebp-0x8
│           ; var int32_t var_4h @ ebp-0x4
│           ; arg LPSTR arg_8h @ ebp+0x8
│           ; arg int32_t arg_ch  { } @ ebp+0xc
│           ; arg int32_t arg_10h @ ebp+0x10
│           ; arg int32_t arg_14h  { } @ ebp+0x14
│           ; arg int32_t arg_18h @ ebp+0x18
│           0x004e1ee0      55             push  ebp
│           0x004e1ee1      8bec           mov   ebp, esp
│           0x004e1ee3      83ec0c         sub   esp, 0xc
│           0x004e1ee6      8b4518         mov   eax, dword [arg_18h]
│           0x004e1ee9      8945f8         mov   dword [var_8h], eax
│           0x004e1eec      c745fc000000.  mov   dword [var_4h], 0
│       ┌─< 0x004e1ef3      eb09           jmp   0x4e1efe
│       │   ; CODE XREF from fcn.004e1ee0 @ 0x4e1f3b
│      ┌──> 0x004e1ef5      8b4dfc         mov   ecx, dword [var_4h]
│      ╎│   0x004e1ef8      83c101         add   ecx, 1
│      ╎│   0x004e1efb      894dfc         mov   dword [var_4h], ecx
│      ╎│   ; CODE XREF from fcn.004e1ee0 @ 0x4e1ef3
│      ╎└─> 0x004e1efe      8b55fc         mov   edx, dword [var_4h]
│      ╎    0x004e1f01      3b5514         cmp   edx, dword [arg_14h]
│      ╎┌─< 0x004e1f04      7d37           jge   0x4e1f3d
│      ╎│   0x004e1f06      8b45f8         mov   eax, dword [var_8h]
│      ╎│   0x004e1f09      c1e808         shr   eax, 8
│      ╎│   0x004e1f0c      8b4df8         mov   ecx, dword [var_8h]
│      ╎│   0x004e1f0f      c1e902         shr   ecx, 2
│      ╎│   0x004e1f12      334df8         xor   ecx, dword [var_8h]
│      ╎│   0x004e1f15      8b55f8         mov   edx, dword [var_8h]
│      ╎│   0x004e1f18      c1ea03         shr   edx, 3
│      ╎│   0x004e1f1b      33ca           xor   ecx, edx
│      ╎│   0x004e1f1d      8b55f8         mov   edx, dword [var_8h]
│      ╎│   0x004e1f20      c1ea07         shr   edx, 7
│      ╎│   0x004e1f23      33ca           xor   ecx, edx
│      ╎│   0x004e1f25      c1e118         shl   ecx, 0x18
│      ╎│   0x004e1f28      0bc1           or    eax, ecx
│      ╎│   0x004e1f2a      0345f8         add   eax, dword [var_8h]
│      ╎│   0x004e1f2d      8945f8         mov   dword [var_8h], eax
│      ╎│   0x004e1f30      8b4510         mov   eax, dword [arg_10h]
│      ╎│   0x004e1f33      0345fc         add   eax, dword [var_4h]
│      ╎│   0x004e1f36      8a4df8         mov   cl, byte [var_8h]
│      ╎│   0x004e1f39      8808           mov   byte [eax], cl
│      └──< 0x004e1f3b      ebb8           jmp   0x4e1ef5
│       └─> 0x004e1f3d      c745fc000000.  mov   dword [var_4h], 0
│       ┌─< 0x004e1f44      eb09           jmp   0x4e1f4f
│       │   ; CODE XREF from fcn.004e1ee0 @ 0x4e200b
│      ┌──> 0x004e1f46      8b55fc         mov   edx, dword [var_4h]
│      ╎│   0x004e1f49      83c201         add   edx, 1
│      ╎│   0x004e1f4c      8955fc         mov   dword [var_4h], edx
│      ╎│   ; CODE XREF from fcn.004e1ee0 @ 0x4e1f44
│      ╎└─> 0x004e1f4f      8b45fc         mov   eax, dword [var_4h]
│      ╎    0x004e1f52      3b450c         cmp   eax, dword [arg_ch]
│      ╎┌─< 0x004e1f55      0f8db5000000   jge   0x4e2010
│      ╎│   0x004e1f5b      8b4d08         mov   ecx, dword [arg_8h]
│      ╎│   0x004e1f5e      034dfc         add   ecx, dword [var_4h]
│      ╎│   0x004e1f61      0fb611         movzx edx, byte [ecx]
│      ╎│   0x004e1f64      0355f8         add   edx, dword [var_8h]
│      ╎│   0x004e1f67      8955f8         mov   dword [var_8h], edx
│      ╎│   0x004e1f6a      c745f4000000.  mov   dword [var_ch], 0
│     ┌───< 0x004e1f71      eb09           jmp   0x4e1f7c
│     │╎│   ; CODE XREF from fcn.004e1ee0 @ 0x4e1fac
│    ┌────> 0x004e1f73      8b45f4         mov   eax, dword [var_ch]
│    ╎│╎│   0x004e1f76      83c001         add   eax, 1
│    ╎│╎│   0x004e1f79      8945f4         mov   dword [var_ch], eax
│    ╎│╎│   ; CODE XREF from fcn.004e1ee0 @ 0x4e1f71
│    ╎└───> 0x004e1f7c      837df420       cmp   dword [var_ch], 0x20
│    ╎┌───< 0x004e1f80      7d2c           jge   0x4e1fae
│    ╎│╎│   0x004e1f82      8b4df8         mov   ecx, dword [var_8h]
│    ╎│╎│   0x004e1f85      c1e908         shr   ecx, 8
│    ╎│╎│   0x004e1f88      8b55f8         mov   edx, dword [var_8h]
│    ╎│╎│   0x004e1f8b      c1ea02         shr   edx, 2
│    ╎│╎│   0x004e1f8e      3355f8         xor   edx, dword [var_8h]
│    ╎│╎│   0x004e1f91      8b45f8         mov   eax, dword [var_8h]
│    ╎│╎│   0x004e1f94      c1e803         shr   eax, 3
│    ╎│╎│   0x004e1f97      33d0           xor   edx, eax
│    ╎│╎│   0x004e1f99      8b45f8         mov   eax, dword [var_8h]
│    ╎│╎│   0x004e1f9c      c1e807         shr   eax, 7
│    ╎│╎│   0x004e1f9f      33d0           xor   edx, eax
│    ╎│╎│   0x004e1fa1      c1e218         shl   edx, 0x18
│    ╎│╎│   0x004e1fa4      0bca           or    ecx, edx
│    ╎│╎│   0x004e1fa6      034df8         add   ecx, dword [var_8h]
│    ╎│╎│   0x004e1fa9      894df8         mov   dword [var_8h], ecx
│    └────< 0x004e1fac      ebc5           jmp   0x4e1f73
│     └───> 0x004e1fae      c745f4000000.  mov   dword [var_ch], 0
│     ┌───< 0x004e1fb5      eb09           jmp   0x4e1fc0
│     │╎│   ; CODE XREF from fcn.004e1ee0 @ 0x4e2009
│    ┌────> 0x004e1fb7      8b4df4         mov   ecx, dword [var_ch]
│    ╎│╎│   0x004e1fba      83c101         add   ecx, 1
│    ╎│╎│   0x004e1fbd      894df4         mov   dword [var_ch], ecx
│    ╎│╎│   ; CODE XREF from fcn.004e1ee0 @ 0x4e1fb5
│    ╎└───> 0x004e1fc0      8b55f4         mov   edx, dword [var_ch]
│    ╎ ╎│   0x004e1fc3      3b5514         cmp   edx, dword [arg_14h]
│    ╎┌───< 0x004e1fc6      7d43           jge   0x4e200b
│    ╎│╎│   0x004e1fc8      8b45f8         mov   eax, dword [var_8h]
│    ╎│╎│   0x004e1fcb      c1e808         shr   eax, 8
│    ╎│╎│   0x004e1fce      8b4df8         mov   ecx, dword [var_8h]
│    ╎│╎│   0x004e1fd1      c1e902         shr   ecx, 2
│    ╎│╎│   0x004e1fd4      334df8         xor   ecx, dword [var_8h]
│    ╎│╎│   0x004e1fd7      8b55f8         mov   edx, dword [var_8h]
│    ╎│╎│   0x004e1fda      c1ea03         shr   edx, 3
│    ╎│╎│   0x004e1fdd      33ca           xor   ecx, edx
│    ╎│╎│   0x004e1fdf      8b55f8         mov   edx, dword [var_8h]
│    ╎│╎│   0x004e1fe2      c1ea07         shr   edx, 7
│    ╎│╎│   0x004e1fe5      33ca           xor   ecx, edx
│    ╎│╎│   0x004e1fe7      c1e118         shl   ecx, 0x18
│    ╎│╎│   0x004e1fea      0bc1           or    eax, ecx
│    ╎│╎│   0x004e1fec      0345f8         add   eax, dword [var_8h]
│    ╎│╎│   0x004e1fef      8945f8         mov   dword [var_8h], eax
│    ╎│╎│   0x004e1ff2      0fb645f8       movzx eax, byte [var_8h]
│    ╎│╎│   0x004e1ff6      8b4d10         mov   ecx, dword [arg_10h]
│    ╎│╎│   0x004e1ff9      034df4         add   ecx, dword [var_ch]
│    ╎│╎│   0x004e1ffc      0fb611         movzx edx, byte [ecx]
│    ╎│╎│   0x004e1fff      03d0           add   edx, eax
│    ╎│╎│   0x004e2001      8b4510         mov   eax, dword [arg_10h]
│    ╎│╎│   0x004e2004      0345f4         add   eax, dword [var_ch]
│    ╎│╎│   0x004e2007      8810           mov   byte [eax], dl
│    └────< 0x004e2009      ebac           jmp   0x4e1fb7
│     └└──< 0x004e200b      e936ffffff     jmp   0x4e1f46
│       └─> 0x004e2010      8be5           mov   esp, ebp
│           0x004e2012      5d             pop   ebp
└           0x004e2013      c3             ret

 */
condition:
	1 of them
}
