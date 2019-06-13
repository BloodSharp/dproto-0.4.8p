#include "osconfig.h"
#include "dproto.h"
#include "cfg.h"
#include "dynpatcher_base.h"
#include "dynparser_linux.h"
#include "engine_data.h"

bool Parse_BaseFunctions() {
	if (!FindSymbol(DSEngineData.hLib, "Q_strcpy", &DSEngineData.Q_strcpy_addr)) return false;
	if (!FindSymbol(DSEngineData.hLib, "SV_ParseCvarValue2", &DSEngineData.SV_ParseCvarValue2_addr)) return false;
	if (!FindSymbol(DSEngineData.hLib, "SV_ConnectClient", &DSEngineData.SV_ConnectClient_addr)) return false;
	if (!FindSymbol(DSEngineData.hLib, "MSG_WriteLong", &DSEngineData.MSG_WriteLong_addr)) return false;
	if (!FindSymbol(DSEngineData.hLib, "SV_RejectConnection", &DSEngineData.SV_RejectConnection_addr)) return false;
	if (!FindSymbol(DSEngineData.hLib, "SV_CheckUserInfo", &DSEngineData.SV_CheckUserInfo_addr)) return false;
	if (!FindSymbol(DSEngineData.hLib, "SV_SendServerinfo", &DSEngineData.SV_SendServerInfo_addr)) return false;
	if (!FindSymbol(DSEngineData.hLib, "SV_ReadPackets", &DSEngineData.SV_ReadPackets_addr)) return false;
	if (!FindSymbol(DSEngineData.hLib, "Info_ValueForKey", &DSEngineData.Info_ValueForKey_addr)) return false;
	if (!FindSymbol(DSEngineData.hLib, "Steam_NotifyClientConnect", &DSEngineData.Steam_NotifyClientConnect_addr)) return false;
	if (!FindSymbol(DSEngineData.hLib, "SV_ConnectionlessPacket", &DSEngineData.SV_ConnectionlessPacket_addr)) return false;
	if (!FindSymbol(DSEngineData.hLib, "NET_SendPacket", &DSEngineData.NET_SendPacket_addr)) return false;
	if (!FindSymbol(DSEngineData.hLib, "SVC_GetChallenge", &DSEngineData.SVC_GetChallenge_addr)) return false;
	if (!FindSymbol(DSEngineData.hLib, "OnGSClientDenyHelper__13CSteam3ServerP8client_s11EDenyReasonPCc", &DSEngineData.GSClientDenyHelper_addr)) return false;
	if (!FindSymbol(DSEngineData.hLib, "net_from", &DSEngineData.net_from_addr)) return false;
	if (!FindSymbol(DSEngineData.hLib, "SV_CheckTimeouts", &DSEngineData.SV_CheckTimeouts_addr)) return false;
	if (!FindSymbol(DSEngineData.hLib, "SV_GetIDString", &DSEngineData.SV_GetIDString_addr)) return false;
	if (!FindSymbol(DSEngineData.hLib, "SV_GetClientIDString", &DSEngineData.SV_GetClientIDString_addr)) return false;
	if (!FindSymbol(DSEngineData.hLib, "Host_Error", &DSEngineData.Host_Error_addr)) return false;
	if (!FindSymbol(DSEngineData.hLib, "SV_ParseVoiceData", &DSEngineData.SV_ParseVoiceData_addr)) return false;
	if (!FindSymbol(DSEngineData.hLib, "Netchan_CreateFragments_", &DSEngineData.Netchan_CreateFragments__addr)) return false;
	if (!FindSymbol(DSEngineData.hLib, "SV_CheckKeyInfo", &DSEngineData.SV_CheckKeyInfo_addr)) return false;
	
	
	
	
	
	return true;
}

bool Parse_Jumps() {
	if (!Dll_FindJumpToFunc(&GenericEngineData, DSEngineData.SV_RejectConnection_addr, NULL, &DSEngineData.SV_RejectConnection_jaddr)) {
		LCPrintf(true, "[DPROTO]: %s: ERROR: JMP for SV_RejectConnection() not found\n", __FUNCTION__);
		return false;
	}

	if (!Dll_FindJumpToFunc(&GenericEngineData, DSEngineData.MSG_WriteLong_addr, NULL, &DSEngineData.MSG_WriteLong_jaddr)) {
		LCPrintf(true, "[DPROTO]: %s: ERROR: JMP for MSG_WriteLong() not found\n", __FUNCTION__);
		return false;
	}

	if (!Dll_FindJumpToFunc(&GenericEngineData, DSEngineData.Q_strcpy_addr, NULL, &DSEngineData.Q_strcpy_jaddr)) return false;
	if (!Dll_FindJumpToFunc(&GenericEngineData, DSEngineData.SV_CheckUserInfo_addr, NULL, &DSEngineData.SV_CheckUserInfo_jaddr)) return false;
	if (!Dll_FindJumpToFunc(&GenericEngineData, DSEngineData.Info_ValueForKey_addr, NULL, &DSEngineData.Info_ValueForKey_jaddr)) return false;
	if (!Dll_FindJumpToFunc(&GenericEngineData, DSEngineData.Steam_NotifyClientConnect_addr, NULL, &DSEngineData.Steam_NotifyClientConnect_jaddr)) return false;
	if (!Dll_FindJumpToFunc(&GenericEngineData, DSEngineData.SV_ConnectionlessPacket_addr, NULL, &DSEngineData.SV_ConnectionlessPacket_jaddr)) return false;
	if (!Dll_FindJumpToFunc(&GenericEngineData, DSEngineData.NET_SendPacket_addr, NULL, &DSEngineData.NET_SendPacket_jaddr)) return false;
	if (!Dll_FindJumpToFunc(&GenericEngineData, DSEngineData.SVC_GetChallenge_addr, NULL, &DSEngineData.SVC_GetChallenge_jaddr)) return false;
	if (!Dll_FindJumpToFunc(&GenericEngineData, DSEngineData.GSClientDenyHelper_addr, NULL, &DSEngineData.GSClientDenyHelper_jaddr)) return false;
	if (!Dll_FindJumpToFunc(&GenericEngineData, DSEngineData.Host_Error_addr, NULL, &DSEngineData.Host_Error_jaddr)) return false;
	if (!Dll_FindJumpToFunc(&GenericEngineData, DSEngineData.Netchan_CreateFragments__addr, NULL, &DSEngineData.Netchan_CreateFragments__jaddr)) return false;
	if (!Dll_FindJumpToFunc(&GenericEngineData, DSEngineData.SV_CheckKeyInfo_addr, NULL, &DSEngineData.SV_CheckKeyInfo_jaddr)) return false;
	
	
	

	return true;
}

bool Parse_ConnectClient() {
	uint32_t coderef_addr;
	uint32_t coderef2_addr;
	uint32_t coderef3_addr;
	uint32_t coderef4_addr;
	uint32_t cstring_addr;
	uint32_t tmp;
	bool bIsOk;
	/* Search for the protocol checking code:
			83FE 30	cmp     esi, 30h
			74 ??	jz      ????
	*/

	const char ScanData[] = "\x83\xFE\x30\x74";
	const char ScanMask[] = "\xFF\xFF\xFF\xFF";
	coderef_addr = DSEngineData.SV_ConnectClient_addr;
	coderef2_addr = Dll_ScanForTemplate_Forward(&GenericEngineData, (unsigned char*) ScanData,(unsigned char*) ScanMask, sizeof(ScanMask) - 1, coderef_addr, 0x100);
	if (!coderef2_addr) {
		LCPrintf(true, "[DPROTO]: %s: parsing error: protocol checking code not found\n", __FUNCTION__);
		return false;
	}
	coderef2_addr += 3;
	tmp = *((uint8_t*) (coderef2_addr + 1)) + coderef2_addr + 2;
	DSEngineData.CheckProto_GoodRet_addr = tmp;
	DSEngineData.CheckProto_haddr = coderef2_addr;

	coderef_addr = coderef2_addr;

	/* Search forward for the SV_RejectConnection() call
			E8 ???????? call _SV_RejectConnection
	*/
	const char ScanData2[] = "\xE8\x00\x00\x00\x00";
	const char ScanMask2[] = "\xFF\x00\x00\x00\x00";
	bIsOk = false;
	coderef2_addr = Dll_ScanForTemplate_Forward(&GenericEngineData, (unsigned char*) ScanData2, (unsigned char*) ScanMask2, sizeof(ScanMask2) - 1, coderef2_addr, 0x60);
	while (coderef2_addr && (coderef2_addr - coderef_addr < 0x60)) {
		tmp = *((uint32_t*) (coderef2_addr + 1)) + coderef2_addr + 5;
		if (tmp == DSEngineData.SV_RejectConnection_jaddr || tmp == DSEngineData.SV_RejectConnection_addr) {
			bIsOk = true;
			break;
		}
		coderef2_addr = Dll_ScanForTemplate_Forward(&GenericEngineData, (unsigned char*) ScanData2, (unsigned char*) ScanMask2, sizeof(ScanMask2) - 1, coderef2_addr+1, 0x60);
	}

	if (!bIsOk) {
		LCPrintf(true, "[DPROTO]: %s: parsing error: protocol checking analyzing error\n", __FUNCTION__);
		return false;
	}

	/* Now search forward for long jmp instruction (used when protocol checking failed)
		E9 ????0000 jmp 0000????
	*/
	const char ScanData3[] = "\xE9\x00\x00\x00\x00";
	const char ScanMask3[] = "\xFF\x00\x00\xFF\xFF";
	coderef2_addr = Dll_ScanForTemplate_Forward(&GenericEngineData, (unsigned char*) ScanData3, (unsigned char*) ScanMask3, sizeof(ScanMask3) - 1, coderef2_addr, 0x20);
	if (!coderef2_addr) {
		LCPrintf(true, "[DPROTO]: %s: parsing error: protocol checking analyzing error (1)\n", __FUNCTION__);
		return false;
	}
	tmp = *((uint32_t*) (coderef2_addr + 1)) + coderef2_addr + 5;
	DSEngineData.CheckProto_BadRet_addr = tmp;


	/*	Process inlined SV_CheckCDKey()
		Search for the SV_CheckUserInfo() call
	*/

	// const char ScanData2[] = "\xE8\x00\x00\x00\x00"; //already defined
	// const char ScanMask2[] = "\xFF\x00\x00\x00\x00";
	bIsOk = false;
	coderef2_addr = DSEngineData.SV_ConnectClient_addr;
	coderef2_addr = Dll_ScanForTemplate_Forward(&GenericEngineData, (unsigned char*) ScanData2, (unsigned char*) ScanMask2, sizeof(ScanMask2) - 1, coderef2_addr, 0x600);
	while (coderef2_addr && (coderef2_addr - DSEngineData.SV_ConnectClient_addr < 0x600)) {
		tmp = *((uint32_t*) (coderef2_addr + 1)) + coderef2_addr + 5;
		if (tmp == DSEngineData.SV_CheckUserInfo_jaddr || tmp == DSEngineData.SV_CheckUserInfo_addr) {
			bIsOk = true;
			break;
		}
		coderef2_addr = Dll_ScanForTemplate_Forward(&GenericEngineData, (unsigned char*) ScanData2, (unsigned char*) ScanMask2, sizeof(ScanMask2) - 1, coderef2_addr+1, 0x600);
	}

	if (!bIsOk) {
		LCPrintf(true, "[DPROTO]: %s: parsing error: cdkey checking code analyzing error (2)\n", __FUNCTION__);
		return false;
	}

	/*	search for authproto comparsion instruction:
			83BD 88F1FFFF 02	cmp [ebp-???], 2
	*/

	const char ScanData4[] = "\x83\xBD\x00\x00\x00\x00\x02";
	const char ScanMask4[] = "\xFF\xFF\x00\x00\x00\x00\xFF";
	coderef2_addr = Dll_ScanForTemplate_Forward(&GenericEngineData, (unsigned char*) ScanData4, (unsigned char*) ScanMask4, sizeof(ScanMask4) - 1, coderef2_addr, 0x30);
	if (!coderef2_addr) {
		LCPrintf(true, "[DPROTO]: %s: parsing error: cdkey checking code analyzing error (3)\n", __FUNCTION__);
		return false;
	}

	DSEngineData.CheckCDKey_haddr = coderef2_addr;
	DSEngineData.ConnectClient_AuthProto_soff = *((uint32_t*) (coderef2_addr + 2));

	/* Search for authtype comparsion result with "steam"
						strcasecmp(authtype, "steam");
		 85C0			test eax, eax
		 0F84 ????0000  jz 0000????
	*/

	const char ScanData5[] = "\x85\xC0\x0F\x84\x00\x00\x00\x00";
	const char ScanMask5[] = "\xFF\xFF\xFF\xFF\x00\x00\xFF\xFF";
	coderef2_addr = Dll_ScanForTemplate_Forward(&GenericEngineData, (unsigned char*) ScanData5, (unsigned char*) ScanMask5, sizeof(ScanMask5) - 1, coderef2_addr+1, 0x50);
	if (!coderef2_addr) {
		LCPrintf(true, "[DPROTO]: %s: parsing error: cdkey checking code analyzing error (4)\n", __FUNCTION__);
		return false;
	}
	coderef2_addr += 2;
	tmp = *((uint32_t*) (coderef2_addr + 2)) + coderef2_addr + 6;
	DSEngineData.CheckCDKey_GoodRet_addr = tmp;

	/* Process validation checking */

	/* search for "lea esi, [ebp+var_CdKey]" instruction
			8DB? ????????	lea ???, [ebp+????]
	*/

	const char ScanData9[] = "\x8D\x80\x00\x00\xFF\xFF";
	const char ScanMask9[] = "\xFF\x80\x00\x00\xFF\xFF";
	
	coderef3_addr = Dll_ScanForTemplate_Backward(&GenericEngineData, (unsigned char*) ScanData9, (unsigned char*) ScanMask9, sizeof(ScanMask9) - 1, coderef2_addr, 0x50);
	if (!coderef3_addr) {
		LCPrintf(true, "[DPROTO]: %s: parsing error: cdkey checking code analyzing error (5)\n", __FUNCTION__);
		return false;
	}
	DSEngineData.ConnectClient_CDKey_soff = *((uint32_t*) (coderef3_addr + 2));

	
	/* Search for reference to "Invalid validation type\n" string */

	char ScanData6[] = "\x8D\x00\x00\x00\x00\x00";
	const char ScanMask6[] = "\xFF\x00\xFF\xFF\xFF\xFF";
	bIsOk = false;

	cstring_addr = Dll_FindString(&GenericEngineData, 0, "Invalid validation type\n", true);
	while (cstring_addr) {
		tmp = cstring_addr - GenericEngineData.GlobalsBase;
		memcpy(ScanData6+2, &tmp, 4);
		coderef_addr = Dll_ScanForTemplate_Forward(&GenericEngineData, (unsigned char*) ScanData6, (unsigned char*) ScanMask6, sizeof(ScanMask6) - 1, DSEngineData.SV_ConnectClient_addr, 0x1000);
		if (coderef_addr) {
			bIsOk = true;
			break;
		}
		cstring_addr = Dll_FindString(&GenericEngineData, cstring_addr, "Invalid validation type\n", true);
	}

	if (!bIsOk) {
		LCPrintf(true, "[DPROTO]: %s: parsing error: validation checking code not found\n", __FUNCTION__);
		return false;
	}

	/* Scan back for the Info_ValueForKey() call */

	// const char ScanData2[] = "\xE8\x00\x00\x00\x00"; //already defined
	// const char ScanMask2[] = "\xFF\x00\x00\x00\x00";
	bIsOk = false;
	coderef2_addr = coderef_addr;
	coderef2_addr = Dll_ScanForTemplate_Backward(&GenericEngineData, (unsigned char*) ScanData2, (unsigned char*) ScanMask2, sizeof(ScanMask2) - 1, coderef2_addr, 0x100);
	while (coderef2_addr && (coderef_addr - coderef2_addr < 0x100)) {
		tmp = *((uint32_t*) (coderef2_addr + 1)) + coderef2_addr + 5;
		if (tmp == DSEngineData.Info_ValueForKey_jaddr || tmp == DSEngineData.Info_ValueForKey_addr) {
			bIsOk = true;
			break;
		}
		coderef2_addr = Dll_ScanForTemplate_Backward(&GenericEngineData, (unsigned char*) ScanData2, (unsigned char*) ScanMask2, sizeof(ScanMask2) - 1, coderef2_addr-1, 0x100);
	}

	if (!bIsOk) {
		LCPrintf(true, "[DPROTO]: %s: parsing error: validation checking code analyzing error (1)\n", __FUNCTION__);
		return false;
	}

	/* search forward for "test eax, eax" instruction:
			85C0	test    eax, eax
			74 ??	jz      short loc_6B7DC
	*/

	const char ScanData7[] = "\x85\xC0\x74";
	const char ScanMask7[] = "\xFF\xFF\xFF";

	coderef3_addr = Dll_ScanForTemplate_Forward(&GenericEngineData, (unsigned char*) ScanData7, (unsigned char*) ScanMask7, sizeof(ScanMask7) - 1, coderef2_addr, 0x30);
	if (!coderef3_addr) {
		LCPrintf(true, "[DPROTO]: %s: parsing error: validation checking code analyzing error (2)\n", __FUNCTION__);
		return false;
	}

	DSEngineData.ValidationChecking_haddr = coderef3_addr; //save it temporary

	/* search forward for "cmp eax, 1" instruction:
			83F8 01		cmp eax, 1
			74 ??		jz ??
	*/

	const char ScanData8[] = "\x83\xF8\x01\x74";
	const char ScanMask8[] = "\xFF\xFF\xFF\xFF";

	coderef3_addr = Dll_ScanForTemplate_Forward(&GenericEngineData, (unsigned char*) ScanData8, (unsigned char*) ScanMask8, sizeof(ScanMask8) - 1, coderef3_addr, 0x50);
	if (!coderef3_addr) {
		LCPrintf(true, "[DPROTO]: %s: parsing error: validation checking code analyzing error (3)\n", __FUNCTION__);
		return false;
	}

	coderef3_addr += 3;
	tmp = *((uint8_t*) (coderef3_addr + 1)) + coderef3_addr + 2;
	DSEngineData.ValidationChecking_GoodRet_addr = tmp;

	/*	now search backward for the authproto comparsion code:
			83F? 02	cmp     eax, 2 
	*/
			
	coderef2_addr = DSEngineData.ValidationChecking_haddr;
	bIsOk = false;
	const char ScanData12[] = "\x83\xF8\x02";
	const char ScanMask12[] = "\xFF\xF0\xFF";
	tmp = Dll_ScanForTemplate_Backward(&GenericEngineData, (unsigned char*) ScanData12,(unsigned char*) ScanMask12, sizeof(ScanMask12) - 1, coderef2_addr, 0x50);
	if (tmp) {
		bIsOk = true;
		DSEngineData.ValidationChecking_haddr = tmp; //will install JMP there
	}

	if (!bIsOk) {
		LCPrintf(true, "[DPROTO]: %s: parsing error: validation checking code analyzing error (4)\n", __FUNCTION__);
		return false;
	}


	/*  ========================================== */
	/*	Process Steam validation checking code.
		Search for the Steam_NotifyClientConnect() call
	*/

	// const char ScanData2[] = "\xE8\x00\x00\x00\x00"; //already defined
	// const char ScanMask2[] = "\xFF\x00\x00\x00\x00";
	bIsOk = false;
	coderef2_addr = DSEngineData.SV_ConnectClient_addr;
	coderef2_addr = Dll_ScanForTemplate_Forward(&GenericEngineData, (unsigned char*) ScanData2, (unsigned char*) ScanMask2, sizeof(ScanMask2) - 1, coderef2_addr, 0x1000);
	while (coderef2_addr && (coderef2_addr - DSEngineData.SV_ConnectClient_addr < 0x1000)) {
		tmp = *((uint32_t*) (coderef2_addr + 1)) + coderef2_addr + 5;
		if (tmp == DSEngineData.Steam_NotifyClientConnect_jaddr || tmp == DSEngineData.Steam_NotifyClientConnect_addr) {
			bIsOk = true;
			break;
		}
		coderef2_addr = Dll_ScanForTemplate_Forward(&GenericEngineData, (unsigned char*) ScanData2, (unsigned char*) ScanMask2, sizeof(ScanMask2) - 1, coderef2_addr+1, 0x1000);
	}

	if (!bIsOk) {
		LCPrintf(true, "[DPROTO]: %s: parsing error: Steam validation code not found\n", __FUNCTION__);
		return false;
	}

	DSEngineData.SteamValidationCheck_haddr = coderef2_addr;


	/* ===================================== */
	/* search for SV_CheckKeyInfo() call */
	coderef_addr = 0;
	coderef2_addr = 0;
	coderef_addr = Dll_FindRef_Prefix1(&GenericEngineData.code, coderef_addr, DSEngineData.SV_CheckKeyInfo_jaddr, 0xE8, true);
	while (coderef_addr) {
		tmp = coderef_addr - DSEngineData.SV_ConnectClient_addr;
		if (tmp < 0x1000) {
			coderef2_addr = coderef_addr;
		}
		coderef_addr = Dll_FindRef_Prefix1(&GenericEngineData.code, coderef_addr, DSEngineData.SV_CheckKeyInfo_jaddr, 0xE8, true);
	}

	if (coderef2_addr == 0) {
		coderef_addr = 0;
		coderef_addr = Dll_FindRef_Prefix1(&GenericEngineData.code, coderef_addr, DSEngineData.SV_CheckKeyInfo_addr, 0xE8, true);
		while (coderef_addr) {
			tmp = coderef_addr - DSEngineData.SV_ConnectClient_addr;
			if (tmp < 0x1000) {
				coderef2_addr = coderef_addr;
			}
			coderef_addr = Dll_FindRef_Prefix1(&GenericEngineData.code, coderef_addr, DSEngineData.SV_CheckKeyInfo_addr, 0xE8, true);
		}
	}

	if (coderef2_addr == 0) {
		LCPrintf(true, "[DPROTO]: %s: parsing error: IP Range checking code not found (1)\n", __FUNCTION__);
		return false;
	}

	coderef_addr = coderef2_addr;

	/* Search forward for authproto checking code 
	
		75 ??		jnz ... //after sv_lan comparsion
		83F? 03		cmp e??, 3
		74 ??		jz ?? //IP checking range not needed

	*/
	const char ScanData11[] = "\x75\x00\x83\xF0\x03\x74\x00";
	const char ScanMask11[] = "\xFF\x00\xFF\xF0\xFF\xFF\x00";
	coderef2_addr = Dll_ScanForTemplate_Forward(&GenericEngineData, (unsigned char*) ScanData11, (unsigned char*) ScanMask11, sizeof(ScanMask11) - 1, coderef_addr, 0x40);
	if (coderef2_addr == 0) {
		LCPrintf(true, "[DPROTO]: %s: parsing error: IP Range checking code not found (2)\n", __FUNCTION__);
		return false;
	}

	DSEngineData.ConnectClient_IPRangeChecking_haddr = coderef2_addr;
	coderef2_addr += 5;
	tmp = *((uint8_t*) (coderef2_addr+1)) + coderef2_addr + 2;
	DSEngineData.ConnectClient_IPRangeChecking_GoodRet_addr = tmp;

	return true;
}

bool Parse_SendServerInfo() {
	bool bIsOk;
	uint32_t tmp;
	uint32_t coderef2_addr;
	uint32_t coderef3_addr;

	/* Search for MSG_WriteLong() call (it writes protocol number to message) */
	const char ScanData2[] = "\xE8\x00\x00\x00\x00";
	const char ScanMask2[] = "\xFF\x00\x00\x00\x00";
	bIsOk = false;
	coderef2_addr = DSEngineData.SV_SendServerInfo_addr;
	coderef2_addr = Dll_ScanForTemplate_Forward(&GenericEngineData, (unsigned char*) ScanData2, (unsigned char*) ScanMask2, sizeof(ScanMask2) - 1, coderef2_addr, 0x200);
	while (coderef2_addr && (coderef2_addr - SV_SendServerInfo_addr < 0x200)) {
		tmp = *((uint32_t*) (coderef2_addr + 1)) + coderef2_addr + 5;
		if (tmp == DSEngineData.MSG_WriteLong_jaddr || tmp == DSEngineData.MSG_WriteLong_addr) {
			bIsOk = true;
			break;
		}
		coderef2_addr = Dll_ScanForTemplate_Forward(&GenericEngineData, (unsigned char*) ScanData2, (unsigned char*) ScanMask2, sizeof(ScanMask2) - 1, coderef2_addr+1, 0x200);
	}

	if (!bIsOk) {
		LCPrintf(true, "[DPROTO]: %s: parsing error: protocol writing code not found\n", __FUNCTION__);
		return false;
	}

	DSEngineData.ProtocolWriteCode_haddr = coderef2_addr;
	return true;
}

bool Parse_ReadPackets() {
	bool bIsOk;
	uint32_t tmp;
	uint32_t coderef2_addr;
	uint32_t coderef3_addr;

	/* Search for SV_ConnectionlessPacket() call */
	const char ScanData2[] = "\xE8\x00\x00\x00\x00";
	const char ScanMask2[] = "\xFF\x00\x00\x00\x00";
	bIsOk = false;
	coderef2_addr = DSEngineData.SV_ReadPackets_addr;
	coderef2_addr = Dll_ScanForTemplate_Forward(&GenericEngineData, (unsigned char*) ScanData2, (unsigned char*) ScanMask2, sizeof(ScanMask2) - 1, coderef2_addr, 0x200);
	while (coderef2_addr && (coderef2_addr - DSEngineData.SV_ReadPackets_addr < 0x200)) {
		tmp = *((uint32_t*) (coderef2_addr + 1)) + coderef2_addr + 5;
		if (tmp == DSEngineData.SV_ConnectionlessPacket_jaddr || tmp == DSEngineData.SV_ConnectionlessPacket_addr) {
			bIsOk = true;
			break;
		}
		coderef2_addr = Dll_ScanForTemplate_Forward(&GenericEngineData, (unsigned char*) ScanData2, (unsigned char*) ScanMask2, sizeof(ScanMask2) - 1, coderef2_addr+1, 0x200);
	}

	if (!bIsOk) {
		LCPrintf(true, "[DPROTO]: %s: parsing error: call of SV_ConnectiolessPacket() not found\n", __FUNCTION__);
		return false;
	}

	uint8_t* batmp = (uint8_t*) (coderef2_addr - 6);
	//LCPrintf(false, "[DPROTO]: %s: Call to SV_ConnectionlessPacket found @ 0x%.8X; Dumping previous 6 bytes: %.2X %.2X %.2X %.2X %.2X %.2X\n", __FUNCTION__, coderef2_addr, batmp[0], batmp[1], batmp[2], batmp[3], batmp[4], batmp[5]);

	//now search for previous call
	coderef3_addr = coderef2_addr;
	bIsOk = false;

	
	coderef3_addr = Dll_ScanForTemplate_Backward(&GenericEngineData, (unsigned char*) ScanData2, (unsigned char*) ScanMask2, sizeof(ScanMask2) - 1, coderef3_addr, 0x30);
	//LCPrintf(false, "[DPROTO]: %s: Loop0: coderef3_addr = 0x%.8X\n", __FUNCTION__, coderef3_addr);
	while (coderef3_addr && (coderef2_addr - coderef3_addr < 0x30)) {
		tmp = *((uint32_t*) (coderef3_addr + 1)) + coderef3_addr + 5;
		//LCPrintf(false, "[DPROTO]: %s: call found to 0x%.8X\n", __FUNCTION__, tmp);
		if (IsRangeInSections(&GenericEngineData.code, tmp, 4) || IsRangeInSections(&GenericEngineData.sect_plt, tmp, 4)) {
			DSEngineData.ISMSU_HandlePacket_haddr = coderef3_addr;
			bIsOk = true;
			break;
		}
		
		coderef3_addr = Dll_ScanForTemplate_Backward(&GenericEngineData, (unsigned char*) ScanData2, (unsigned char*) ScanMask2, sizeof(ScanMask2) - 1, coderef3_addr-1, 0x30);
	}

	if (!bIsOk) {
		LCPrintf(true, "[DPROTO]: %s: parsing error: code parsing error\n", __FUNCTION__);
		return false;
	}
	
	return true;
}

bool Parse_GetChallenge() {
	bool bIsOk;
	uint32_t tmp;
	uint32_t coderef2_addr;

	/* Search for SV_ConnectionlessPacket() call */
	const char ScanData2[] = "\xE8\x00\x00\x00\x00";
	const char ScanMask2[] = "\xFF\x00\x00\x00\x00";
	bIsOk = false;
	coderef2_addr = DSEngineData.SVC_GetChallenge_addr;
	coderef2_addr = Dll_ScanForTemplate_Forward(&GenericEngineData, (unsigned char*) ScanData2, (unsigned char*) ScanMask2, sizeof(ScanMask2) - 1, coderef2_addr, 0x600);
	while (coderef2_addr && (coderef2_addr - DSEngineData.SVC_GetChallenge_addr < 0x600)) {
		tmp = *((uint32_t*) (coderef2_addr + 1)) + coderef2_addr + 5;
		if (tmp == DSEngineData.NET_SendPacket_jaddr || tmp == DSEngineData.NET_SendPacket_addr) {
			bIsOk = true;
			break;
		}
		coderef2_addr = Dll_ScanForTemplate_Forward(&GenericEngineData, (unsigned char*) ScanData2, (unsigned char*) ScanMask2, sizeof(ScanMask2) - 1, coderef2_addr+1, 0x600);
	}

	if (!bIsOk) {
		LCPrintf(true, "[DPROTO]: %s: parsing error: code parsing error\n", __FUNCTION__);
		return false;
	}

	DSEngineData.GetChallenge_SendPacket_haddr = coderef2_addr;

	return true;
}

bool Parse_CheckTimeouts() {
	uint32_t tmp;
	uint32_t coderef2_addr;
	/*	Search forward for the "add esi, 0000????h" instruction
				81 ?? ???? 0000	add     esi, 5008h
	*/

	const char ScanData[] = "\x81\x00\x00\x00\x00\x00";
	const char ScanMask[] = "\xFF\x00\x00\x00\xFF\xFF";
	coderef2_addr = DSEngineData.SV_CheckTimeouts_addr;
	coderef2_addr = Dll_ScanForTemplate_Forward(&GenericEngineData, (unsigned char*) ScanData,(unsigned char*) ScanMask, sizeof(ScanMask) - 1, coderef2_addr, 0x180);
	if (coderef2_addr) {
		//increment
		tmp = *((uint32_t*)(coderef2_addr + 2));
		DSEngineData.client_t_size = tmp;
	} else {
		LCPrintf(true, "[DPROTO]: %s: parsing error: sizeof(client_t) not found\n", __FUNCTION__);
		return false;
	}

	return true;
}

bool Parse_GetClientIDString() {
	uint32_t tmp;
	uint32_t coderef2_addr;
	/* Search for ClientID offset in client_t
		05 ????0000	add eax, 0000????
	*/
	const char ScanData2[] = "\x05\x00\x00\x00\x00";
	const char ScanMask2[] = "\xFF\x00\x00\xFF\xFF";
	coderef2_addr = DSEngineData.SV_GetClientIDString_addr;
	coderef2_addr = Dll_ScanForTemplate_Forward(&GenericEngineData, (unsigned char*) ScanData2,(unsigned char*) ScanMask2, sizeof(ScanMask2) - 1, coderef2_addr, 0x80);
	if (coderef2_addr) {
		tmp = *((uint32_t*)(coderef2_addr + 1));
		DSEngineData.ClientID_off = tmp;
	} else {
		LCPrintf(true, "[DPROTO]: %s: parsing error: ClientID offset in client_t not found\n", __FUNCTION__);
		return false;
	}

	return true;
}

bool Parse_ParseVoiceData() {
	uint32_t cstring_addr;
	uint32_t tmp;
	uint32_t coderef_addr;
	uint32_t coderef2_addr;
	bool bIsOk;

	DSEngineData.ParseVoiceData_HostError_haddr = 0;
	/* search for reference to "SV_ParseVoiceData: invalid incoming packet.\n" */

	char ScanData[] = "\x8D\x00\x00\x00\x00\x00";
	const char ScanMask[] = "\xFF\x00\xFF\xFF\xFF\xFF";
	bIsOk = false;

	cstring_addr = Dll_FindString(&GenericEngineData, 0, "SV_ParseVoiceData: invalid incoming packet.\n", true);
	while (cstring_addr) {
		tmp = cstring_addr - GenericEngineData.GlobalsBase;
		memcpy(ScanData+2, &tmp, 4);
		coderef_addr = Dll_ScanForTemplate_Forward(&GenericEngineData, (unsigned char*) ScanData, (unsigned char*) ScanMask, sizeof(ScanMask) - 1, DSEngineData.SV_ParseVoiceData_addr, 0x300);
		if (coderef_addr) {
			bIsOk = true;
			break;
		}
		cstring_addr = Dll_FindString(&GenericEngineData, cstring_addr, "Invalid validation type\n", true);
	}

	if (!bIsOk) {
		return true;
	}

	/* Scan forward for Host_Error() call */
	const char ScanData2[] = "\xE8\x00\x00\x00\x00";
	const char ScanMask2[] = "\xFF\x00\x00\x00\x00";
	bIsOk = false;
	coderef2_addr = coderef_addr;
	coderef2_addr = Dll_ScanForTemplate_Forward(&GenericEngineData, (unsigned char*) ScanData2, (unsigned char*) ScanMask2, sizeof(ScanMask2) - 1, coderef2_addr, 0x30);
	while (coderef2_addr && (coderef2_addr - coderef_addr < 0x30)) {
		tmp = *((uint32_t*) (coderef2_addr + 1)) + coderef2_addr + 5;
		if (tmp == DSEngineData.Host_Error_jaddr || tmp == DSEngineData.Host_Error_addr) {
			bIsOk = true;
			break;
		}
		coderef2_addr = Dll_ScanForTemplate_Forward(&GenericEngineData, (unsigned char*) ScanData2, (unsigned char*) ScanMask2, sizeof(ScanMask2) - 1, coderef2_addr+1, 0x30);
	}

	if (!bIsOk) {
		return true;
	}

	DSEngineData.ParseVoiceData_HostError_haddr = coderef2_addr;
	return true;
}

bool Parse_ParseCvarValue2() {
	bool bIsOk;
	uint32_t tmp;
	uint32_t coderef2_addr;
	uint32_t coderef3_addr;

	DSEngineData.ParseCvarValue2_StrCpy_haddr = 0;
	/* Search for Q_StrCpy() call */
	const char ScanData2[] = "\xE8\x00\x00\x00\x00";
	const char ScanMask2[] = "\xFF\x00\x00\x00\x00";
	bIsOk = false;
	coderef2_addr = DSEngineData.SV_ParseCvarValue2_addr;
	coderef2_addr = Dll_ScanForTemplate_Forward(&GenericEngineData, (unsigned char*) ScanData2, (unsigned char*) ScanMask2, sizeof(ScanMask2) - 1, coderef2_addr, 0x60);
	while (coderef2_addr && (coderef2_addr - DSEngineData.SV_ParseCvarValue2_addr < 0x60)) {
		tmp = *((uint32_t*) (coderef2_addr + 1)) + coderef2_addr + 5;
		if (tmp == DSEngineData.Q_strcpy_jaddr || tmp == DSEngineData.Q_strcpy_jaddr) {
			bIsOk = true;
			break;
		}
		coderef2_addr = Dll_ScanForTemplate_Forward(&GenericEngineData, (unsigned char*) ScanData2, (unsigned char*) ScanMask2, sizeof(ScanMask2) - 1, coderef2_addr+1, 0x60);
	}

	//it's ok
	if (!bIsOk) {
		return true;
	}

	DSEngineData.ParseCvarValue2_StrCpy_haddr = coderef2_addr;
	return true;
}