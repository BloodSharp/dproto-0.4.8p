#include "osconfig.h"
#include "dproto.h"
#include "cfg.h"
#include "dynpatcher_base.h"
#include "dynparser_win.h"

size_t gISteamGS_BSecure_addr = 0;
size_t gISteamMSU_HandleIncomingPacket_addr = 0;
size_t gpISteamMSU_HandleIncomingPacket_addr = 0;

bool Parse_Imports() {
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER) GenericEngineData.DllBase;
	PIMAGE_NT_HEADERS NTHeaders = (PIMAGE_NT_HEADERS) ((size_t)GenericEngineData.DllBase + dosHeader->e_lfanew);
	PIMAGE_IMPORT_DESCRIPTOR cIDescr = (PIMAGE_IMPORT_DESCRIPTOR) (NTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + (size_t)GenericEngineData.DllBase);
	PIMAGE_THUNK_DATA cThunk;

	HMODULE hSteamAPI = GetModuleHandleW(L"steam_api_c.dll");
	if (hSteamAPI == 0)
		return false;
	gISteamGS_BSecure_addr = (size_t) GetProcAddress(hSteamAPI, "ISteamGameServer_BSecure");
	gISteamMSU_HandleIncomingPacket_addr = (size_t) GetProcAddress(hSteamAPI, "ISteamMasterServerUpdater_HandleIncomingPacket");

	if (gISteamGS_BSecure_addr == 0 || gISteamMSU_HandleIncomingPacket_addr == 0)
		return false;

	char* LibName;
	for (; cIDescr->Name; cIDescr++) {
		LibName = (char*) (cIDescr->Name + (size_t)GenericEngineData.DllBase);
		if (!stricmp(LibName, "steam_api_c.dll")) {
			cThunk = (PIMAGE_THUNK_DATA)((size_t)GenericEngineData.DllBase + cIDescr->FirstThunk);
			for (; cThunk->u1.Function; cThunk++) {
				uint32_t* FuncAddr = (uint32_t*) (&cThunk->u1.Function);
				if (*FuncAddr == gISteamMSU_HandleIncomingPacket_addr) {
					gpISteamMSU_HandleIncomingPacket_addr = (size_t)FuncAddr;
				}
			} // ~for
		} // ~if (!stricmp(LibName, "steam_api_c.dll"))
	} //~for

	if (gpISteamMSU_HandleIncomingPacket_addr == 0)
		return false;

	return true;
}

bool Parse_CheckProtocol() {
	uint32_t cstring_addr;
	uint32_t coderef_addr;
	uint32_t validstringref;
	uint32_t tmp;
	int Cnt;

	
	//find function address. It contains ref to string "This server is using an older protocol ( %i ) than your client ( %i ).  If you believe this server is outdated, you can contact the server administrator at %s.\n"
	cstring_addr = Dll_FindString(&GenericEngineData, 0, "This server is using an older protocol ( %i ) than your client ( %i ).  If you believe this server is outdated, you can contact the server administrator at %s.\n", true);
	Cnt = 0;
	while (cstring_addr) {
		coderef_addr = Dll_FindRef_Push(&GenericEngineData.code, 0, cstring_addr);
		while (coderef_addr) {

			/* now find the beginning of the function
				B8 ????0000		mov     eax, 1000h
				E8 ????????		call    __alloca_probe
				8B8C24 ????0000	mov     ecx, [esp+1000h+Format]
				8D8424 ????0000	lea     eax, [esp+1000h+Args]
			*/

			const char ScanData[] = "\x55\x8B\xEC\x56\x57";
			const char ScanMask[] = "\xFF\xFF\xFF\xFF\xFF";
			tmp = Dll_ScanForTemplate_Backward(&GenericEngineData, (unsigned char*) ScanData,(unsigned char*) ScanMask, sizeof(ScanMask) - 1, coderef_addr, 0x200);
			if (tmp) {
				Cnt++;
				DSEngineData.SV_CheckProtocol_addr = tmp;
				validstringref = coderef_addr;
			}
					
			coderef_addr = Dll_FindRef_Push(&GenericEngineData.code, coderef_addr, cstring_addr);
		}
		cstring_addr = Dll_FindString(&GenericEngineData, cstring_addr, "This server is using an older protocol ( %i ) than your client ( %i ).  If you believe this server is outdated, you can contact the server administrator at %s.\n", true);
	}

	if (Cnt == 0) {
		LCPrintf(true, "[DPROTO]: Parse_CheckProtocol() parsing error: function not found\n");
		return false;
	} else if (Cnt > 1) {
		LCPrintf(true, "[DPROTO]: Parse_CheckProtocol() parsing warning: %d candidates found\n", Cnt);
	}

	/*	find reference to SV_RejectConnection()
		
		push "This server is using an older...."
		...
		E8 ???????? call SV_RejectConnection
	*/

	const char ScanData2[] = "\xE8\x00\x00\x00\x00";
	const char ScanMask2[] = "\xFF\x00\x00\x00\x00";

	Cnt = 0;
	coderef_addr = validstringref + 0x5;
	coderef_addr = Dll_ScanForTemplate_Forward(&GenericEngineData, (unsigned char*) ScanData2,(unsigned char*) ScanMask2, sizeof(ScanMask2) - 1, coderef_addr, 0x10);
	while (coderef_addr && (coderef_addr - validstringref < 0x10)) {
		if (IsRangeInSections(&GenericEngineData.code, coderef_addr, 5)) {
			//get address of function being called
			tmp = *(uint32_t*) (coderef_addr + 1) + coderef_addr + 5;
			
			//validate it
			if (IsRangeInSections(&GenericEngineData.code, tmp, 4)) {
				Cnt++;
				DSEngineData.SV_RejectConnection_addr = tmp;
				break;
			}
		}
		coderef_addr = Dll_ScanForTemplate_Forward(&GenericEngineData, (unsigned char*) ScanData2,(unsigned char*) ScanMask2, sizeof(ScanMask2) - 1, coderef_addr+1, 0x10);
	}

	if (Cnt == 0) {
		LCPrintf(true, "[DPROTO]: Parse_CheckProtocol() parsing error: reference to SV_RejectConnection() not found\n");
		return false;
	}
	
	return true;
}

bool Parse_SendServerInfo() {
	uint32_t cstring_addr;
	uint32_t coderef_addr;
	uint32_t validstringref;
	uint32_t tmp;
	int Cnt;

	
	//find function address. It contains ref to string "%c\nBUILD %d SERVER (%i CRC)\nServer # %i"
	cstring_addr = Dll_FindString(&GenericEngineData, 0, "%c\nBUILD %d SERVER (%i CRC)\nServer # %i\n", true);
	Cnt = 0;
	while (cstring_addr) {
		coderef_addr = Dll_FindRef_Push(&GenericEngineData.code, 0, cstring_addr);
		while (coderef_addr) {
			Cnt++;
			validstringref = coderef_addr;
					
			coderef_addr = Dll_FindRef_Push(&GenericEngineData.code, coderef_addr, cstring_addr);
		}
		cstring_addr = Dll_FindString(&GenericEngineData, cstring_addr, "%c\nBUILD %d SERVER (%i CRC)\nServer # %i", true);
	}

	if (Cnt == 0) {
		LCPrintf(true, "[DPROTO]: %s: parsing error: function not found\n", __FUNCTION__);
		return false;
	} else if (Cnt > 1) {
		LCPrintf(true, "[DPROTO]: %s: parsing warning: %d candidates found\n", __FUNCTION__, Cnt);
	}

	/*	find reference to svs
		
		A1 ???????? mov eax, svs.SpawnCount
		...

	*/

	const char ScanData2[] = "\xA1\x00\x00\x00\x00";
	const char ScanMask2[] = "\xFF\x00\x00\x00\x00";

	Cnt = 0;
	coderef_addr = validstringref - 0x1;
	coderef_addr = Dll_ScanForTemplate_Backward(&GenericEngineData, (unsigned char*) ScanData2,(unsigned char*) ScanMask2, sizeof(ScanMask2) - 1, coderef_addr, 0x30);
	while (coderef_addr && (validstringref - coderef_addr < 0x30)) {
		if (IsRangeInSections(&GenericEngineData.code, coderef_addr, 5)) {
			//get address of variable
			tmp = *(uint32_t*) (coderef_addr + 1);
			
			//validate it
			if (IsRangeInSections(GenericEngineData.vdata, tmp, 4)) {
				Cnt++;
				DSEngineData.svs_addr = tmp - 0x10;
				break;
			}
		}
		coderef_addr = Dll_ScanForTemplate_Backward(&GenericEngineData, (unsigned char*) ScanData2,(unsigned char*) ScanMask2, sizeof(ScanMask2) - 1, coderef_addr-1, 0x30);
	}

	if (!Cnt) {
		LCPrintf(true, "[DPROTO]: %s: parsing error: address of svs not found\n", __FUNCTION__);
		return false;
	}

	/*	find references to MSG_WriteString, MSG_WriteByte and MSG_WriteLong

		Engine contains following code:

			push "This server is using an older...."
			...
			call sprintf
			...
			call MSG_WriteString
			...
			call MSG_WriteByte
			...
			call MSG_WriteLong
		
	*/

	const char ScanData3[] = "\xE8\x00\x00\x00\x00";
	const char ScanMask3[] = "\xFF\x00\x00\x00\x00";

	Cnt = 0;
	coderef_addr = validstringref + 0x6;
	coderef_addr = Dll_ScanForTemplate_Forward(&GenericEngineData, (unsigned char*) ScanData3,(unsigned char*) ScanMask3, sizeof(ScanMask3) - 1, coderef_addr, 0x40);
	while (coderef_addr && (coderef_addr - validstringref < 0x60) && Cnt < 4) {
		if (IsRangeInSections(&GenericEngineData.code, coderef_addr, 5)) {
			//get address of calling function
			tmp = *(uint32_t*) (coderef_addr + 1) + coderef_addr + 5;

			//validate it
			if (IsRangeInSections(&GenericEngineData.code, tmp, 4)) {
				switch(Cnt) {
					case 1:
						DSEngineData.MSG_WriteString_addr = tmp;
						break;

					case 2:
						DSEngineData.MSG_WriteByte_addr = tmp;
						break;

					case 3:
						DSEngineData.MSG_WriteLong_addr = tmp;
						DSEngineData.SendServerInfo_WriteLongProto_haddr = coderef_addr;
						break;

				}
				Cnt++;
			}
		}
		coderef_addr = Dll_ScanForTemplate_Forward(&GenericEngineData, (unsigned char*) ScanData3,(unsigned char*) ScanMask3, sizeof(ScanMask3) - 1, coderef_addr+1, 0x40);
	}

	if (Cnt != 4) {
		LCPrintf(true, "[DPROTO]: %s: parsing error: MSG_* functions\n", __FUNCTION__);
		return false;
	}

	return true;
}

bool Parse_ConnectClient() {
	uint32_t cstring_addr;
	uint32_t coderef_addr;
	uint32_t coderef2_addr;
	uint32_t tmp;
	bool bIsOk;
	int Cnt;

	/* =========================================== */	
	/*	find auth protocol validation code in SV_ConnectClient. It contains ref to string "Invalid validation type\n"
			83F? 02			cmp     eax, 2 // <<<== need to hook there
							jnz     loc_1D99FF1 //jump to reject with reason "Invalid authentication type"
							lea     edx, [ebp+Str]

							push    offset "*hltv"
							push    edx
							call    Info_ValueForKey
							mov     esi, eax
							push    esi             ; str
							call    Q_StrLen
			83C4 0C			add     esp, 0Ch
			85C0			test    eax, eax
			0F84 ????????	jz      loc_1D99FD9
							push    esi
							call    Q_atoi
							add     esp, 4
			83F8 01			cmp     eax, 1
			74 ??			jz      short loc_1D99CC2
							lea     eax, [ebp+adr]
			68 ????????		push    "Invalid validation type\n"
	*/
	
	cstring_addr = Dll_FindString(&GenericEngineData, 0, "Invalid validation type\n", true);
	Cnt = 0;
	while (cstring_addr) {
		coderef_addr = Dll_FindRef_Push(&GenericEngineData.code, 0, cstring_addr);
		while (coderef_addr) {
			/*
				now search backward for the
					83F8 01		cmp     eax, 1
				instruction
			*/
			
			const char ScanData[] = "\x83\xF8\x01";
			const char ScanMask[] = "\xFF\xFF\xFF";
			coderef2_addr = Dll_ScanForTemplate_Backward(&GenericEngineData, (unsigned char*) ScanData,(unsigned char*) ScanMask, sizeof(ScanMask) - 1, coderef_addr, 0x20);
			if (coderef2_addr) {
				/* Check for next instruction - it should be short jz */
				coderef2_addr += 3;
				tmp = *(uint8_t*) coderef2_addr;
				if (tmp == 0x74) {
					tmp = *((uint8_t*) (coderef2_addr + 1));
					DSEngineData.AuthProtoValidation__LongJZ_GoodAddr = coderef2_addr + 2 + tmp;

					/*	now search backward for the authproto comparsion code:

						83F? 02	cmp     eax, 2 
					*/
			
					coderef2_addr -= 3;
					const char ScanData2[] = "\x83\xF8\x02";
					const char ScanMask2[] = "\xFF\xF0\xFF";
					tmp = Dll_ScanForTemplate_Backward(&GenericEngineData, (unsigned char*) ScanData2,(unsigned char*) ScanMask2, sizeof(ScanMask2) - 1, coderef2_addr, 0x50);
					if (tmp) {
						Cnt++;
						DSEngineData.AuthProtoValidation__LongJZ_haddr = tmp; //will install JMP there
						
					}
				}

			}
					
			coderef_addr = Dll_FindRef_Push(&GenericEngineData.code, coderef_addr, cstring_addr);
		}
		cstring_addr = Dll_FindString(&GenericEngineData, cstring_addr, "Invalid validation type\n", true);
	}

	if (Cnt <= 0) {
		LCPrintf(true, "[DPROTO]: %s: parsing error: AuthProto validation code not found\n", __FUNCTION__);
		return false;
	} else if (Cnt > 1) {
		LCPrintf(true, "[DPROTO]: %s: parsing warning: %d candidates found for AuthProto validation code\n", __FUNCTION__, Cnt);
	}


	/*	Find STEAM ticket validation code. It contains ref to string "STEAM validation rejected\n"
			E8 ????????		call    Steam_NotifyClientConnect
			83C4 0C			add     esp, 0Ch
			85C0			test    eax, eax
							jnz     loc_1D99CF2
							fld     cv_sv_lan.value
							fcomp   ds:f_zero
							fnstsw  ax
							test    ah, 40h
							jz      short loc_1D99C35
							lea     eax, [ebp+adr]
							push    "STEAM validation rejected\n"
	*/


	cstring_addr = Dll_FindString(&GenericEngineData, 0, "STEAM validation rejected\n", true);
	Cnt = 0;
	while (cstring_addr) {
		coderef_addr = Dll_FindRef_Push(&GenericEngineData.code, 0, cstring_addr);
		while (coderef_addr) {

			/*	Search backward for Steam_NotifySteamClientConnect() call:

				E8 ????????		call    Steam_NotifyClientConnect
				83C4 0C			add     esp, 0Ch
				85C0			test    eax, eax

			*/

			const char ScanData3[] = "\xE8\x00\x00\x00\x00\x83\xC4\x0C\x85\xC0";
			const char ScanMask3[] = "\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF";
			coderef2_addr = Dll_ScanForTemplate_Backward(&GenericEngineData, (unsigned char*) ScanData3,(unsigned char*) ScanMask3, sizeof(ScanMask3) - 1, coderef_addr, 0x40);
			if (coderef2_addr) {
				tmp = *((uint32_t*) (coderef2_addr + 1)) + coderef2_addr + 5;
				DSEngineData.Steam_NotifyClientConnect_addr = tmp;
				DSEngineData.SteamValidation_NotifyCC_haddr = coderef2_addr;
				Cnt++;

			}

			coderef_addr = Dll_FindRef_Push(&GenericEngineData.code, coderef_addr, cstring_addr);
		}
		cstring_addr = Dll_FindString(&GenericEngineData, cstring_addr, "STEAM validation rejected\n", true);
	}

	if (Cnt <= 0) {
		LCPrintf(true, "[DPROTO]: %s: parsing error: Steam Ticket validation code not found\n", __FUNCTION__);
		return false;
	} else if (Cnt > 1) {
		LCPrintf(true, "[DPROTO]: %s: parsing warning: %d candidates found for Steam Ticket validation code\n", __FUNCTION__, Cnt);
	}

	/* =========================================== */
	/* Search call to SV_CheckCertificate() */

	coderef_addr = 0;
	coderef2_addr = 0;
	coderef_addr = Dll_FindRef_Prefix1(&GenericEngineData.code, coderef_addr, DSEngineData.SV_CheckCertificate_addr, 0xE8, true);
	while (coderef_addr) {
		int cRange = coderef_addr - DSEngineData.AuthProtoValidation__LongJZ_GoodAddr;
		cRange = abs(cRange);
		if (cRange < 0x800) {
			coderef2_addr = coderef_addr;
		}
		coderef_addr = Dll_FindRef_Prefix1(&GenericEngineData.code, coderef_addr, DSEngineData.SV_CheckCertificate_addr, 0xE8, true);
	}

	if (coderef2_addr == 0) {
		LCPrintf(true, "[DPROTO]: %s: parsing error: IP Range code not found (1)\n", __FUNCTION__);
		return false;
	}

	coderef_addr = coderef2_addr;

	/* Scan forward for next call. It should be SV_CheckIPRestrictions */

	const char ScanData4[] = "\xE8\x00\x00\x00\x00";
	const char ScanMask4[] = "\xFF\x00\x00\x00\x00";
	bIsOk = false;
	coderef2_addr = Dll_ScanForTemplate_Forward(&GenericEngineData, (unsigned char*) ScanData4, (unsigned char*) ScanMask4, sizeof(ScanMask4) - 1, coderef2_addr+1, 0x50);
	while (coderef2_addr && (coderef2_addr - coderef_addr < 0x50)) {
		tmp = *((uint32_t*) (coderef2_addr + 1)) + coderef2_addr + 5;
		if (IsRangeInSections(&GenericEngineData.code, tmp, 4)) {
			bIsOk = true;
			DSEngineData.SV_CheckIPRestrictions_addr = tmp;
			break;
		}
		coderef2_addr = Dll_ScanForTemplate_Forward(&GenericEngineData, (unsigned char*) ScanData4, (unsigned char*) ScanMask4, sizeof(ScanMask4) - 1, coderef2_addr+1, 0x50);
	}

	if (!bIsOk) {
		LCPrintf(true, "[DPROTO]: %s: parsing error: IP Range code not found (2)\n", __FUNCTION__);
		return false;
	}

	return true;
}

bool Parse_GetChallenge() {
	uint32_t cstring_addr;
	uint32_t coderef_addr;
	uint32_t coderef2_addr;
	int Cnt;

	
	/*	Search for challenge packet generation code. It contains reference to string "%c%c%c%c%c00000000 %u %i\n" */

	cstring_addr = Dll_FindString(&GenericEngineData, 0, "%c%c%c%c%c00000000 %u %i\n", true);
	Cnt = 0;
	while (cstring_addr) {
		coderef_addr = Dll_FindRef_Push(&GenericEngineData.code, 0, cstring_addr);
		while (coderef_addr) {

			/* Now search forward for the NET_SendPacket() call
				6A 01  		push    1
				E8 ????????	call    NET_SendPacket
				83C4 20		add     esp, 20h

			*/
			
			const char ScanData[] = "\x6A\x01\xE8\x00\x00\x00\x00\x83\xC4\x20";
			const char ScanMask[] = "\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF";
			coderef2_addr = Dll_ScanForTemplate_Forward(&GenericEngineData, (unsigned char*) ScanData,(unsigned char*) ScanMask, sizeof(ScanMask) - 1, coderef_addr, 0x100);
			if (coderef2_addr) {
				coderef2_addr += 2;
				DSEngineData.ChallengeGen_SendPacket_haddr = coderef2_addr;
				DSEngineData.NET_SendPacket_addr = (*((uint32_t*)(coderef2_addr + 1))) + coderef2_addr + 5;
				Cnt++;
			}

			coderef_addr = Dll_FindRef_Push(&GenericEngineData.code, coderef_addr, cstring_addr);
		}
		cstring_addr = Dll_FindString(&GenericEngineData, cstring_addr, "%c%c%c%c%c00000000 %u %i\n", true);
	}

	if (Cnt <= 0) {
		LCPrintf(true, "[DPROTO]: %s: parsing error: Challenge generation code not found\n", __FUNCTION__);
		return false;
	} else if (Cnt > 1) {
		LCPrintf(true, "[DPROTO]: %s: parsing warning: %d candidates found for challenge generation code\n", __FUNCTION__, Cnt);
	}

	return true;
}

bool Parse_GSClientDenyHelper() {
	uint32_t cstring_addr;
	uint32_t coderef_addr;
	uint32_t coderef2_addr;
	int Cnt;

	/*	Search for the GS_ClientDenyHelper() function . It contains reference to string "This Steam account is being used in another location\n" */
	
	
	cstring_addr = Dll_FindString(&GenericEngineData, 0, "This Steam account is being used in another location\n", true);
	Cnt = 0;
	while (cstring_addr) {
		coderef_addr = Dll_FindRef_Push(&GenericEngineData.code, 0, cstring_addr);
		while (coderef_addr) {

			/* Now find the beginning of the function
					55	 	push    ebp
					8BEC	mov     ebp, esp
					8B45 0C	mov     eax, [ebp+arg_4]
			*/
			
			const char ScanData[] = "\x55\x8B\xEC\x8B\x45\x0C";
			const char ScanMask[] = "\xFF\xFF\xFF\xFF\xFF\xFF";
			coderef2_addr = Dll_ScanForTemplate_Backward(&GenericEngineData, (unsigned char*) ScanData,(unsigned char*) ScanMask, sizeof(ScanMask) - 1, coderef_addr, 0x200);
			if (coderef2_addr) {
				DSEngineData.GS_ClientDenyHelper_addr = coderef2_addr;
				Cnt++;
			}

			coderef_addr = Dll_FindRef_Push(&GenericEngineData.code, coderef_addr, cstring_addr);
		}
		cstring_addr = Dll_FindString(&GenericEngineData, cstring_addr, "This Steam account is being used in another location\n", true);
	}

	if (Cnt <= 0) {
		LCPrintf(true, "[DPROTO]: %s: parsing error: GS_ClientDenyHelper() not found\n", __FUNCTION__);
		return false;
	} else if (Cnt > 1) {
		LCPrintf(true, "[DPROTO]: %s: parsing warning: %d candidates found for GS_ClientDenyHelper()\n", __FUNCTION__, Cnt);
	}

	return true;
}

bool Parse_EntityInterface() {
	uint32_t cstring_addr;
	uint32_t coderef_addr;
	uint32_t coderef2_addr;
	uint32_t coderef3_addr;
	uint32_t tmp;
	int Cnt;

	/* Search for GameDLL loading code. It contains reference to string "Game DLL version mismatch\n" */

	cstring_addr = Dll_FindString(&GenericEngineData, 0, "Game DLL version mismatch\n", true);
	Cnt = 0;
	DSEngineData.gEntityInterface_addr = 0;
	while (cstring_addr) {
		coderef_addr = Dll_FindRef_Push(&GenericEngineData.code, 0, cstring_addr);
		while (coderef_addr) {

			/* Now search backward for "test eax, eax" instruction:

					68 ????????	push    offset gEntityInterface
								mov     [ebp+var_4], esi
								call    eax
								add     esp, 8
					85C0		test    eax, eax
								jnz     short loc_1DAE02C
								push    "==================\n"
								call    Con_Printf
								push    "Game DLL version mismatch\n"

			*/
			
			const char ScanData[] = "\x85\xC0";
			const char ScanMask[] = "\xFF\xFF";
			coderef2_addr = Dll_ScanForTemplate_Backward(&GenericEngineData, (unsigned char*) ScanData,(unsigned char*) ScanMask, sizeof(ScanMask) - 1, coderef_addr, 0x30);
			if (coderef2_addr) {

				/* Search backward for "push    offset gEntityInterface" instruction" */

				const char ScanData2[] = "\x68\x00\x00\x00\x00";
				const char ScanMask2[] = "\xFF\x00\x00\x00\x00";
				coderef3_addr = coderef2_addr - 1;
				coderef3_addr = Dll_ScanForTemplate_Backward(&GenericEngineData, (unsigned char*) ScanData2,(unsigned char*) ScanMask2, sizeof(ScanMask2) - 1, coderef3_addr, 0x40);
				bool bFound = false;
				while (coderef3_addr && (coderef2_addr - coderef3_addr < 0x40)) {

					//address of variable being pushed
					tmp = *((uint32_t*)(coderef3_addr + 1));
					if (IsRangeInSections(GenericEngineData.vdata, tmp, 4)) {
						bFound = true;
						break;
					}

					coderef3_addr = Dll_ScanForTemplate_Backward(&GenericEngineData, (unsigned char*) ScanData2,(unsigned char*) ScanMask2, sizeof(ScanMask2) - 1, coderef3_addr-1, 0x40);
				}

				if (bFound) {
					if (Cnt) {
						if (DSEngineData.gEntityInterface_addr != tmp)
							Cnt++;
					} else {
						Cnt++;
					}
					DSEngineData.gEntityInterface_addr = tmp;
				}

			}

			coderef_addr = Dll_FindRef_Push(&GenericEngineData.code, coderef_addr, cstring_addr);
		}
		cstring_addr = Dll_FindString(&GenericEngineData, cstring_addr, "Game DLL version mismatch\n", true);
	}

	if (Cnt <= 0) {
		LCPrintf(true, "[DPROTO]: %s: parsing error: gEntityInterface not found\n", __FUNCTION__);
		return false;
	} else if (Cnt > 1) {
		LCPrintf(true, "[DPROTO]: %s: parsing warning: %d candidates found for gEntityInterface\n", __FUNCTION__, Cnt);
	}

	return true;
}

bool Parse_LogPrintServerVars() {
	uint32_t cstring_addr;
	uint32_t coderef_addr;
	uint32_t coderef2_addr;
	uint32_t tmp;
	int Cnt;

	/* Search for Log_PrintServerVars() function . It contains reference to string "Server cvars start\n" */

	cstring_addr = Dll_FindString(&GenericEngineData, 0, "Server cvars start\n", true);
	Cnt = 0;
	while (cstring_addr) {
		coderef_addr = Dll_FindRef_Push(&GenericEngineData.code, 0, cstring_addr);
		while (coderef_addr) {

			/* Search for the "mov esi, cvar_vars" instruction
				68 ????????		push offset aServerCvarsSta ; "Server cvars start\n"
				E8 ????????		call Log_Printf
				8B ?? ????????	mov  esi, cvar_vars
			*/

			const char ScanData[] = "\x8B\x00\x00\x00\x00\x00";
			const char ScanMask[] = "\xFF\x00\x00\x00\x00\x00";
			coderef2_addr = coderef_addr + 5;
			coderef2_addr = Dll_ScanForTemplate_Forward(&GenericEngineData, (unsigned char*) ScanData,(unsigned char*) ScanMask, sizeof(ScanMask) - 1, coderef2_addr, 0x20);
			while (coderef2_addr && (coderef2_addr - coderef_addr < 0x20)) {
				//address of variable being moved
				tmp = *((uint32_t*)(coderef2_addr + 2));
				if (IsRangeInSections(GenericEngineData.vdata, tmp, 4)) {
					Cnt++;
					DSEngineData.cvars_vars_addr = tmp;
					break;
				}

				coderef2_addr = Dll_ScanForTemplate_Forward(&GenericEngineData, (unsigned char*) ScanData,(unsigned char*) ScanMask, sizeof(ScanMask) - 1, coderef2_addr+1, 0x20);
			}

			coderef_addr = Dll_FindRef_Push(&GenericEngineData.code, coderef_addr, cstring_addr);
		}
		
		cstring_addr = Dll_FindString(&GenericEngineData, cstring_addr, "Server cvars start\n", true);
	}

	if (Cnt <= 0) {
		LCPrintf(true, "[DPROTO]: %s: parsing error: cvars_vars not found\n", __FUNCTION__);
		return false;
	} else if (Cnt > 1) {
		LCPrintf(true, "[DPROTO]: %s: parsing warning: %d candidates found for cvars_vars\n", __FUNCTION__, Cnt);
	}

	return true;
}

bool Parse_ListId() {
	uint32_t cstring_addr;
	uint32_t coderef_addr;
	uint32_t coderef2_addr;
	uint32_t tmp;
	int Cnt;

	/* Search for SV_ListId_f() function . It contains reference to string "UserID filter list: empty\n" */
	

	cstring_addr = Dll_FindString(&GenericEngineData, 0, "UserID filter list: empty\n", true);
	Cnt = 0;
	while (cstring_addr) {
		coderef_addr = Dll_FindRef_Push(&GenericEngineData.code, 0, cstring_addr);
		while (coderef_addr) {
			Cnt++;
	
			coderef2_addr = coderef_addr;
			coderef_addr = Dll_FindRef_Push(&GenericEngineData.code, coderef_addr, cstring_addr);
		}
		
		cstring_addr = Dll_FindString(&GenericEngineData, cstring_addr, "UserID filter list: empty\n", true);
	}

	if (Cnt <= 0) {
		LCPrintf(true, "[DPROTO]: %s: parsing error: SV_ListId_f() not found\n", __FUNCTION__);
		return false;
	} else if (Cnt > 1) {
		LCPrintf(true, "[DPROTO]: %s: parsing warning: %d candidates found for SV_ListId_f()\n", __FUNCTION__, Cnt);
	}

	/*	Search backward for the "mov eax, numuserfilters" instruction

				A1 ????????		mov		eax, numuserfilters
								test    eax, eax
								jg      short loc_1DA03B0
								push    "UserID filter list: empty\n"

	*/

	const char ScanData[] = "\xA1\x00\x00\x00\x00";
	const char ScanMask[] = "\xFF\x00\x00\x00\x00";
	Cnt = 0;
	coderef_addr = coderef2_addr;
	coderef2_addr = coderef_addr - 1;
	coderef2_addr = Dll_ScanForTemplate_Backward(&GenericEngineData, (unsigned char*) ScanData,(unsigned char*) ScanMask, sizeof(ScanMask) - 1, coderef2_addr, 0x30);
	while (coderef2_addr && (coderef_addr - coderef2_addr < 0x30)) {
		//address of variable being moved
		tmp = *((uint32_t*)(coderef2_addr + 1));
		if (IsRangeInSections(GenericEngineData.vdata, tmp, 4)) {
			Cnt++;
			DSEngineData.numuserfilters_addr = tmp;
			break;
		}

		coderef2_addr = Dll_ScanForTemplate_Backward(&GenericEngineData, (unsigned char*) ScanData,(unsigned char*) ScanMask, sizeof(ScanMask) - 1, coderef2_addr-1, 0x30);
	}

	if (Cnt <= 0) {
		LCPrintf(true, "[DPROTO]: %s: parsing error: numuserfilters not found\n", __FUNCTION__);
		return false;
	} else if (Cnt > 1) {
		LCPrintf(true, "[DPROTO]: %s: parsing warning: %d candidates found for numuserfilters\n", __FUNCTION__, Cnt);
	}

	/*	Search forward for the "mov edi, userfilters" instruction

								jg      short loc_1DA03B0
								push    "UserID filter list: empty\n"
								...
								push    esi
								push    edi
								mov     esi, 1
					B8 ????????	mov     edi, offset userfilters
	*/

	const char ScanData2[] = "\xB8\x00\x00\x00\x00";
	const char ScanMask2[] = "\xF8\x00\x00\x00\x00";
	Cnt = 0;
	coderef2_addr = coderef_addr + 5;
	coderef2_addr = Dll_ScanForTemplate_Forward(&GenericEngineData, (unsigned char*) ScanData2,(unsigned char*) ScanMask2, sizeof(ScanMask2) - 1, coderef2_addr, 0x80);
	while (coderef2_addr && (coderef2_addr - coderef_addr < 0x80)) {
		//address of variable being moved
		tmp = *((uint32_t*)(coderef2_addr + 1));
		if (IsRangeInSections(GenericEngineData.vdata, tmp, 4) && tmp != DSEngineData.numuserfilters_addr) {
			Cnt++;
			DSEngineData.userfilters_addr = tmp;
			break;
		}

		coderef2_addr = Dll_ScanForTemplate_Forward(&GenericEngineData, (unsigned char*) ScanData2,(unsigned char*) ScanMask2, sizeof(ScanMask2) - 1, coderef2_addr+1, 0x80);
	}

	if (Cnt <= 0) {
		LCPrintf(true, "[DPROTO]: %s: parsing error: userfilters not found\n", __FUNCTION__);
		return false;
	} else if (Cnt > 1) {
		LCPrintf(true, "[DPROTO]: %s: parsing warning: %d candidates found for userfilters\n", __FUNCTION__, Cnt);
	}

	return true;
}

bool Parse_CheckTimeouts() {
	uint32_t cstring_addr;
	uint32_t coderef_addr;
	uint32_t coderef2_addr;
	uint32_t tmp;
	int Cnt;

	/* Search for SV_CheckTimeouts() function . It contains reference to string "%s timed out\n" */
	

	cstring_addr = Dll_FindString(&GenericEngineData, 0, "%s timed out\n", true);
	Cnt = 0;
	while (cstring_addr) {
		coderef_addr = Dll_FindRef_Push(&GenericEngineData.code, 0, cstring_addr);
		while (coderef_addr) {
			Cnt++;
			coderef2_addr = coderef_addr;

			coderef_addr = Dll_FindRef_Push(&GenericEngineData.code, coderef_addr, cstring_addr);
		}
		
		cstring_addr = Dll_FindString(&GenericEngineData, cstring_addr, "%s timed out\n", true);
	}

	if (Cnt <= 0) {
		LCPrintf(true, "[DPROTO]: %s: parsing error: SV_CheckTimeouts() not found\n", __FUNCTION__);
		return false;
	} else if (Cnt > 1) {
		LCPrintf(true, "[DPROTO]: %s: parsing warning: %d candidates found for SV_CheckTimeouts()\n", __FUNCTION__, Cnt);
	}


	/*	Search forward for the "add esi, 0000????h" instruction

				81 ?? ???? 0000	add     esi, 5008h

	*/

	const char ScanData[] = "\x81\x00\x00\x00\x00\x00";
	const char ScanMask[] = "\xFF\x00\x00\x00\xFF\xFF";
	coderef_addr = coderef2_addr;
	coderef2_addr = coderef_addr + 5;
	coderef2_addr = Dll_ScanForTemplate_Forward(&GenericEngineData, (unsigned char*) ScanData,(unsigned char*) ScanMask, sizeof(ScanMask) - 1, coderef2_addr, 0x60);
	if (coderef2_addr) {
		//increment
		tmp = *((uint32_t*)(coderef2_addr + 2));
		DSEngineData.client_t_size = tmp;
	} else {
		LCPrintf(true, "[DPROTO]: %s: parsing error: sizeof(client_t) not found\n", __FUNCTION__);
		return false;
	}

	/*	Search forward for the "fsubr   realtime" instruction

				DC2D ????????	fsubr   realtime

	*/

	const char ScanData2[] = "\xDC\x2D\x00\x00\x00\x00";
	const char ScanMask2[] = "\xFF\xFF\x00\x00\x00\x00";
	coderef2_addr = coderef_addr - 1;
	Cnt = 0;
	coderef2_addr = Dll_ScanForTemplate_Backward(&GenericEngineData, (unsigned char*) ScanData2,(unsigned char*) ScanMask2, sizeof(ScanMask2) - 1, coderef2_addr, 0x60);
	while (coderef2_addr && (coderef_addr - coderef2_addr < 0x60)) {
		//increment
		tmp = *((uint32_t*)(coderef2_addr + 2));
		if (IsRangeInSections(GenericEngineData.vdata, tmp, 4)) {
			Cnt++;
			DSEngineData.realtime_addr = tmp;
			break;
		}

		coderef2_addr = Dll_ScanForTemplate_Backward(&GenericEngineData, (unsigned char*) ScanData2,(unsigned char*) ScanMask2, sizeof(ScanMask2) - 1, coderef2_addr-1, 0x60);
	}
	
	if (Cnt <= 0) {
		LCPrintf(true, "[DPROTO]: %s: parsing error: realtime not found\n", __FUNCTION__);
		return false;
	}

	return true;
}

bool Parse_GetClientIDString() {
	uint32_t cstring_addr;
	uint32_t coderef_addr;
	uint32_t coderef2_addr;
	uint32_t tmp;
	int Cnt;

	/* Search for SV_GetClientIDString() function . It contains reference to string "VALVE_ID_LOOPBACK" */
	

	cstring_addr = Dll_FindString(&GenericEngineData, 0, "VALVE_ID_LOOPBACK", true);
	Cnt = 0;
	while (cstring_addr) {
		coderef_addr = Dll_FindRef_Push(&GenericEngineData.code, 0, cstring_addr);
		while (coderef_addr) {
			Cnt++;
			coderef2_addr = coderef_addr;

			coderef_addr = Dll_FindRef_Push(&GenericEngineData.code, coderef_addr, cstring_addr);
		}
		
		cstring_addr = Dll_FindString(&GenericEngineData, cstring_addr, "VALVE_ID_LOOPBACK", true);
	}

	if (Cnt <= 0) {
		LCPrintf(true, "[DPROTO]: %s: parsing error: SV_GetClientIDString() not found\n", __FUNCTION__);
		return false;
	} else if (Cnt > 1) {
		LCPrintf(true, "[DPROTO]: %s: parsing warning: %d candidates found for SV_GetClientIDString()\n", __FUNCTION__, Cnt);
	}
	
	/* Search for the beginning 
		55		push ebp
		8B EC	mov ebp, esp
	*/

	const char ScanData[] = "\x55\x8B\xEC";
	const char ScanMask[] = "\xFF\xFF\xFF";
	coderef_addr = coderef2_addr;
	coderef2_addr = coderef_addr - 1;
	coderef2_addr = Dll_ScanForTemplate_Backward(&GenericEngineData, (unsigned char*) ScanData,(unsigned char*) ScanMask, sizeof(ScanMask) - 1, coderef2_addr, 0x60);
	if (coderef2_addr) {
		DSEngineData.SV_GetClientIDString_addr = coderef2_addr;
	} else {
		LCPrintf(true, "[DPROTO]: %s: parsing error: beginning of SV_GetClientIDString() not found\n", __FUNCTION__);
		return false;
	}

	/* Search for ClientID offset in client_t
		05 ????0000	add eax, 0000????
	*/
	const char ScanData2[] = "\x05\x00\x00\x00\x00";
	const char ScanMask2[] = "\xFF\x00\x00\xFF\xFF";
	coderef2_addr = coderef_addr + 5;
	coderef2_addr = Dll_ScanForTemplate_Forward(&GenericEngineData, (unsigned char*) ScanData2,(unsigned char*) ScanMask2, sizeof(ScanMask2) - 1, coderef2_addr, 0x60);
	if (coderef2_addr) {
		tmp = *((uint32_t*)(coderef2_addr + 1));
		DSEngineData.ClientID_off = tmp;
	} else {
		LCPrintf(true, "[DPROTO]: %s: parsing error: ClientID offset in client_t not found\n", __FUNCTION__);
		return false;
	}

	return true;
}

bool Parse_GetIDString() {
	uint32_t cstring_addr;
	uint32_t coderef_addr;
	uint32_t coderef2_addr;
	int Cnt;

	/* Search for SV_GetIDString() function . It contains reference to string "STEAM_%u:%u:%u" */
	

	cstring_addr = Dll_FindString(&GenericEngineData, 0, "STEAM_%u:%u:%u", true);
	Cnt = 0;
	while (cstring_addr) {
		coderef_addr = Dll_FindRef_Push(&GenericEngineData.code, 0, cstring_addr);
		while (coderef_addr) {
			Cnt++;
			coderef2_addr = coderef_addr;

			coderef_addr = Dll_FindRef_Push(&GenericEngineData.code, coderef_addr, cstring_addr);
		}
		
		cstring_addr = Dll_FindString(&GenericEngineData, cstring_addr, "STEAM_%u:%u:%u", true);
	}

	if (Cnt <= 0) {
		LCPrintf(true, "[DPROTO]: %s: parsing error: SV_GetIDString() not found\n", __FUNCTION__);
		return false;
	} else if (Cnt > 1) {
		LCPrintf(true, "[DPROTO]: %s: parsing warning: %d candidates found for SV_GetIDString()\n", __FUNCTION__, Cnt);
	}
	
	/* Search for the beginning 
		55		push ebp
		8B EC	mov ebp, esp
	*/

	const char ScanData[] = "\x55\x8B\xEC";
	const char ScanMask[] = "\xFF\xFF\xFF";
	coderef_addr = coderef2_addr;
	coderef2_addr = coderef_addr - 1;

	coderef2_addr = Dll_ScanForTemplate_Backward(&GenericEngineData, (unsigned char*) ScanData,(unsigned char*) ScanMask, sizeof(ScanMask) - 1, coderef2_addr, 0x240);
	if (coderef2_addr) {
		DSEngineData.SV_GetIDString_addr = coderef2_addr;
	} else {
		LCPrintf(true, "[DPROTO]: %s: parsing error: beginning of SV_GetIDString() not found\n", __FUNCTION__);
		return false;
	}

	return true;
}

bool Parse_CheckCDKey() {
	uint32_t cstring_addr;
	uint32_t coderef_addr;
	uint32_t coderef2_addr;
	int Cnt;

	/* Search for SV_CheckCDKey() function . It contains reference to string "Expecting STEAM authentication USERID ticket!\n" */
	

	cstring_addr = Dll_FindString(&GenericEngineData, 0, "Expecting STEAM authentication USERID ticket!\n", true);
	Cnt = 0;
	while (cstring_addr) {
		coderef_addr = Dll_FindRef_Push(&GenericEngineData.code, 0, cstring_addr);
		while (coderef_addr) {
			Cnt++;
			coderef2_addr = coderef_addr;

			coderef_addr = Dll_FindRef_Push(&GenericEngineData.code, coderef_addr, cstring_addr);
		}
		
		cstring_addr = Dll_FindString(&GenericEngineData, cstring_addr, "Expecting STEAM authentication USERID ticket!\n", true);
	}

	if (Cnt <= 0) {
		LCPrintf(true, "[DPROTO]: %s: parsing error: SV_CheckCDKey() not found\n", __FUNCTION__);
		return false;
	} else if (Cnt > 1) {
		LCPrintf(true, "[DPROTO]: %s: parsing warning: %d candidates found for SV_CheckCDKey()\n", __FUNCTION__, Cnt);
	}
	
	/* Search for the beginning 
		55		push ebp
		8B EC	mov ebp, esp
	*/

	const char ScanData[] = "\x55\x8B\xEC";
	const char ScanMask[] = "\xFF\xFF\xFF";
	coderef_addr = coderef2_addr;
	coderef2_addr = coderef_addr - 1;
	coderef2_addr = Dll_ScanForTemplate_Backward(&GenericEngineData, (unsigned char*) ScanData,(unsigned char*) ScanMask, sizeof(ScanMask) - 1, coderef2_addr, 0x240);
	if (coderef2_addr) {
		DSEngineData.SV_CheckCDKey_addr = coderef2_addr;
	} else {
		LCPrintf(true, "[DPROTO]: %s: parsing error: beginning of SV_CheckCDKey() not found\n", __FUNCTION__);
		return false;
	}

	return true;
}

bool Parse_CheckUserInfo() {
	uint32_t cstring_addr;
	uint32_t coderef_addr;
	uint32_t coderef2_addr;
	int Cnt;

	/* Search for SV_CheckUserInfo() function . It contains reference to string "%s:  password failed\n" */
	

	cstring_addr = Dll_FindString(&GenericEngineData, 0, "%s:  password failed\n", true);
	Cnt = 0;
	while (cstring_addr) {
		coderef_addr = Dll_FindRef_Push(&GenericEngineData.code, 0, cstring_addr);
		while (coderef_addr) {
			Cnt++;
			coderef2_addr = coderef_addr;

			coderef_addr = Dll_FindRef_Push(&GenericEngineData.code, coderef_addr, cstring_addr);
		}
		
		cstring_addr = Dll_FindString(&GenericEngineData, cstring_addr, "%s:  password failed\n", true);
	}

	if (Cnt <= 0) {
		LCPrintf(true, "[DPROTO]: %s: parsing error: SV_CheckUserInfo() not found\n", __FUNCTION__);
		return false;
	} else if (Cnt > 1) {
		LCPrintf(true, "[DPROTO]: %s: parsing warning: %d candidates found for SV_CheckUserInfo()\n", __FUNCTION__, Cnt);
	}
	
	/* Search for the beginning 
		55		push ebp
		8B EC	mov ebp, esp
	*/

	const char ScanData[] = "\x55\x8B\xEC";
	const char ScanMask[] = "\xFF\xFF\xFF";
	coderef_addr = coderef2_addr;
	coderef2_addr = coderef_addr - 1;
	coderef2_addr = Dll_ScanForTemplate_Backward(&GenericEngineData, (unsigned char*) ScanData,(unsigned char*) ScanMask, sizeof(ScanMask) - 1, coderef2_addr, 0x240);
	if (coderef2_addr) {
		DSEngineData.SV_CheckUserInfo_addr = coderef2_addr;
	} else {
		LCPrintf(true, "[DPROTO]: %s: parsing error: beginning of SV_CheckUserInfo() not found\n", __FUNCTION__);
		return false;
	}

	return true;
}

bool Parse_ReadPackets() {
	uint32_t coderef_addr = 0;
	uint32_t coderef2_addr = 0;
	int Cnt = 0;

	/* Just find reference to pISteamMSU_HandleIncomingPacket */

	coderef_addr = Dll_FindRef_Prefix2(&GenericEngineData.code, 0, gpISteamMSU_HandleIncomingPacket_addr, 0x15FF, false);
	while (coderef_addr) {
		Cnt++;
		coderef2_addr = coderef_addr;
		
		coderef_addr = Dll_FindRef_Prefix2(&GenericEngineData.code, coderef_addr, gpISteamMSU_HandleIncomingPacket_addr, 0x15FF, false);
	}

	if (Cnt <= 0) {
		LCPrintf(true, "[DPROTO]: %s: parsing error: SV_ReadPackets() not found\n", __FUNCTION__);
		return false;
	} else if (Cnt > 1) {
		LCPrintf(true, "[DPROTO]: %s: parsing warning: %d candidates found for SV_ReadPackets()\n", __FUNCTION__, Cnt);
	}
	
	DSEngineData.ReadPackets__ISMSU_HandleIncoming__haddr = coderef2_addr + 2;
	return true;
}

bool Parse_HostError() {
	uint32_t cstring_addr;
	uint32_t coderef_addr;
	uint32_t coderef2_addr;
	int Cnt;

	/* Search for Host_Error() function. It contains reference to string "Host_Error: recursively entered" */
	

	cstring_addr = Dll_FindString(&GenericEngineData, 0, "Host_Error: recursively entered", true);
	Cnt = 0;
	while (cstring_addr) {
		coderef_addr = Dll_FindRef_Push(&GenericEngineData.code, 0, cstring_addr);
		while (coderef_addr) {
			Cnt++;
			coderef2_addr = coderef_addr;

			coderef_addr = Dll_FindRef_Push(&GenericEngineData.code, coderef_addr, cstring_addr);
		}
		
		cstring_addr = Dll_FindString(&GenericEngineData, cstring_addr, "Host_Error: recursively entered", true);
	}

	if (Cnt <= 0) {
		LCPrintf(true, "[DPROTO]: %s: parsing error: Host_Error() not found\n", __FUNCTION__);
		return false;
	} else if (Cnt > 1) {
		LCPrintf(true, "[DPROTO]: %s: parsing warning: %d candidates found for Host_Error()\n", __FUNCTION__, Cnt);
	}
	
	/* Search for the beginning 
		55		push ebp
		8B EC	mov ebp, esp
	*/

	const char ScanData[] = "\x55\x8B\xEC";
	const char ScanMask[] = "\xFF\xFF\xFF";
	coderef_addr = coderef2_addr;
	coderef2_addr = coderef_addr - 1;
	coderef2_addr = Dll_ScanForTemplate_Backward(&GenericEngineData, (unsigned char*) ScanData,(unsigned char*) ScanMask, sizeof(ScanMask) - 1, coderef2_addr, 0x40);
	if (coderef2_addr) {
		DSEngineData.Host_Error_addr = coderef2_addr;
	} else {
		LCPrintf(true, "[DPROTO]: %s: parsing error: beginning of Host_Error() not found\n", __FUNCTION__);
		return false;
	}

	return true;
}

bool Parse_ParseVoiceData() {
	uint32_t cstring_addr;
	uint32_t coderef_addr;
	uint32_t coderef2_addr;
	uint32_t tmp;
	bool bIsOk;
	int Cnt;

	DSEngineData.ParseVoiceData_HostError_haddr = 0;

	/* Search for SV_ParseVoiceData() function. It contains reference to string "SV_ParseVoiceData: invalid incoming packet.\n" */
	

	cstring_addr = Dll_FindString(&GenericEngineData, 0, "SV_ParseVoiceData: invalid incoming packet.\n", true);
	Cnt = 0;
	while (cstring_addr) {
		coderef_addr = Dll_FindRef_Push(&GenericEngineData.code, 0, cstring_addr);
		while (coderef_addr) {
			Cnt++;
			coderef2_addr = coderef_addr;

			coderef_addr = Dll_FindRef_Push(&GenericEngineData.code, coderef_addr, cstring_addr);
		}
		
		cstring_addr = Dll_FindString(&GenericEngineData, cstring_addr, "SV_ParseVoiceData: invalid incoming packet.\n", true);
	}

	if (Cnt <= 0) {
		return true;
	} else if (Cnt > 1) {
		LCPrintf(true, "[DPROTO]: %s: parsing warning: %d candidates found for Host_Error()\n", __FUNCTION__, Cnt);
	}

	/* Scan forward for Host_Error() call */
	const char ScanData2[] = "\xE8\x00\x00\x00\x00";
	const char ScanMask2[] = "\xFF\x00\x00\x00\x00";
	bIsOk = false;
	coderef_addr = coderef2_addr;
	coderef2_addr = Dll_ScanForTemplate_Forward(&GenericEngineData, (unsigned char*) ScanData2, (unsigned char*) ScanMask2, sizeof(ScanMask2) - 1, coderef2_addr, 0x30);
	while (coderef2_addr && (coderef2_addr - coderef_addr < 0x30)) {
		tmp = *((uint32_t*) (coderef2_addr + 1)) + coderef2_addr + 5;
		if (tmp == DSEngineData.Host_Error_addr) {
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



bool Parse_NetchanCreateFragments_() {
	uint32_t cstring_addr;
	uint32_t coderef_addr;
	uint32_t coderef2_addr;
	int Cnt;

	DSEngineData.CreateFragments__Calls = NULL;

	/* Search for Netchan_CreateFragments_() function. It contains reference to string "Compressing split packet (%d -> %d bytes)\n" */
	

	cstring_addr = Dll_FindString(&GenericEngineData, 0, "Compressing split packet (%d -> %d bytes)\n", true);
	Cnt = 0;
	while (cstring_addr) {
		coderef_addr = Dll_FindRef_Push(&GenericEngineData.code, 0, cstring_addr);
		while (coderef_addr) {
			Cnt++;
			coderef2_addr = coderef_addr;

			coderef_addr = Dll_FindRef_Push(&GenericEngineData.code, coderef_addr, cstring_addr);
		}
		
		cstring_addr = Dll_FindString(&GenericEngineData, cstring_addr, "Compressing split packet (%d -> %d bytes)\n", true);
	}

	if (Cnt <= 0) {
		LCPrintf(true, "[DPROTO]: %s: parsing error: Netchan_CreateFragments_() not found\n", __FUNCTION__);
		return false;
	} else if (Cnt > 1) {
		LCPrintf(true, "[DPROTO]: %s: parsing warning: %d candidates found for Netchan_CreateFragments_()\n", __FUNCTION__, Cnt);
	}

	/* Search for the beginning 
		55		push ebp
		8B EC	mov ebp, esp
	*/

	const char ScanData[] = "\x55\x8B\xEC";
	const char ScanMask[] = "\xFF\xFF\xFF";
	coderef_addr = coderef2_addr;
	coderef2_addr = coderef_addr - 1;
	coderef2_addr = Dll_ScanForTemplate_Backward(&GenericEngineData, (unsigned char*) ScanData,(unsigned char*) ScanMask, sizeof(ScanMask) - 1, coderef2_addr, 0x200);
	if (coderef2_addr) {
		DSEngineData.Netchan_CreateFragments__addr = coderef2_addr;
	} else {
		LCPrintf(true, "[DPROTO]: %s: parsing error: beginning of Netchan_CreateFragments_() not found\n", __FUNCTION__);
		return false;
	}

	/* Search for all references to Netchan_CreateFragments_ */

	coderef_addr = 0;
	coderef_addr = Dll_FindRef_Prefix1(&GenericEngineData.code, coderef_addr, DSEngineData.Netchan_CreateFragments__addr, 0xE8, true);
	while (coderef_addr) {
		CFuncAddr* cfa = new CFuncAddr(coderef_addr);
		cfa->Next = DSEngineData.CreateFragments__Calls;
		DSEngineData.CreateFragments__Calls = cfa;

		coderef_addr = Dll_FindRef_Prefix1(&GenericEngineData.code, coderef_addr, DSEngineData.Netchan_CreateFragments__addr, 0xE8, true);
	}

	if (DSEngineData.CreateFragments__Calls == NULL) {
		LCPrintf(true, "[DPROTO]: %s: parsing error: references to Netchan_CreateFragments_() not found\n", __FUNCTION__);
		return false;
	}
	return true;
}

bool Parse_CheckCertificate() {
	uint32_t cstring_addr;
	uint32_t coderef_addr;
	uint32_t coderef2_addr;
	int Cnt;

	/* Search for SV_CheckCertificate() function. It contains reference to string "Invalid authentication certificate length.\n" */
	

	cstring_addr = Dll_FindString(&GenericEngineData, 0, "Invalid authentication certificate length.\n", true);
	Cnt = 0;
	while (cstring_addr) {
		coderef_addr = Dll_FindRef_Push(&GenericEngineData.code, 0, cstring_addr);
		while (coderef_addr) {
			Cnt++;
			coderef2_addr = coderef_addr;

			coderef_addr = Dll_FindRef_Push(&GenericEngineData.code, coderef_addr, cstring_addr);
		}
		
		cstring_addr = Dll_FindString(&GenericEngineData, cstring_addr, "Invalid authentication certificate length.\n", true);
	}

	if (Cnt <= 0) {
		LCPrintf(true, "[DPROTO]: %s: parsing error: SV_CheckCertificate() not found\n", __FUNCTION__);
		return false;
	} else if (Cnt > 1) {
		LCPrintf(true, "[DPROTO]: %s: parsing warning: %d candidates found for SV_CheckCertificate()\n", __FUNCTION__, Cnt);
	}

	/* Search for the beginning 
		55		push ebp
		8B EC	mov ebp, esp
	*/

	const char ScanData[] = "\x55\x8B\xEC";
	const char ScanMask[] = "\xFF\xFF\xFF";
	coderef_addr = coderef2_addr;
	coderef2_addr = coderef_addr - 1;
	coderef2_addr = Dll_ScanForTemplate_Backward(&GenericEngineData, (unsigned char*) ScanData,(unsigned char*) ScanMask, sizeof(ScanMask) - 1, coderef2_addr, 0x140);
	if (coderef2_addr) {
		DSEngineData.SV_CheckCertificate_addr = coderef2_addr;
	} else {
		LCPrintf(true, "[DPROTO]: %s: parsing error: beginning of SV_CheckCertificate() not found\n", __FUNCTION__);
		return false;
	}

	return true;
}

bool Parse_QStrCpy() {
	uint32_t coderef2_addr;

	// find function by template
	const char ScanData2[] = "\x55\x8B\xEC\x8B\x45\x08\x85\xC0\x74\x15\x8B\x55\x0C\x85\xD2\x74\x0E\x8A\x0A\x84\xC9\x74\x08\x88\x08\x40\x42\x85\xC0\x75\xEE\xC6\x00\x00\x5D\xC3";
	const char ScanMask2[] = "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF";
	int numFound = 0;

	coderef2_addr = GenericEngineData.code.start;
	coderef2_addr = Dll_ScanForTemplate_Forward(&GenericEngineData, (unsigned char*) ScanData2, (unsigned char*) ScanMask2, sizeof(ScanMask2) - 1, coderef2_addr, 0x7FFFFFFF);
	while (coderef2_addr) {
		numFound++;
		DSEngineData.Q_strcpy_addr = coderef2_addr;
		coderef2_addr = Dll_ScanForTemplate_Forward(&GenericEngineData, (unsigned char*) ScanData2, (unsigned char*) ScanMask2, sizeof(ScanMask2) - 1, coderef2_addr+1, 0x7FFFFFFF);
	}

	if (numFound <= 0) {
		LCPrintf(true, "[DPROTO]: %s: parsing error: Q_StrCpy() not found\n", __FUNCTION__);
		return false;
	} else if (numFound > 1) {
		LCPrintf(true, "[DPROTO]: %s: parsing warning: %d candidates found for Q_StrCpy()\n", __FUNCTION__, numFound);
	}

	
	return true;
}

bool Parse_ParseCvarValue2() {
	uint32_t cstring_addr;
	uint32_t coderef_addr;
	uint32_t coderef2_addr;
	uint32_t tmp;
	int Cnt;

	DSEngineData.ParseCvarValue2_StrCpy_haddr = NULL;

	/* Search Parse_ParseCvarValue2 function. It contains reference to string "Cvar query response: name:%s, request ID %d, cvar:%s, value:%s\n" */

	cstring_addr = Dll_FindString(&GenericEngineData, 0, "Cvar query response: name:%s, request ID %d, cvar:%s, value:%s\n", true);
	Cnt = 0;
	while (cstring_addr) {
		coderef_addr = Dll_FindRef_Push(&GenericEngineData.code, 0, cstring_addr);
		while (coderef_addr) {
			Cnt++;
			coderef2_addr = coderef_addr;

			coderef_addr = Dll_FindRef_Push(&GenericEngineData.code, coderef_addr, cstring_addr);
		}
		
		cstring_addr = Dll_FindString(&GenericEngineData, cstring_addr, "Cvar query response: name:%s, request ID %d, cvar:%s, value:%s\n", true);
	}

	if (Cnt <= 0) {
		LCPrintf(true, "[DPROTO]: %s: parsing error: SV_ParseCvarValue2() not found\n", __FUNCTION__);
		return false;
	} else if (Cnt > 1) {
		LCPrintf(true, "[DPROTO]: %s: parsing warning: %d candidates found for SV_ParseCvarValue2()\n", __FUNCTION__, Cnt);
	}

	DSEngineData.SV_ParseCvarValue2_addr = coderef2_addr;

	/*
		Search for the Q_StrCpy call
	*/

	const char ScanData3[] = "\xE8\x00\x00\x00\x00";
	const char ScanMask3[] = "\xFF\x00\x00\x00\x00";
	coderef_addr = coderef2_addr;
	Cnt = 0;
	coderef2_addr = Dll_ScanForTemplate_Backward(&GenericEngineData, (unsigned char*) ScanData3,(unsigned char*) ScanMask3, sizeof(ScanMask3) - 1, coderef_addr, 0x60);
	while (coderef2_addr && coderef_addr - coderef2_addr < 0x60) {
		tmp = *((uint32_t*) (coderef2_addr + 1)) + coderef2_addr + 5;
		if (tmp == DSEngineData.Q_strcpy_addr) {
			Cnt++;
			DSEngineData.ParseCvarValue2_StrCpy_haddr = coderef2_addr;
		}

		coderef2_addr = Dll_ScanForTemplate_Backward(&GenericEngineData, (unsigned char*) ScanData3,(unsigned char*) ScanMask3, sizeof(ScanMask3) - 1, coderef2_addr, 0x60);
	}

	if (Cnt <= 0) {
		//seems that exploit fixed
		return true;
	} else if (Cnt > 1) {
		LCPrintf(true, "[DPROTO]: %s: parsing warning: %d candidates found for vulnerable code in SV_ParseCvarValue2()\n", __FUNCTION__, Cnt);
	}

	return true;
}
