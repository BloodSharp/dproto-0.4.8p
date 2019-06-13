#include "osconfig.h"
#include "dproto.h"
#include "engine_data.h"
#include "HookTools.h"
#include "bspec.h"
#include "dynpatcher_base.h"
#include "dynparser_linux.h"

int CDECL VA_GetMaxClients_LDyn() {
	return psvs->max_clients;
}

clientid_t* CDECL VA_GetCIDByClient_LDyn(void* cl) {
	return (clientid_t*) (size_t(cl) + DSEngineData.ClientID_off);
}

void* CDECL VA_GetClientByCID_LDyn(clientid_t* cid) {
	return (void*) (size_t(cid) - DSEngineData.ClientID_off);
}

int CDECL VA_GetClientID_LDyn(void* cl) {
	return (size_t(cl) - size_t(psvs->clients)) / DSEngineData.client_t_size;
}

bool CDECL VA_IsClientActive_LDyn(int clid) {
	int* icl = (int*) (size_t(psvs->clients) + clid * DSEngineData.client_t_size);
	return (icl[0] || icl[1] || icl[3]);
}

bool CDECL VA_IsClientPlaying_LDyn(int clid) {
	int* icl = (int*) (size_t(psvs->clients) + clid * DSEngineData.client_t_size);
	return (icl[0]);
}

float* CDECL VA_GetClientConnTime_LDyn(int clid) {
	float* icl = (float*) (size_t(psvs->clients) + clid * DSEngineData.client_t_size);
	return &icl[0xF];
}


int CDECL VA_StartAuth_LDyn(void* cl, netadr_t* addr, char* key, int len, int auth_type) {
	return Steam_NotifyClientConnect_func(cl, key, len);
}

int CDECL VA_IsServerSecure_LDyn() {
	return Steam_GSBSecure_func()?1:0;
}

void CDECL VA_ISMSHandle_LDyn(char* data, int len, int ip, int port) {
	ISMSU_HandlePacket_func(data, len, ip, port);
}

int STDCALL CheckProtocol_CHelper_LDyn(int cproto) {
	return SV_CheckProtocol_rev(pnet_from, cproto);
}

__declspec(naked) void CheckProtocol_AsmHelper_LDyn() {
	__asm {
		push esi
		mov eax, pnet_from
		push eax
		call SV_CheckProtocol_rev
		add esp, 8
		test eax, eax
		jz __dpfail2
		mov eax, DSEngineData.CheckProto_GoodRet_addr
		jmp eax

		__dpfail2:
		mov eax, DSEngineData.CheckProto_BadRet_addr
		jmp eax
	}
}

__declspec(naked) void CheckCDKey_Helper_LDyn() {
	__asm {
		mov eax, LastUserInfo
		push eax
		mov eax, DSEngineData.ConnectClient_CDKey_soff
		add eax, ebp
		push eax
		mov eax, DSEngineData.ConnectClient_AuthProto_soff
		add eax, ebp
		mov eax, [eax]
		push eax
		mov eax, pnet_from
		push eax
		call SV_CheckCDKey_rev
		add esp, 0x10
		test eax, eax
		jz __cdfail2
		mov eax, DSEngineData.CheckCDKey_GoodRet_addr
		jmp eax

		__cdfail2:
		mov eax, DSEngineData.CheckProto_BadRet_addr
		jmp eax
	}
}


int CDECL CheckUserInfo_CHelper_LDyn(netadr_t *client_addr, char *UInfo, int bIsReconnecting, int UserSlot, char* ResultName) {
	if (CheckUserInfo(client_addr, UInfo)) {
		return CheckUserInfo_func(client_addr, UInfo, bIsReconnecting, UserSlot, ResultName);
	} else 
		return 0;
}

__declspec(naked) void SendSrvInfo_WriteLongProto_LDyn() {
	__asm {
		mov eax, [esp+4] //sbuf
		push eax
		mov eax, [ebp+0xC] //client
		push eax
		call SendSrvInfo_WriteProto
		retn
	}
}

__declspec(naked) void DenyHelper_Hooked_WDyn() {
	__asm {
		mov eax, [esp+8]
		cmp eax, 0xE
		ja _ret
		cmp eax, 7
		jz _ret

		mov eax, DSEngineData.GSClientDenyHelper_addr
		jmp eax

	_ret:
		retn 0xC

	}
}

char* CDECL ParseCvarValue2_StrCpyPatch(char* Dst, char* Src) {
	char* res = strncpy(Dst, Src, 255);
	Dst[255] = 0;
	return res;
}

void CDECL BS_PreInit_LDyn() {
}

bool CDECL BS_Probe_LDyn(const ProbeData_t* prData) {
	if (!ParseGenericDllData_ELF(prData->libBase, prData->libFileBase, prData->libFileSize, &GenericEngineData)) {
		LCPrintf(true, "[DPROTO]: Failed to parse generic ELF data\n");
		return false;
	}

	DSEngineData.hLib = prData->hLib;
	DSEngineData.libBase = prData->libBase;

	if (!Parse_BaseFunctions()) {
		LCPrintf(true, "[DPROTO]: Failed to find symbols addrs\n");
		return false;
	}

	if (!Parse_Jumps()) {
		LCPrintf(true, "[DPROTO]: Failed to find jumps to functions\n");
		return false;
	}

	if (!Parse_ConnectClient()) {
		LCPrintf(true, "[DPROTO]: Parse_ConnectClient() failed\n");
		return false;
	}

	if (!Parse_SendServerInfo()) {
		LCPrintf(true, "[DPROTO]: Parse_SendServerInfo() failed\n");
		return false;
	}

	if (!Parse_ReadPackets()) {
		LCPrintf(true, "[DPROTO]: Parse_ReadPackets() failed\n");
		return false;
	}

	if (!Parse_GetChallenge()) {
		LCPrintf(true, "[DPROTO]: Parse_GetChallenge() failed\n");
		return false;
	}

	if (! Parse_GetClientIDString()) {
		LCPrintf(true, "[DPROTO]:  Parse_GetClientIDString() failed\n");
		return false;
	}

	if (!Parse_CheckTimeouts()) {
		LCPrintf(true, "[DPROTO]: Parse_CheckTimeouts() failed\n");
		return false;
	}

	if (!Parse_ParseVoiceData()) {
		LCPrintf(true, "[DPROTO]: Parse_ParseVoiceData() failed\n");
		return false;
	}

	if (!Parse_ParseCvarValue2()) {
		LCPrintf(true, "[DPROTO]: Parse_ParseCvarValue2() failed\n");
		return false;
	}

/*
	LCPrintf(false, "[DPROTO]: Dumping Addrs:\n", __FUNCTION__);
	LCPrintf(false, "[DPROTO]: \tCheckProto_GoodRet_addr = 0x%.8X (0x%.8X)\n", DSEngineData.CheckProto_GoodRet_addr, DSEngineData.CheckProto_GoodRet_addr - (uint32_t)prData->libBase);
	LCPrintf(false, "[DPROTO]: \tCheckProto_BadRet_addr = 0x%.8X (0x%.8X)\n", DSEngineData.CheckProto_BadRet_addr, DSEngineData.CheckProto_BadRet_addr - (uint32_t)prData->libBase);
	LCPrintf(false, "[DPROTO]: \tCheckProto_haddr = 0x%.8X (0x%.8X)\n", DSEngineData.CheckProto_haddr, DSEngineData.CheckProto_haddr - (uint32_t)prData->libBase);
	LCPrintf(false, "[DPROTO]: \tConnectClient_CDKey_soff = 0x%.8X\n", DSEngineData.ConnectClient_CDKey_soff);
	LCPrintf(false, "[DPROTO]: \tConnectClient_AuthProto_soff = 0x%.8X\n", DSEngineData.ConnectClient_AuthProto_soff);
	LCPrintf(false, "[DPROTO]: \tNetchan_CreateFragments__addr = 0x%.8X (0x%.8X)\n", DSEngineData.Netchan_CreateFragments__addr, DSEngineData.Netchan_CreateFragments__addr - (uint32_t)prData->libBase);
	
	LCPrintf(true, "[DPROTO]: %s: OK\n", __FUNCTION__);
*/
	
	return true;
}


bool CDECL BS_Init_LDyn(void* hlib) {
	size_t addr;
	if (!FindSymbol(hlib, "Steam_GSBSecure", &Steam_GSBSecure_addr)) return 0;
	if (!FindSymbol(hlib, "Steam_NotifyClientConnect", &Steam_NotifyClientConnect_addr)) return 0;
	if (!FindSymbol(hlib, "ISteamMasterServerUpdater_HandleIncomingPacket", &ISMSU_HandlePacket_addr)) return 0;	
	if (!FindSymbol(hlib, "OnGSClientDenyHelper__13CSteam3ServerP8client_s11EDenyReasonPCc", &GSClientDenyHelper_addr)) return 0;

	if (!FindSymbol(hlib, "userfilters", &addr)) return 0;
	memcpy(&p_userfilters, &addr, 4);
	if (!FindSymbol(hlib, "numuserfilters", &addr)) return 0;
	memcpy(&p_numuserfilters, &addr, 4);
	if (!FindSymbol(hlib, "realtime", &addr)) return 0;
	memcpy(&prealtime, &addr, 4);
	

	memcpy(&ISMSU_HandlePacket_func, &ISMSU_HandlePacket_addr, 4);
	memcpy(&Steam_GSBSecure_func, &Steam_GSBSecure_addr, 4);
	memcpy(&Steam_NotifyClientConnect_func, &Steam_NotifyClientConnect_addr, 4);
	memcpy(&CheckUserInfo_func, &DSEngineData.SV_CheckUserInfo_addr, 4);
	memcpy(&Netchan_CreateFragments__func, &DSEngineData.Netchan_CreateFragments__addr, 4);

	
	VA_Funcs.GetMaxClients = &VA_GetMaxClients_LDyn;
	VA_Funcs.GetCIDByClient = &VA_GetCIDByClient_LDyn;
	VA_Funcs.GetClientByCID = &VA_GetClientByCID_LDyn;
	VA_Funcs.GetClientID = &VA_GetClientID_LDyn;
	VA_Funcs.IsClientActive = &VA_IsClientActive_LDyn;
	VA_Funcs.IsClientPlaying = &VA_IsClientPlaying_LDyn;
	VA_Funcs.GetClientConnTime = &VA_GetClientConnTime_LDyn;
	VA_Funcs.StartAuth = &VA_StartAuth_LDyn;
	VA_Funcs.IsServerSecure = &VA_IsServerSecure_LDyn;
	VA_Funcs.ISMSHandle = &VA_ISMSHandle_LDyn;
	return true;
}
	
bool CDECL BS_Patch_LDyn() {
	HookFunction( (void*) DSEngineData.CheckProto_haddr, (void*) &CheckProtocol_AsmHelper_LDyn);
	HookFunction( (void*) DSEngineData.SV_CheckUserInfo_jaddr, (void*) &CheckUserInfo_CHelper_LDyn);
	HookFunction( (void*) DSEngineData.CheckCDKey_haddr, (void*) &CheckCDKey_Helper_LDyn);
	HookFunction( (void*) DSEngineData.ValidationChecking_haddr, (void*) DSEngineData.ValidationChecking_GoodRet_addr);
	HookFunction_call( (void*) DSEngineData.SteamValidationCheck_haddr, (void*) &SteamConnect_hook);
	HookFunction ((void*) DSEngineData.ConnectClient_IPRangeChecking_haddr, (void*) DSEngineData.ConnectClient_IPRangeChecking_GoodRet_addr);
	
	
	HookFunction_call( (void*) DSEngineData.ProtocolWriteCode_haddr, (void*) &SendSrvInfo_WriteLongProto_LDyn);
	
	HookFunction_call( (void*) DSEngineData.ISMSU_HandlePacket_haddr, (void*) &ISMSU_HandlePacket_hook);

	HookFunction((void*) DSEngineData.SV_GetClientIDString_addr,(void*) &GetClientIDString_Helper);
	HookFunction((void*) DSEngineData.SV_GetIDString_addr,(void*) &SV_GetIDString_rev);
	HookFunction_call((void*)DSEngineData.GetChallenge_SendPacket_haddr, (void*) &SVC_GetChallenge_hook);
	
	HookFunction((void*) DSEngineData.GSClientDenyHelper_jaddr,(void*) &DenyHelper_Hooked_WDyn);

	if (DSEngineData.ParseVoiceData_HostError_haddr) {
		PatchNOPs((void*)DSEngineData.ParseVoiceData_HostError_haddr, 5);
		LCPrintf(false, "[DPROTO]: SV_ParseVoiceData vulnerability patched.\n");
	}

	if (DSEngineData.ParseCvarValue2_StrCpy_haddr) {
		HookFunction_call((void*)DSEngineData.ParseCvarValue2_StrCpy_haddr, (void*) &ParseCvarValue2_StrCpyPatch);
		LCPrintf(false, "[DPROTO]: SV_ParseCvarValue2 vulnerability patched.\n");
	}

	HookFunction((void*)DSEngineData.Netchan_CreateFragments__jaddr, (void*) &Netchan_CreateFragments__hooked);
	return true;
}

const char* BS_GetBuildDescr_LDyn() {
	return "<Dynamic p48 Linux patcher>";
}


void BS_Register_LDyn() {
	PatchingFuncs_s cfuncs;
	cfuncs.GetBuildDescription = &BS_GetBuildDescr_LDyn;
	cfuncs.Probe = &BS_Probe_LDyn;
	cfuncs.PreInit = &BS_PreInit_LDyn;
	cfuncs.Init = &BS_Init_LDyn;
	cfuncs.Patch = &BS_Patch_LDyn;
	RegisterPFuncs(&cfuncs);
}
