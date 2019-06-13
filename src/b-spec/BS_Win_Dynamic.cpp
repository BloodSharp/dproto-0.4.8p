#include "osconfig.h"
#include "b-spec/BS_Win_Dynamic.h"
#include "dproto.h"
#include "swds_data.h"
#include "HookTools.h"
#include "bspec.h"
#include "cfg.h"
#include "dynpatcher_base.h"
#include "dynparser_win.h"


int CDECL VA_GetMaxClients_WDyn() {
	return psvs->max_clients;
}

clientid_t* CDECL VA_GetCIDByClient_WDyn(void* cl) {
	return (clientid_t*) (size_t(cl) + DSEngineData.ClientID_off);
}

void* CDECL VA_GetClientByCID_WDyn(clientid_t* cid) {
	return (void*) (size_t(cid) - DSEngineData.ClientID_off);
}

int CDECL VA_GetClientID_WDyn(void* cl) {
	return (size_t(cl) - size_t(psvs->clients)) / DSEngineData.client_t_size;
}

bool CDECL VA_IsClientActive_WDyn(int clid) {
	int* icl = (int*) (size_t(psvs->clients) + clid * DSEngineData.client_t_size);
	return (icl[0] || icl[1] || icl[3]);
}

bool VA_IsClientPlaying_WDyn(int clid) {
	int* icl = (int*) (size_t(psvs->clients) + clid * DSEngineData.client_t_size);
	return (icl[0] != 0);
}

float* VA_GetClientConnTime_WDyn(int clid) {
	float* icl = (float*) (size_t(psvs->clients) + clid * DSEngineData.client_t_size);
	return &icl[0x10];
}

int CDECL VA_IsServerSecure_WDyn(void) {
	return Steam_GSBSecure_func()?1:0;
}

int CDECL VA_StartAuth_WDyn(void* cl, netadr_t* addr, char* key, int len, int auth_type) {
	return Steam_NotifyClientConnect_func(cl, key, len);
}

void CDECL VA_ISMSHandle_WDyn(char* data, int len, int ip, int port) {
	return ISMSU_HandlePacket_func(data, len, ip, port);
}

bool BS_Probe_WDyn(const ProbeData_t* prData) {
	if (!ParseGenericDllData_PE(prData->hLib, &GenericEngineData))
		return false;

	if (!Parse_Imports())
		return false;

	if (!Parse_CheckCertificate())
		return false;

	if (!Parse_CheckProtocol()) {
		return false;
	}

	if (!Parse_SendServerInfo()) {
		return false;
	}

	if (!Parse_ConnectClient()) {
		return false;
	}

	if (!Parse_GetChallenge()) {
		return false;
	}

	if (!Parse_GSClientDenyHelper()) {
		return false;
	}

	if (!Parse_EntityInterface()) {
		return false;
	}

	if (!Parse_LogPrintServerVars()) {
		return false;
	}

	if (!Parse_ListId()) {
		return false;
	}

	if (!Parse_CheckTimeouts()) {
		return false;
	}

	if (!Parse_GetClientIDString()) {
		return false;
	}

	if (!Parse_GetIDString()) {
		return false;
	}

	if (!Parse_CheckCDKey()) {
		return false;
	}

	if (!Parse_CheckUserInfo()) {
		return false;
	}

	if (!Parse_ReadPackets()) {
		return false;
	}

	if (!Parse_HostError()) {
		return false;
	}

	if (!Parse_ParseVoiceData())
		return false;

	if (!Parse_NetchanCreateFragments_())
		return false;

	if (!Parse_QStrCpy())
		return false;

	if (!Parse_ParseCvarValue2())
		return false;

	return true;
}

void BS_PreInit_WDyn() {
	/* Initialize all addresses */
	cvar_vars_addr = DSEngineData.cvars_vars_addr;
	SV_RejectConnection_addr = DSEngineData.SV_RejectConnection_addr;
	SV_GetIDString_addr = DSEngineData.SV_GetIDString_addr;
	svs_addr = DSEngineData.svs_addr;
	MSG_WriteLong_addr = DSEngineData.MSG_WriteLong_addr;
	NET_SendPacket_addr = DSEngineData.NET_SendPacket_addr;
	userfilters_addr = DSEngineData.userfilters_addr;
	numuserfilters_addr = DSEngineData.numuserfilters_addr;
	realtime_addr = DSEngineData.realtime_addr;
	gEntityInterface_addr = DSEngineData.gEntityInterface_addr;

	// these needed by SV_GetClientIDString_rev
	SV_ConnectClient_addr = DSEngineData.SteamValidation_NotifyCC_haddr;
	SVC_GetChallenge_addr = DSEngineData.ChallengeGen_SendPacket_haddr;
	



	VA_Funcs.GetMaxClients = &VA_GetMaxClients_WDyn;
	VA_Funcs.GetCIDByClient = &VA_GetCIDByClient_WDyn;
	VA_Funcs.GetClientByCID = &VA_GetClientByCID_WDyn;
	VA_Funcs.GetClientID = &VA_GetClientID_WDyn;
	VA_Funcs.IsClientActive = &VA_IsClientActive_WDyn;
	VA_Funcs.IsClientPlaying = &VA_IsClientPlaying_WDyn;
	VA_Funcs.GetClientConnTime = &VA_GetClientConnTime_WDyn;

	VA_Funcs.IsServerSecure = &VA_IsServerSecure_WDyn;
	VA_Funcs.StartAuth = &VA_StartAuth_WDyn;
	VA_Funcs.ISMSHandle= &VA_ISMSHandle_WDyn;
}

bool BS_Init_WDyn(void* dllBase) {
	memcpy(&Steam_GSBSecure_func, &gISteamGS_BSecure_addr, 4);
	memcpy(&Steam_NotifyClientConnect_func, &DSEngineData.Steam_NotifyClientConnect_addr, 4);
	memcpy(&ISMSU_HandlePacket_func, &gISteamMSU_HandleIncomingPacket_addr, 4);
	memcpy(&Netchan_CreateFragments__func, &DSEngineData.Netchan_CreateFragments__addr, 4);
	return true;
}

__declspec(naked) void SendSrvInfo_WriteLongProto_WDyn() {
	__asm {
		mov eax, [esp+4] //sbuf
		push eax
		mov eax, [ebp+0xC] //client
		push eax
		call SendSrvInfo_WriteProto
		retn
	}
}


__declspec(naked) int CheckUserInfo_Helper_WDyn() {
	__asm {
		push ebp
		mov ebp, esp
		mov eax, [ebp+0xC]
		push eax
		mov eax, [ebp+0x8]
		push eax
		call CheckUserInfo
		test eax, eax
		jnz Cnt
		mov esp, ebp
		pop ebp
		ret

Cnt:
		sub esp, 0x24
		mov eax, DSEngineData.SV_CheckUserInfo_addr
		add eax, 6
		jmp eax

	}
}

__declspec(naked) void DenyHelper_Hooked_WDyn() {
	__asm {
		mov eax, [esp+8]
		cmp eax, 0xE
		ja _ret
		cmp eax, 7
		jz _ret

		push ebp
		mov ebp, esp
		mov eax, [ebp+0xC]
		mov edx, DSEngineData.GS_ClientDenyHelper_addr
		add edx, 6
		jmp edx

	_ret:
		retn 0xC

	}
}

char* CDECL ParseCvarValue2_StrCpyPatch(char* Dst, char* Src) {
	char* res = strncpy(Dst, Src, 255);
	Dst[255] = 0;
	return res;
}

__declspec(naked) int SV_CheckIPRestrictions_Hooked() {
	__asm {
		mov eax, 1
		retn
	}
}

bool BS_Patch_WDyn() {
	HookFunctionEx((void*)DSEngineData.SV_CheckProtocol_addr, &SV_CheckProtocol_rev, 0x56EC8B55, "#1");
	HookFunctionEx((void*)DSEngineData.SV_CheckCDKey_addr, &SV_CheckCDKey_rev, 0x8BEC8B55, "#2");
	HookFunction((void*) DSEngineData.AuthProtoValidation__LongJZ_haddr, (void*) DSEngineData.AuthProtoValidation__LongJZ_GoodAddr);
	HookFunction_call((void*) DSEngineData.SteamValidation_NotifyCC_haddr, (void*) &SteamConnect_hook);
	HookFunctionEx((void*) DSEngineData.SV_GetClientIDString_addr, &GetClientIDString_Helper, 0x8BEC8B55, "#5");
	HookFunctionEx((void*) DSEngineData.SV_GetIDString_addr, &SV_GetIDString_rev, 0x83EC8B55, "#6");
	HookFunction_call((void*) DSEngineData.SendServerInfo_WriteLongProto_haddr, &SendSrvInfo_WriteLongProto_WDyn);
	HookFunctionEx((void*) DSEngineData.SV_CheckUserInfo_addr, &CheckUserInfo_Helper_WDyn, 0x83EC8B55, "#10");

	static uint32_t ISMSU_HandlePacket_hook_addr = (uint32_t) &ISMSU_HandlePacket_hook;
	HookDWord((uint32_t*) DSEngineData.ReadPackets__ISMSU_HandleIncoming__haddr, (uint32_t) &ISMSU_HandlePacket_hook_addr);

	HookFunction_call((void*)DSEngineData.ChallengeGen_SendPacket_haddr, (void*) &SVC_GetChallenge_hook);
	HookFunction( (void*) DSEngineData.GS_ClientDenyHelper_addr, (void*) &DenyHelper_Hooked_WDyn);
	HookFunction( (void*) DSEngineData.SV_CheckIPRestrictions_addr, (void*) &SV_CheckIPRestrictions_Hooked);
	

	if (DSEngineData.ParseVoiceData_HostError_haddr) {
		PatchNOPs((void*)DSEngineData.ParseVoiceData_HostError_haddr, 5);
		LCPrintf(false, "[DPROTO]: SV_ParseVoiceData vulnerability patched.\n");
	}

	if (DSEngineData.ParseCvarValue2_StrCpy_haddr) {
		HookFunction_call((void*)DSEngineData.ParseCvarValue2_StrCpy_haddr, (void*) &ParseCvarValue2_StrCpyPatch);
		LCPrintf(false, "[DPROTO]: SV_ParseCvarValue2 vulnerability patched.\n");
	}

	CFuncAddr *cfa = DSEngineData.CreateFragments__Calls;
	while (cfa) {
		HookFunction_call((void*)cfa->Addr, (void*) &Netchan_CreateFragments__hooked);
		cfa = cfa->Next;
	}

	return true;
}

const char* CDECL BS_GetBuildDescr_WDyn() {
	return "<Windows p48 Dynamic Patcher>";
}

void BS_Register_WDyn() {
	PatchingFuncs_s cfuncs;
	cfuncs.GetBuildDescription = &BS_GetBuildDescr_WDyn;
	cfuncs.Probe = &BS_Probe_WDyn;
	cfuncs.PreInit = &BS_PreInit_WDyn;
	cfuncs.Init = &BS_Init_WDyn;
	cfuncs.Patch = &BS_Patch_WDyn;
	RegisterPFuncs(&cfuncs);
}