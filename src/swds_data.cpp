#include "osconfig.h"
#include "swds_data.h"
#include <string.h>
#include <stdlib.h>
#include "cfg.h"

#include "bspec.h"

size_t SV_CheckProtocol_off = 0;
size_t SV_GetClientIDString_off = 0;
size_t SV_GetIDString_off = 0;
size_t SV_RejectConnection_off = 0;
size_t svs_off = 0;
size_t SV_CheckCDKey_off = 0;
size_t SV_ConnectClient_off = 0;
size_t SV_SendServerInfo_off = 0;
size_t MSG_WriteLong_off = 0;
size_t ISMSU_HandlePacket_ioff = 0;
size_t NCmd_Argv_off = 0;
size_t NET_SendPacket_off = 0;
size_t RealTime_off = 0;
size_t SV_CheckUserInfo_off = 0;
size_t Steam_GSBSecure_off = 0;
size_t gEntityInterface_off = 0;

size_t Info_ValueForKey_off = 0;
size_t Info_SetValueForStarKey_off = 0;
size_t Info_RemoveKey_off = 0;

size_t cvar_vars_off = 0;
size_t SVC_GetChallenge_off = 0;
size_t Steam_NotifyClientConnect_off = 0;
size_t GSClientDenyHelper_off = 0;
size_t realtime_off = 0;
size_t userfilters_off = 0;
size_t numuserfilters_off = 0;

size_t SV_CheckProtocol_addr = 0;
size_t SV_GetClientIDString_addr = 0;
size_t SV_GetIDString_addr = 0;
size_t SV_RejectConnection_addr = 0;
size_t svs_addr = 0;
size_t SV_CheckCDKey_addr = 0;
size_t SV_ConnectClient_addr = 0;
size_t SV_SendServerInfo_addr = 0;
size_t SV_CheckUserInfo_addr = 0;
size_t SVC_GetChallenge_addr = 0;
size_t NET_SendPacket_addr = 0;
size_t MSG_WriteLong_addr = 0;
size_t cvar_vars_addr = 0;
size_t SV_ConnectionlessPacket_addr = 0;

size_t ISMSU_HandlePacket_iaddr = 0;
size_t Steam_NotifyClientConnect_addr = 0;
size_t Steam_GSBSecure_addr = 0;
size_t ISMSU_HandlePacket_addr = 0;
size_t GSClientDenyHelper_addr = 0;
size_t realtime_addr = 0;
size_t userfilters_addr = 0;
size_t numuserfilters_addr = 0;
size_t gEntityInterface_addr = 0;

size_t Info_ValueForKey_addr = 0;
size_t Info_SetValueForStarKey_addr = 0;
size_t Info_RemoveKey_addr = 0;
size_t Info_RemovePrefixedKeys_addr = 0;


SV_RejectConnection_proto SV_RejectConnection_func;
SV_GetIDString_proto SV_GetIDString_func;
MSG_WriteLong_proto MSG_WriteLong_func;
ISMSU_HandlePacket_proto ISMSU_HandlePacket_func;
NCmd_Argv_proto NCmd_Argv_func;
NET_SendPacket_proto NET_SendPacket_func;
Steam_GSBSecure_proto Steam_GSBSecure_func;
Steam_NotifyClientConnect_proto Steam_NotifyClientConnect_func;
SV_ConnectionlessPacket_proto SV_ConnectionlessPacket_func;

svs_t *psvs;
cvar_t** cvar_vars_v;
net_message_t* pnet_message;
netadr_t* pnet_from;

#define DP_BINDOFFSET(v, o) { if (v == 0 && (o)) v = (o) + (size_t)dllBase; }
bool SwdsData_Bind(int build, void* dllBase) {
	DP_BINDOFFSET(SV_CheckProtocol_addr, SV_CheckProtocol_off);
	DP_BINDOFFSET(SV_GetClientIDString_addr, SV_GetClientIDString_off);
	DP_BINDOFFSET(SV_GetIDString_addr, SV_GetIDString_off);
	DP_BINDOFFSET(SV_RejectConnection_addr, SV_RejectConnection_off);
	DP_BINDOFFSET(svs_addr, svs_off);
	DP_BINDOFFSET(SV_CheckCDKey_addr, SV_CheckCDKey_off);
	DP_BINDOFFSET(SV_ConnectClient_addr, SV_ConnectClient_off);
	DP_BINDOFFSET(SV_SendServerInfo_addr, SV_SendServerInfo_off);
	DP_BINDOFFSET(MSG_WriteLong_addr, MSG_WriteLong_off);
	DP_BINDOFFSET(NET_SendPacket_addr, NET_SendPacket_off);
	DP_BINDOFFSET(SV_CheckUserInfo_addr, SV_CheckUserInfo_off);
	DP_BINDOFFSET(cvar_vars_addr, cvar_vars_off);
	DP_BINDOFFSET(SVC_GetChallenge_addr, SVC_GetChallenge_off);
	DP_BINDOFFSET(GSClientDenyHelper_addr, GSClientDenyHelper_off);
	DP_BINDOFFSET(realtime_addr, realtime_off);
	DP_BINDOFFSET(userfilters_addr, userfilters_off);
	DP_BINDOFFSET(numuserfilters_addr, numuserfilters_off);
	DP_BINDOFFSET(gEntityInterface_addr, gEntityInterface_off);

	if (gEntityInterface_addr)
		memcpy(&gOrigEntityInterface, &gEntityInterface_addr, 4);

	if (!CurPatchData->Init(dllBase)) {
		return false;
	}

	memcpy(&cvar_vars_v, &cvar_vars_addr, 4);
	memcpy(&SV_RejectConnection_func, &SV_RejectConnection_addr, 4);
	memcpy(&SV_GetIDString_func, &SV_GetIDString_addr, 4);
	memcpy(&psvs, &svs_addr, 4);
	memcpy(&MSG_WriteLong_func, &MSG_WriteLong_addr, 4);
	memcpy(&NET_SendPacket_func, &NET_SendPacket_addr, 4);

	memcpy(&p_userfilters, &userfilters_addr, 4);
	memcpy(&p_numuserfilters, &numuserfilters_addr, 4);
	memcpy(&prealtime, &realtime_addr, 4);

	
	return true;
}

bool SwdsData_Init(int build) {
	void* dbase = GetModuleHandleA("swds.dll");
	int i;
	if (dbase == NULL) {
		LCPrintf(true, "[DPROTO]: Failed to locate swds.dll\n");
		return false;
	}
	LCPrintf(false, "[DPROTO]: Found swds.dll at %p\n", dbase);

	CurPatchData = NULL;

	ProbeData_t prData;
	memset(&prData, 0, sizeof(prData));
	prData.hLib = dbase;
	for (i = 0; i < PFDataCount; i++) {
		if (PFData[i].Probe(&prData)) 
			CurPatchData = &PFData[i];
	}
	if (!CurPatchData) {
		LCPrintf(true, "[DPROTO]: Sorry, this engine does not supported\n");
		return false;
	}

	CurPatchData->PreInit();

	if (SwdsData_Bind(build, dbase)) {
		return true;
	}
	return false;
}