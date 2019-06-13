#include "osconfig.h"
#include "engine_data.h"
#include "HookTools.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <dlfcn.h>
#include <unistd.h>

#include "cfg.h"
#include "bspec.h"

size_t SV_CheckProtocol_addr = 0;
size_t SV_GetClientIDString_addr = 0;
size_t SV_GetIDString_addr = 0;
size_t SV_RejectConnection_addr = 0;
size_t svs_addr = 0;
size_t SV_CheckCDKey_addr = 0;
size_t SV_ConnectClient_addr = 0;
size_t CSteamServer__ClientDenyHelper_addr = 0;
size_t SV_SendServerInfo_addr = 0;
size_t MSG_WriteLong_addr = 0;
size_t ISMSU_HandlePacket_addr = 0;
size_t NET_SendPacket_addr = 0;
size_t SV_CheckUserInfo_addr = 0;
size_t Steam_GSBSecure_addr = 0;
size_t SV_ReadPackets_addr = 0;
size_t CheckUserName_addr = 0;
size_t SV_CheckForDuplicateNames_addr = 0;
size_t SVC_GetChallenge_addr = 0;
size_t Steam_NotifyClientConnect_addr = 0;
size_t cvar_vars_addr = 0;
size_t COM_BuildNumber_addr = 0;
size_t net_from_addr = 0;
size_t net_message_addr = 0;
size_t SV_ConnectionlessPacket_addr = 0;
size_t COM_Munge2_addr = 0;
size_t gEntityInterface_addr = 0;
size_t GSClientDenyHelper_addr = 0;

size_t Info_ValueForKey_addr = 0;
size_t Info_SetValueForStarKey_addr = 0;
size_t Info_RemoveKey_addr = 0;
size_t Info_RemovePrefixedKeys_addr = 0;

//for old engines
size_t SV_FinishCertificateCheck_addr = 0;
size_t ValveAuth_Init_addr = 0;
size_t SV_StartSteamValidation_addr = 0;
size_t SV_StartSteamValidation_jmp = 0;

SV_RejectConnection_proto SV_RejectConnection_func = NULL;
SV_GetIDString_proto SV_GetIDString_func = NULL;
MSG_WriteLong_proto MSG_WriteLong_func = NULL;
SV_ConnectionlessPacket_proto SV_ConnectionlessPacket_func = NULL;
ISMSU_HandlePacket_proto ISMSU_HandlePacket_func = NULL;
NET_SendPacket_proto NET_SendPacket_func = NULL;
Steam_GSBSecure_proto Steam_GSBSecure_func = NULL;
Steam_NotifyClientConnect_proto Steam_NotifyClientConnect_func = NULL;
cvar_t** cvar_vars_v = NULL;
SV_StartSteamValidation_proto SV_StartSteamValidation_func = NULL;
COM_BuildNumber_proto COM_BuildNumber_func = NULL;
CheckUserInfo_proto CheckUserInfo_func = NULL;
net_message_t* pnet_message;
netadr_t* pnet_from;
svs_t *psvs;

char MBuffer[32768];

const char* GetFileName(const char *fpath) {
	int sl = strlen(fpath);
	const char *cp = fpath + sl;
	while (size_t(cp) > size_t(fpath)) {
		if (*cp == '\\' || *cp == '/') {
			return cp+1;
		}
		cp--;
	}
	return cp;
}

void* LocateLib(const char* libname) {
	char fname[128];
	char linebuf[512];
	char clib[256];
	const char *clp;
	FILE *fl;
	int sl;
	void* RegStart;
	void* RegEnd;
	Dl_info dli;

	sprintf(fname, "/proc/%d/maps", getpid());
	fl = fopen(fname, "r");
	if (fl == NULL) {
		return NULL;
	}

	setbuffer(fl, MBuffer, sizeof(MBuffer));
	while (fgets(linebuf, sizeof(linebuf), fl)) {
		sl = sscanf(linebuf, "%x-%x %s %s %s %s %s", &RegStart, &RegEnd, fname, fname, fname, fname, clib);
		if (sl != 7) {
			continue;
		}

		if (dladdr(RegStart, &dli) == 0) {
			continue;
		}

		clp = GetFileName(dli.dli_fname);
		if (strcmp(libname, clp) == 0) {
			fclose(fl);
			return dli.dli_fbase;
		}
	}
	fclose(fl);
	return NULL;
}


bool FindSymbol(void* hlib, const char* sName, uint32_t* pSym) {
	uint32_t csym =(uint32_t) dlsym(hlib, sName);
	if (csym == 0) {
		LCPrintf(true, "[DPROTO]: Cant Resolve '%s'\n", sName);
		return false;
	}
	*pSym = csym;
	return true;
}

int EngineData_Init(int build) {
	void* lib;
	void* slib;
	int Sym;
	int i;
	bool ires = false;
	char* EngineFileName = NULL;
	char* EngineName = NULL;
	
	lib = LocateLib("engine_i686.so");
	if (lib == NULL) {
		lib = LocateLib("engine_amd.so");
		if (lib == NULL) {
			lib = LocateLib("engine_i486.so");
			if (lib == NULL) {
				LCPrintf(true, "[DPROTO]: Cant locate engine_i686.so\n");
				return 0;
			} else {
				EngineName = "engine_i486.so";
				EngineFileName = "./engine_i486.so";
			}
		} else {
			EngineName = "engine_amd.so";
			EngineFileName = "./engine_amd.so";
		}
	} else {
		EngineName = "engine_i686.so";
		EngineFileName = "./engine_i686.so";
	}

	LCPrintf(false, "[DPROTO]: %s found at %p\n", EngineName, lib);
	slib = dlopen(EngineFileName, RTLD_NOW);
	if (slib == NULL) {
		LCPrintf(true, "[DPROTO]: Cant load '%s'\n", EngineFileName);
		return 0;
	}

	if (!FindSymbol(slib, "SV_ConnectClient", &SV_ConnectClient_addr)) return 0;
	if (!FindSymbol(slib, "SV_SendServerinfo", &SV_SendServerInfo_addr)) return 0;
	if (!FindSymbol(slib, "NET_SendPacket", &NET_SendPacket_addr)) return 0;
	if (!FindSymbol(slib, "SV_RejectConnection", &SV_RejectConnection_addr)) return 0;
	if (!FindSymbol(slib, "SV_GetIDString", &SV_GetIDString_addr)) return 0;
	if (!FindSymbol(slib, "SV_GetClientIDString", &SV_GetClientIDString_addr)) return 0;
	if (!FindSymbol(slib, "MSG_WriteLong", &MSG_WriteLong_addr)) return 0;
	if (!FindSymbol(slib, "SV_ReadPackets", &SV_ReadPackets_addr)) return 0;
	if (!FindSymbol(slib, "SV_CheckUserInfo", &SV_CheckUserInfo_addr)) return 0;
	if (!FindSymbol(slib, "SV_CheckForDuplicateNames", &SV_CheckForDuplicateNames_addr)) return 0;
	if (!FindSymbol(slib, "SVC_GetChallenge", &SVC_GetChallenge_addr)) return 0;
	if (!FindSymbol(slib, "COM_BuildNumber__Fv", &COM_BuildNumber_addr)) return 0;
	if (!FindSymbol(slib, "SV_ConnectionlessPacket", &SV_ConnectionlessPacket_addr)) return 0;
	if (!FindSymbol(slib, "net_from", &net_from_addr)) return 0;
	if (!FindSymbol(slib, "net_message", &net_message_addr)) return 0;
	if (!FindSymbol(slib, "gEntityInterface", &gEntityInterface_addr)) return 0;

	memcpy(&COM_BuildNumber_func, &COM_BuildNumber_addr, 4);

	FILE *fl = fopen(EngineFileName, "rb");
	int EngineSize;
	void* EngineBuf;
	if (fl == NULL) {
		LCPrintf(true, "[DPROTO]: Failed to open '%s' for read\n", EngineFileName);
		return 0;
	}

	fseek(fl, 0, SEEK_END);
	EngineSize = ftell(fl);
	fseek(fl, 0, SEEK_SET);


	if (EngineSize < 0)
		EngineSize = 0;
	EngineBuf = malloc(EngineSize + 4);
	fread(EngineBuf, 1, EngineSize, fl);

	fclose(fl);

	ProbeData_t prData;
	memset(&prData, 0, sizeof(prData));
	prData.hLib = slib;
	prData.libBase = lib;
	prData.libFileBase = EngineBuf;
	prData.libFileSize = EngineSize;

	CurPatchData = NULL;
	for (i = 0; i < PFDataCount; i++) {
		if (PFData[i].Probe(&prData)) {
			CurPatchData = &PFData[i];
			break;
		}
	}

	free(EngineBuf);

	if (!CurPatchData) {
		LCPrintf(true, "Sorry, this version of engine does not supported\n");
		dlclose(slib);
		return 0;
	}
	

	if (!FindSymbol(slib, "svs", &svs_addr)) return 0;
	if (!FindSymbol(slib, "cvar_vars", &cvar_vars_addr)) return 0;

	memcpy(&SV_RejectConnection_func, &SV_RejectConnection_addr, 4);
	memcpy(&MSG_WriteLong_func, &MSG_WriteLong_addr, 4);
	
	memcpy(&NET_SendPacket_func, &NET_SendPacket_addr, 4);
	memcpy(&SV_ConnectionlessPacket_func, &SV_ConnectionlessPacket_addr, 4);
	
	memcpy(&cvar_vars_v, &cvar_vars_addr, 4);
	memcpy(&psvs, &svs_addr, 4);
	memcpy(&pnet_message, &net_message_addr, 4);
	memcpy(&pnet_from, &net_from_addr, 4);
	memcpy(&gOrigEntityInterface, &gEntityInterface_addr, 4);

	
	CurPatchData->PreInit();
	ires = CurPatchData->Init(slib);
	
	dlclose(slib);

	return ires?1:0;
}

