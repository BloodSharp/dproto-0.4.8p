#include "osconfig.h"
#include <stdio.h>
#include <string.h>

#include <extdll.h>
#include <meta_api.h>
#include "pm_defs.h"

#include "dproto.h"
#include "cfg.h"
#include "plr_list.h"
#include "bspec.h"
#include "HookTools.h"
#include "dynpatcher_base.h"

generic_dlldata_t GenericEngineData;

#ifdef _WIN32
	DSEngineData_Win_t DSEngineData;
#else
	DSEngineData_Lin_t DSEngineData;
#endif


VA_Funcs_t VA_Funcs;

int curProto = 0;
int curAuthType = 0;
bool curIsHltv = false;
int curIsRevEmu = 0;
bool curHasFuckedUserinfo;
int curIsOldRevEmu = 0;
int curAuthFail = 0;
int curIsSteamEmu = 0;
int CurIsSetti = 0;
unsigned int CurAddr;
netadr_t CurNetAddr;
int g_HaveAmxx = 0;
char* LastUserInfo;

eclientdata_t eCliData[64];
char CurPlrName[64];

bannedid_t *p_userfilters = NULL;
int* p_numuserfilters = NULL;
double *prealtime;
DLL_FUNCTIONS *gOrigEntityInterface;

cvar_t *cv_SvContact;

CMasterClient PrimaryMasterClient;
CSubServer RedirServer;

cvar_t cv_dp_r_protocol = {"dp_r_protocol", "0", FCVAR_EXTDLL, 0, NULL};
cvar_t cv_dp_r_id_provider = {"dp_r_id_provider", "0", FCVAR_EXTDLL, 0, NULL};
cvar_t cv_dp_clientbanner = {"dp_clientbanner", "", FCVAR_EXTDLL, 0, NULL};
cvar_t cv_dp_rejmsg_steam = {"dp_rejmsg_steam", "Sorry, legit clients are not alowed on this server", FCVAR_EXTDLL, 0, NULL};
cvar_t cv_dp_rejmsg_nosteam47 = {"dp_rejmsg_nosteam47", "Sorry, no-steam p47 clients are not allowed on this server", FCVAR_EXTDLL, 0, NULL};
cvar_t cv_dp_rejmsg_nosteam48 = {"dp_rejmsg_nosteam48", "Sorry, no-steam p48 clients are not allowed on this server", FCVAR_EXTDLL, 0, NULL};
cvar_t cv_dp_rejmsg_hltv = {"dp_rejmsg_hltv", "Sorry, HLTV are not allowed on this server", FCVAR_EXTDLL, 0, NULL};
cvar_t cv_dp_rejmsg_pending = {"dp_rejmsg_pending", "Sorry, unathorized clients are not allowed on this server", FCVAR_EXTDLL, 0, NULL};
cvar_t cv_dp_rejmsg_revemu = {"dp_rejmsg_revemu", "Sorry, RevEmu clients are not allowed on this server", FCVAR_EXTDLL, 0, NULL};
cvar_t cv_dp_rejmsg_steamemu = {"dp_rejmsg_steamemu", "Sorry, SteamEmu clients are not allowed on this server", FCVAR_EXTDLL, 0, NULL};
cvar_t cv_dp_rejmsg_oldrevemu = {"dp_rejmsg_oldrevemu", "Sorry, Old RevEmu clients are not allowed on this server", FCVAR_EXTDLL, 0, NULL};
cvar_t cv_dp_version = {"dp_version", "0", FCVAR_EXTDLL, 0, NULL};

cvar_t *pcv_dp_r_protocol;
cvar_t *pcv_dp_r_id_provider;
cvar_t *pcv_dp_rejmsg_steam;
cvar_t *pcv_dp_rejmsg_nosteam47;
cvar_t *pcv_dp_rejmsg_nosteam48;
cvar_t *pcv_dp_rejmsg_hltv;
cvar_t *pcv_dp_rejmsg_pending;
cvar_t *pcv_dp_rejmsg_revemu;
cvar_t *pcv_dp_rejmsg_steamemu;
cvar_t *pcv_dp_rejmsg_oldrevemu;
cvar_t *pcv_dp_clientbanner;

Netchan_CreateFragments__proto Netchan_CreateFragments__func = NULL;

/* defines for dp_r_id_provider cvar: */
#define DP_AUTH_NONE 		'0'
#define DP_AUTH_DPROTO		'1'
#define DP_AUTH_STEAM		'2'
#define DP_AUTH_STEAMEMU	'3'
#define DP_AUTH_REVEMU		'4'
#define DP_AUTH_OLDREVEMU	'5'
#define DP_AUTH_HLTV		'6'


#if defined(DP_SLEEP_PATCH) && defined(_WIN32)

#endif

unsigned int revHash(const char* Str) {
	int i;
	unsigned int Hash;
	int CurChar;

	i = 0;
	Hash = 0x4E67C6A7;
	CurChar = Str[i++];
	while (CurChar) {
		Hash ^= (Hash >> 2) + CurChar + 32 * Hash;
		CurChar = Str[i++];
	}
	return Hash;
}

int dproto_CalcEId() {
	if (curIsHltv) return MainConfig.cid_HLTV;
	
	if (curAuthFail) {
		if (CurIsSetti) return MainConfig.cid_Setti;
		else if (curProto == 47) return MainConfig.cid_NoSteam47;
		else return MainConfig.cid_NoSteam48;
	} else {
		if (curIsSteamEmu) return MainConfig.cid_SteamEmu;
		if (curIsRevEmu) return MainConfig.cid_RevEmu;
		if (curIsOldRevEmu) return MainConfig.cid_OldRevEmu;
	}
	return MainConfig.cid_Steam;
}

eclientdata_t* GetEData(void* cl) {
	int idx = VA_Funcs.GetClientID(cl);
	if (idx < 0 || idx > 33) return NULL;
	return eCliData + idx;
}

void dp_RemoveBan(int slot) {
	int nflt = *p_numuserfilters;
	memmove(p_userfilters + slot, p_userfilters + slot + 1, sizeof(bannedid_t) * (nflt - slot - 1));
	*p_numuserfilters = nflt - 1;
}

bool dp_CheckBan(clientid_t* cid) {
	if (p_numuserfilters == NULL) {
		return false;
	}
	int nflt = *p_numuserfilters;
	int i;
	bannedid_t* cfilter = p_userfilters;
	for (i = 0; i < nflt; i++, cfilter++) {
		if (cfilter->cid.ID_Type == cid->ID_Type && cfilter->cid.ID_Ident1 == cid->ID_Ident1) {
			if (cfilter->iBanTime == 0) {
				return true;
			}
			if (cfilter->UnbanTime > *prealtime) {
				return true;
			}
			dp_RemoveBan(i);
			return false;
		}
	}
	return false;
}

void dp_Reject_Pending() {
	if (pcv_dp_rejmsg_pending->string == NULL || !pcv_dp_rejmsg_pending->string[0]) {
		SV_RejectConnection_func(&CurNetAddr, "Sorry, unathorized clients are not allowed on this server.\n");
	} else {
		SV_RejectConnection_func(&CurNetAddr, pcv_dp_rejmsg_pending->string);
	}
}

void dp_Reject_SteamEmu() {
	if (pcv_dp_rejmsg_steamemu->string == NULL || !pcv_dp_rejmsg_steamemu->string[0]) {
		SV_RejectConnection_func(&CurNetAddr, "Sorry, SteamEmu clients are not allowed on this server.\n");
	} else {
		SV_RejectConnection_func(&CurNetAddr, pcv_dp_rejmsg_steamemu->string);
	}
}

void dp_Reject_OldRevEmu() {
	if (pcv_dp_rejmsg_oldrevemu->string == NULL || !pcv_dp_rejmsg_oldrevemu->string[0]) {
		SV_RejectConnection_func(&CurNetAddr, "Sorry, Old RevEmu clients are not allowed on this server.\n");
	} else {
		SV_RejectConnection_func(&CurNetAddr, pcv_dp_rejmsg_oldrevemu->string);
	}
}

void dp_Reject_RevEmu() {
	if (pcv_dp_rejmsg_revemu->string == NULL || !pcv_dp_rejmsg_revemu->string[0]) {
		SV_RejectConnection_func(&CurNetAddr, "Sorry, RevEmu clients are not allowed on this server.\n");
	} else {
		SV_RejectConnection_func(&CurNetAddr, pcv_dp_rejmsg_revemu->string);
	}
}

void dp_Reject_NS48() {
	if (pcv_dp_rejmsg_nosteam48->string == NULL || !pcv_dp_rejmsg_nosteam48->string[0]) {
		SV_RejectConnection_func(&CurNetAddr, "Sorry, p.48 No-Steam clients are not allowed on this server.\n");
	} else {
		SV_RejectConnection_func(&CurNetAddr, pcv_dp_rejmsg_nosteam48->string);
	}
}

void dp_Reject_NS47() {
	if (pcv_dp_rejmsg_nosteam47->string == NULL || !pcv_dp_rejmsg_nosteam47->string[0]) {
		SV_RejectConnection_func(&CurNetAddr, "Sorry, p.47 No-Steam clients are not allowed on this server.\n");
	} else {
		SV_RejectConnection_func(&CurNetAddr, pcv_dp_rejmsg_nosteam47->string);
	}
}

void dp_Reject_Legit() {
	if (pcv_dp_rejmsg_steam->string == NULL || !pcv_dp_rejmsg_steam->string[0]) {
		SV_RejectConnection_func(&CurNetAddr, "Sorry, Legit Steam clients are not allowed on this server.\n");
	} else {
		SV_RejectConnection_func(&CurNetAddr, pcv_dp_rejmsg_steam->string);
	}
}


int CDECL SV_CheckProtocol_rev(netadr_t *addr, int proto) {
	curIsSteamEmu = 0;
	curIsRevEmu = 0;
	curAuthFail = 0;
	CurIsSetti = 0;
	curIsOldRevEmu = 0;
	if (proto > 48) {
		char* cstr = cv_SvContact->string;
		if (*cstr == 0) {
			cstr = "(no email address specified)";
		}
		SV_RejectConnection_func(addr, "This server is using an older protocol ( 47-48 ) than your client ( %i ).  If you believe this server is outdated, you can contact the server administrator at %s.\n", proto, cstr);
		return 0;
	} else if (proto < 47) {
		SV_RejectConnection_func(addr, "This server is using an newer protocol ( 47-48 ) than your client ( %i ).  You should check for updates to your client.\n", proto);
		return 0;
	}
	curProto = proto;
	memcpy(&CurAddr, addr->ip_addr, 4);
	memcpy(&CurNetAddr, addr, sizeof(netadr_t));
	return 1;
}

int CDECL SV_CheckCDKey_rev(netadr_t *addr, int auth_type, char *cdkey, char *userinfo) {
	char *hltv = g_engfuncs.pfnInfoKeyValue(userinfo, "*hltv");
	if (hltv == NULL || strlen(hltv) == 0) {
		curIsHltv = false;
	} else {
		curIsHltv = true;
		if (MainConfig.cid_HLTV == 5) {
			if (pcv_dp_rejmsg_hltv->string == NULL || !pcv_dp_rejmsg_hltv->string[0]) {
				SV_RejectConnection_func(addr, "Sorry, HLTV are not allowed on this server.\n");
			} else {
				SV_RejectConnection_func(addr, pcv_dp_rejmsg_hltv->string);
			}
			return 0;
		}
	}
	curAuthType = auth_type;
	if (auth_type == 2 || auth_type == 4) {
		//its no-steam
		if (curProto == 47 && MainConfig.cid_NoSteam47 == 5 && !curIsHltv) {
			dp_Reject_NS47();
			return 0;
		}
		if (curProto == 48 && MainConfig.cid_NoSteam48 == 5 && !curIsHltv) {
			dp_Reject_NS48();
			return 0;
		}
		curAuthFail = 1;
		return 1;
	} else if (auth_type == 3) {
		if (strcasecmp(cdkey, "steam")) {
			SV_RejectConnection_func(addr, "Expecting STEAM authentication USERID ticket! (d)\n");
			return 0;
		}
	} else {
		SV_RejectConnection_func(addr, "Invalid auth type (%d)!\n", auth_type);
		return 0;
	}
	return 1;
}


unsigned int* ParseSteamId(unsigned int* parr, unsigned int sid1, unsigned int sid2) {
	parr[0] = 0;
	parr[1] = 0;
	parr[2] = sid1 & 1;
	parr[3] = sid1 >> 1;	
	return parr;
}

char IDString_Buf[64];
char* GetIDString_int(int oid, int it, int id1, int id2);

char* ParseSteamIdEx(unsigned int *parr, int id1, int id2) {
	ParseSteamId(parr, id1, id2);
	if (parr[2] == 0 && parr[3] == 0) {
		strcpy(IDString_Buf, "PENDING");
		return IDString_Buf;
	}
	return NULL;
}

char* GetIDString_int(int oid, int it, int id1, int id2) {
	unsigned int PData[4];
	char* pRes;
	//LCPrintf(false, "[DPROTO]: GetIDString_int(%u %u %u %u)\n", oid, it, id1, id2);
	switch(it) {
		case 1:
			pRes = ParseSteamIdEx(PData, id1, id2);
			if (pRes) return pRes;
			sprintf(IDString_Buf, "STEAM_%u:%u:%u", PData[0] & 0xFFFF, PData[2], PData[3]);
			break;
		case 2:
			pRes = ParseSteamIdEx(PData, id1, id2);
			if (pRes) return pRes;
			sprintf(IDString_Buf, "VALVE_%u:%u:%u", PData[0] & 0xFFFF, PData[2], PData[3]);
			break;
		case 3:
			pRes = ParseSteamIdEx(PData, id1, id2);
			if (pRes) return pRes;
			sprintf(IDString_Buf, "STEAM_%u:%u:%u", MainConfig.IPGen_Prefix1, MainConfig.IPGen_Prefix2, PData[3]);
			break;
		case 4:
			pRes = ParseSteamIdEx(PData, id1, id2);
			if (pRes) return pRes;
			sprintf(IDString_Buf, "VALVE_%u:%u:%u", MainConfig.IPGen_Prefix1, MainConfig.IPGen_Prefix2, PData[3]);
			break;
		case 7:
			strcpy(IDString_Buf, "HLTV");
			break;
		case 8:
			strcpy(IDString_Buf, "STEAM_ID_LAN");
			break;
		case 9:
			strcpy(IDString_Buf, "STEAM_ID_PENDING");
			break;
		case 10:
			strcpy(IDString_Buf, "VALVE_ID_LAN");
			break;
		case 11:
			strcpy(IDString_Buf, "VALVE_ID_PENDING");
			break;
		case 12:
			strcpy(IDString_Buf, "STEAM_666:88:666");
			break;

		default:
			strcpy(IDString_Buf, "UNKNOWN");
	}
	return IDString_Buf;
}

char* CDECL SV_GetIDString_rev(clientid_t *cid) {
	IDString_Buf[0] = 0;
	void* pClient;
	eclientdata_t* eData;
	int clid;
	char* res;
	unsigned int idtype;

	//1877661022
	if (cid == NULL) {
		strcpy(IDString_Buf, "UNKNOWN");
		return IDString_Buf;
	}
	pClient = VA_Funcs.GetClientByCID(cid);
	clid = VA_Funcs.GetClientID(pClient);

	if (clid >= 0 && clid <= 31) {
		eData = GetEData(pClient);
		if (eData->isAuthFailed) {
			cid->ID_Ident2 = (eData->AuthId << 24) | 0x80000000;
		}
		idtype = eData->AuthId;
	} else { //its ban list
		if (cid->ID_Ident2 & 0x80000000) {
			idtype = (cid->ID_Ident2 >> 24) & 0x7F;
		} else { // legit/native
			switch(cid->ID_Type) {
				case 1:
					idtype = 1;
					break;

				case 2:
					idtype = 2;
					break;

				case 3:
					idtype = 7;
					break;
			}
		}
	}

	res = GetIDString_int(cid->ID_Type, idtype, cid->ID_Ident1, cid->ID_Ident2);
	//LCPrintf(false, "GetIDString(): returning '%s'; type=%d\n", res, idtype);
	return res;
}

char ClientIDString_buf[64];

char* CDECL SV_GetClientIDString_rev(size_t caddr, void *cl) {
	eclientdata_t* eData;
	clientid_t* cid = VA_Funcs.GetCIDByClient(cl);
	char* res;
	eData = GetEData(cl);
	int clid = VA_Funcs.GetClientID(cl);
	unsigned int i;
	bool IsNumericId = false;
	if (!VA_Funcs.IsClientActive(clid)) {
		strcpy(ClientIDString_buf, "UNKNOWN");
		return ClientIDString_buf;
	}
	if (caddr > SV_ConnectClient_addr && caddr < SVC_GetChallenge_addr) {
		if (eData) {
			const char* sIdProvider;
			if (CurIsSetti) {
				curAuthFail = 1;
			}
			eData->Proto = curProto;
			eData->IP = CurAddr;
			eData->IP2 = CurAddr;
			eData->AuthId = dproto_CalcEId();
			eData->cl = cl;
			eData->isAuthFailed = curAuthFail;
			eData->isRevEmu = curIsRevEmu;
			eData->isOldRevEmu = curIsOldRevEmu;
			eData->isSteamEmu = curIsSteamEmu;
			eData->isBanned = 0;
			eData->isHLTV = curIsHltv;
			eData->bHasFuckedUserinfo = curHasFuckedUserinfo;
			
			if (curIsHltv) {
				sIdProvider = "HLTV";
				cid->ID_Ident2 = (eData->AuthId << 24) | 0x80000000;
			} else if (curAuthFail) {
				cid->ID_Ident2 = (eData->AuthId << 24) | 0x80000000;
				//LCPrintf(true, "Ident2: %.8X (%u)\n", cid->ID_Ident2, eData->AuthId);
				if (CurIsSetti) {
					sIdProvider = "dp_Setti";
				} else {
					sIdProvider = "dproto";
				}
			} else {
				if (curIsRevEmu) {
					sIdProvider = "dp_RevEmu";
				} else if (curIsSteamEmu) {
					sIdProvider = "dp_SteamEmu";
				} else if (curIsOldRevEmu) {
					sIdProvider = "dp_OldRevEmu";
				} else {
					sIdProvider = "Native";
				}

				if (cid->ID_Ident2 == 0 && cid->ID_Ident1 == 0) {
					eData->AuthId = MainConfig.cid_SteamPending;
					cid->ID_Ident2 = (eData->AuthId << 24) | 0x80000000;
				}
			}

			switch (eData->AuthId) {
				case 1:
				case 3:
				case 8:
				case 9:
				case 12:
					cid->ID_Type = 1;
					break;
				case 2:
				case 4:
				case 10:
				case 11:
					cid->ID_Type = 2;
					break;
			}

			switch (eData->AuthId) {
				case 3:
				case 4:
					i = (CurAddr ^ 0xA95CE2B9);
					if (MainConfig.eSTCompat) {
						i = i << 1;
					}
					//LCPrintf(false, "IPGen_Ids: %u %u %u\n", CurAddr, CurAddr ^ 0xA95CE2B9, i);
					cid->ID_Ident1 = i;
					
				case 1:
				case 2:
					IsNumericId = true;
			}
			if (IsNumericId) {
				if (dp_CheckBan(cid)) {
					eData->isBanned = 1;
					edict_t *plr = g_engfuncs.pfnPEntityOfEntIndex(eData->iId + 1);
					if (plr) {
						int UserId = g_engfuncs.pfnGetPlayerUserId(plr);
						char Buf[256];
						sprintf(Buf, "kick #%d You have been banned from this server.\n", UserId);
						g_engfuncs.pfnServerCommand(Buf);
					}
				}
			}
			LCPrintf(false, "[DPROTO]: Client %d - Set AuthIdType %d [%s]; pClient = %p\n", eData->iId, eData->AuthId, sIdProvider, cl);
		}
		curAuthFail = 0;
		curProto = 0;
		curIsRevEmu = 0;
		curIsOldRevEmu = 0;
		CurIsSetti = 0;
		curIsHltv = false;
	}

	ClientIDString_buf[0] = 0;
	res = SV_GetIDString_rev(VA_Funcs.GetCIDByClient(cl));
	sprintf(ClientIDString_buf, "%s", res);
	return ClientIDString_buf;
}

#ifdef _WIN32	//WINDOWS
__declspec(naked) void CDECL GetClientIDString_Helper() {
	__asm {
		call SV_GetClientIDString_rev
		ret
	}
}
#elif defined(linux) //LINUX
void CDECL GetClientIDString_Helper() {
	__asm (
		"calll SV_GetClientIDString_rev;"
		"ret;"
	);
}
#endif

void STDCALL SendSrvInfo_WriteProto(void *cl, int* Msg) {
	eclientdata_t* eData = GetEData(cl);
	int proto = 0;
	if (eData) proto = eData->Proto;
	MSG_WriteLong_func(Msg, proto);
}

int CDECL ISMSU_HandlePacket_hook(char* data, int len, int ip, int port) {
	bool handled = false;
	if (len < 5) {
		VA_Funcs.ISMSHandle(data, len, ip, port);
		return 0;
	}
	data[len] = 0;

	switch (data[4]) {
		case 'T':
			SendSrvInfo_Native(ip, port, MainConfig.ServerInfoAnswerType);
			break;
		case 'd':    //details (thx to 	Rulzy)
			SendSrvInfo_Native(ip, port, 1);
			break;
		case 'U':
		case 'p': //players
			SendPlayersList_Native(ip, port);
			break;
		case 'V':
			SendRules_Native(ip, port);
			break;

		default:
			if (MainConfig.MasterClient)
				handled = PrimaryMasterClient.ParseIncoming(data, len, ntohl(ip), port);

			if (!handled) 
				VA_Funcs.ISMSHandle(data, len, ip, port);

			return 0;
	}
	return 1;
}

void CDECL SVC_GetChallenge_hook(int nSock, int length, void *data, netadr_t to) {
	char ChallengeBuf[2048];
	int CLen = length;
	int CPos = 0;
	int res;
	const char* aid = g_engfuncs.pfnCmd_Argv(1);
	if (strcmp(aid, "steam") || length > (sizeof(ChallengeBuf) - 384)) {
		NET_SendPacket_func(nSock, length, data, to);
		return;
	}

	
	strncpy(ChallengeBuf, (char*)data, sizeof(ChallengeBuf));
	ChallengeBuf[sizeof(ChallengeBuf) - 1] = 0;
	while (CLen > 0) {
		if (ChallengeBuf[CLen] == ' ') {
			CPos = CLen;
			break;
		}
		CLen--;
	}
	if (CPos == 0) {
		LCPrintf(false, "[DPROTO]: Invalid challenge format '%s'\n", data);
		NET_SendPacket_func(nSock, length, data, to);
		return;
	}
	CLen--;
	CPos = 0;

	while (CLen > 0) {
		if (ChallengeBuf[CLen] == ' ') {
			CPos = CLen;
			break;
		}
		CLen--;
	}
	if (CPos == 0) {
		LCPrintf(false, "[DPROTO]: Invalid challenge format '%s'\n", data);
		NET_SendPacket_func(nSock, length, data, to);
		return;
	}
	CPos++;
	res = sprintf(ChallengeBuf+CPos, "%dm ", 1); 
	CLen += res;
	CPos += res;
	
	CLen += sprintf(ChallengeBuf+CPos, "%s", "30819d300d06092a864886f70d010101050003818b0030818702818100b5a614e896036cc9f9bd6d13f2f5c79fbb5f925e8dbb50f0b9ee9a5499f535978fe60c188e4f8872160d86b76b80f1ba82333d586b32692ffa31e1dd59a603dc6370004566afa54830898d4ff210c738deb059e0a94a87dd85be28668793681a4ecf647fa1b5294a73927f23ffba0c6a9140922d27002012fed2b4a898aa7811020111\n"); 
	CLen += 2;
	//LCPrintf(false, "[DPROTO]: GetChallenge() '%s'\n", ChallengeBuf);
	NET_SendPacket_func(nSock, CLen, ChallengeBuf, to);
}

struct RevTicket_t {
	unsigned int Unk00;
	unsigned int Unk04;
	unsigned int Unk08;
	unsigned int Unk0C;
	unsigned int Unk10;
	unsigned int Unk14;
	char TicketBuf[128];
};


int TryAuthRevEmu(clientid_t *cid, void* cl, unsigned char *key, int len) {
	RevTicket_t* tickt = (RevTicket_t*) key;
	unsigned int Hash;

	if (len < 0x98) {
		return 0;
	}
	if (tickt->Unk08 != 'rev' || tickt->Unk0C != 0 || tickt->Unk00 != 0x4A) {
		return 0;
	}
	tickt->TicketBuf[127] = 0;
	Hash = revHash(tickt->TicketBuf) & 0x7FFFFFFF;
	unsigned int tmp = (tickt->Unk10 >> 1);
	if (Hash != (tickt->Unk04 & 0x7FFFFFFF) || tmp != Hash) {
		return 0;
	}
	cid->ID_Ident1 = tickt->Unk10;
	cid->ID_Ident2 = 0;
	cid->ID_Type = 1;

	if (MainConfig.cid_RevEmu == 5) {
		dp_Reject_RevEmu();
		return 2;
	}

	if ((cid->ID_Ident1 & 0xFFFFFFFE) == 0) {
		dp_Reject_Pending();
		return 2;
	}

	return 1;
}

int TryAuthSteamEmu(clientid_t *cid, void* cl, unsigned char *key, int len) {
	unsigned int *ikey = (unsigned int*) key;
	if (len != 0x300) {
		return 0;
	}
	if (ikey[20] != 0xFFFFFFFF || ikey[21] == 777) {
		return 0;
	}

	cid->ID_Ident2 = 0;
	cid->ID_Type = 1;

	if (MainConfig.SteamEmuCompatMode) {
		cid->ID_Ident1 = ikey[21] << 1;
	} else {
		cid->ID_Ident1 = (ikey[21] ^ 0xC9710266);
	}

	if (MainConfig.cid_SteamEmu == 5) {
		dp_Reject_SteamEmu();
		return 2;
	}

	if ((cid->ID_Ident1 & 0xFFFFFFFE) == 0) {
		dp_Reject_Pending();
		return 2;
	}

	return 1;
}

int TryAuthOldRevEmu(clientid_t *cid, void* cl, unsigned char *key, int len) {
	unsigned int *ikey = (unsigned int*) key;
	if (len != 10) {
		return 0;
	}
	if ((ikey[0] & 0xFFFF) != 0xFFFF || ikey[1] == 0) {
		return 0;
	}

	cid->ID_Ident2 = 0;
	cid->ID_Type = 1;

	if (!MainConfig.SteamEmuCompatMode) {
		cid->ID_Ident1 = (ikey[1]);
	} else {
		cid->ID_Ident1 = ((ikey[1] ^ 0xC9710266) << 1);
	}

	if (MainConfig.cid_OldRevEmu == 5) {
		dp_Reject_OldRevEmu();
		return 2;
	}

	if ((cid->ID_Ident1 & 0xFFFFFFFE) == 0) {
		dp_Reject_Pending();
		return 2;
	}

	return 1;
}

int TryAuthSetti(clientid_t *cid, void* cl, unsigned char *key, int len) {
	unsigned int *ikey = (unsigned int*) key;
	if (len != 0x300) {
		return 0;
	}

	CurIsSetti = 0;

	//thx to vityan666
	if (ikey[0] == 0xD4CA7F7B || ikey[1] == 0xC7DB6023 || ikey[2] == 0x6D6A2E1F || ikey[5] == 0xB4C43105) {
        CurIsSetti = 1;
	}

	if (!CurIsSetti) {
		return 0;
	}

	if (MainConfig.cid_Setti == 5) {
		dp_Reject_NS47();
		return 2;
	}


	cid->ID_Ident2 = 0;
	cid->ID_Type = 1;
	cid->ID_Ident1 = 123;

	return 1;
}


int SteamAuthFailed(clientid_t *cid, void* cl, unsigned char *key, int len) {
	void* hValidation = NULL;
	int Unk = 0;
	unsigned int i;
	
/*	
	FILE *fl;
	char FName[128];
	sprintf(FName, "zz_ticket_%s.bin", CurPlrName);
	fl = fopen(FName, "wb");
	if (fl) {
		fwrite(key, len, 1, fl);
		fclose(fl);
	}
*/


	//try auth revemu client
	i = TryAuthRevEmu(cid, cl, key, len);
	if (i == 1) {
		curIsRevEmu = 1;
		return 1;
	} else if (i == 2) {
		return 0;
	}

	i = TryAuthSetti(cid, cl, key, len);
	if (i == 1) {
		return 1;
	} else if (i == 2) {
		return 0;
	}


	i = TryAuthSteamEmu(cid, cl, key, len);
	if (i == 1) {
		curIsSteamEmu = 1;
		return 1;
	} else if (i == 2) {
		return 0;
	}

	i = TryAuthOldRevEmu(cid, cl, key, len);
	if (i == 1) {
		curIsOldRevEmu = 1;
		return 1;
	} else if (i == 2) {
		return 0;
	}

	curAuthFail = 1;
	if (curProto == 47 && MainConfig.cid_NoSteam47 == 5) {
		dp_Reject_NS47();
		return 0;
	}
	if (curProto == 48 && MainConfig.cid_NoSteam48 == 5) {
		dp_Reject_NS48();
		return 0;
	}

	return 1;
	
	//LCPrintf(false, "[DPROTO]: Native auth failed.\n");

/*	#if defined(linux)
		i = (SArr[1] << 1) | (SArr[2] & 1);
	#else
		i = (SArr[2] << 1) | (SArr[3] & 1);
	#endif

	if (MainConfig.eSTCompat) {
		i = i << 1;
	}
	cid->ID_Ident1 = i;
*/

	
}

bool ValidateSteamTicket(unsigned char* key, int len) {
	if (len < 16)
		return false;
	unsigned char* EndKey = key + len;
	unsigned char* cc;
	int tmp;
	int TicketOff = *(int*)key;
	if (TicketOff < 0 || (TicketOff + 16) > len) {
		return false;
	}

	cc = key + 4 + TicketOff;
	tmp = *(int*) cc;
	if (tmp < 0)
		return false;
	cc += 4;
	tmp = *(int*) cc;
	if (tmp < 0)
		return false;
	return true;
}

int CDECL SteamConnect_hook(void* cl, unsigned char *key, int len) {
	int res = 0;
	clientid_t* cid = VA_Funcs.GetCIDByClient(cl);
	cid->ID_Ident1 = 0;
	cid->ID_Ident2 = 0;

	//LCPrintf(false, "[DPROTO]: Native auth\n");
	bool IsBad = !ValidateSteamTicket(key, len);
	if (!MainConfig.DisableNativeAuth && !IsBad)
		res = VA_Funcs.StartAuth(cl, NULL, (char*)key, len, 0);

	if (res) {
		//LCPrintf(false, "[DPROTO]: Native auth passed\n");
		if (MainConfig.cid_Steam == 5) {
			dp_Reject_Legit();
			return 0;
		}
		if (cid->ID_Ident1 == 0 && cid->ID_Ident2 == 0 && MainConfig.cid_SteamPending == 5) {
			dp_Reject_Pending();
			return 0;
		}
		return res;
	}

	res = SteamAuthFailed(cid, cl, key, len);
	return res;
}

int CDECL StartSteamAuth_hook(void* cl, netadr_t *addr, unsigned char *key, int len, int auth_type) {
	int res = 0;
	clientid_t* cid = VA_Funcs.GetCIDByClient(cl);
	cid->ID_Ident1 = 0;
	cid->ID_Ident2 = 0;


	//LCPrintf(false, "[DPROTO]: Native auth2\n");
	bool IsBad = !ValidateSteamTicket(key, len);
	if (!MainConfig.DisableNativeAuth && !IsBad)
		res = VA_Funcs.StartAuth(cl, NULL, (char*)key, len, 0);

	if (res) {
		//LCPrintf(false, "[DPROTO]: Native auth2 passed\n");
		if (MainConfig.cid_Steam == 5) {
			dp_Reject_Legit();
			return 0;
		}
		if (cid->ID_Ident1 == 0 && cid->ID_Ident2 == 0 && MainConfig.cid_SteamPending == 5) {
			dp_Reject_Pending();
			return 0;
		}
		return res;
	}

	curAuthFail = 1;
	res = SteamAuthFailed(cid, cl, key, len);
	return res;
}

int STDCALL CheckUserInfo(netadr_t *addr, char* uinfo) {
	char* name;
	int i;
	
	LastUserInfo = uinfo; //may be used in SV_CheckCDKey()
	char TmpUserInfo[512];
	char* UInfoVals[256];
	
	curHasFuckedUserinfo = false;

	strncpy(TmpUserInfo, uinfo, 511);
	TmpUserInfo[511] = 0;
	char* cwpos = uinfo;
	int NInfoFields = ParseInfoLine(TmpUserInfo, UInfoVals, 256);
	if (NInfoFields < 2 || (NInfoFields & 1)) {
		SV_RejectConnection_func(addr, "Invalid userinfo, go clean your config.");
		return 0;
	}

	for (i = 0; i < (NInfoFields / 2); i++) {
		char* fName = UInfoVals[i*2];
		char* fVal = UInfoVals[i*2+1];
		if (!strcmp(fName, "name")) {
			if (*fVal && strstr(fVal, "..")) {
				SV_RejectConnection_func(addr, "Hacker? xD");
				return 0;
			}
		}

		if (fVal[0] == 0) {
			SV_RejectConnection_func(addr, "Invalid userinfo, go clean your config.");
			return 0;
		} else if (fName[0] == 0) {
			curHasFuckedUserinfo = true;
		} else if (strlen(fName) < 128 && strlen(fVal) < 128) {
			cwpos += sprintf(cwpos, "\\%s\\%s", fName, fVal);
		}
	}
	*cwpos = 0;

	name = g_engfuncs.pfnInfoKeyValue(uinfo, "name");

	strncpy(CurPlrName, name, 32);
	CurPlrName[31] = 0;

	return 1;
}

void CDECL SV_ReadPackets_old_hook() {
	int ip;
	int res;
	memcpy(&ip, &pnet_from->ip_addr, 4);
	ip = ntohl(ip);
	res = ISMSU_HandlePacket_hook((char*)pnet_message->buffer, pnet_message->msg_len, ip, ntohs(pnet_from->port));
	if (!res) 
		SV_ConnectionlessPacket_func();
}


void StartFrame_fwd() {
	if (MainConfig.SubServer_Enable) {
		RedirServer.Think();
	}
	if (MainConfig.MasterClient) {
		PrimaryMasterClient.OnThink(false);
	}
	SET_META_RESULT(MRES_HANDLED);
}

bool dproto_init_shared() {
	int i;
	memset(eCliData, 0, sizeof(eCliData));
	for (i = 0; i < 64; i++)
		eCliData[i].iId = i;
	
	GET_GAME_DIR(MainConfig.GameDir);
	sprintf(MainConfig.VVF_Name, "ValidInfoFields_%s", MainConfig.GameDir);

	if (!MainConfig.LoadCfg()) {
		LCPrintf(true, "[DPROTO]: Cant load config - detaching...\n");
		return false;
	}

	if (!PlrList_Init()) {
		return false;
	}
	
	cv_SvContact = CVAR_GET_POINTER("sv_contact");
	if (cv_SvContact == 0) {
		return 0;
	}

	MainConfig.SrvPort = atoi(g_engfuncs.pfnCVarGetString("hostport"));
	if (!MainConfig.SrvPort) {
		MainConfig.SrvPort = atoi(g_engfuncs.pfnCVarGetString("port"));
		if (!MainConfig.SrvPort) {
			MainConfig.SrvPort = 27015;
		}
	}
	LCPrintf(false, "[DPROTO]: Server port: %d\n", MainConfig.SrvPort);

	BSpec_Init();

	return 1;
}

void DP_ClientInfo_Disp() {
	int ArgCount = g_engfuncs.pfnCmd_Argc();
	if (ArgCount > 1) {
		int ClientID = atoi(g_engfuncs.pfnCmd_Argv(1)) - 1;
		if (ClientID >= 0 && ClientID < psvs->max_clients) {
			if (VA_Funcs.IsClientActive(ClientID)) {
				char Buf[32];
				eclientdata_t* eData = &eCliData[ClientID];
				sprintf(Buf, "%d", eData->Proto);
				g_engfuncs.pfnCvar_DirectSet(pcv_dp_r_protocol, Buf);
				
				Buf[1] = 0;
				if (eData->isHLTV) {
					Buf[0] = DP_AUTH_HLTV;
				} else if (!eData->isAuthFailed) {
					if (eData->isSteamEmu) { Buf[0] = DP_AUTH_STEAMEMU; }
					else if (eData->isRevEmu) { Buf[0] = DP_AUTH_REVEMU; }
					else if (eData->isOldRevEmu) { Buf[0] = DP_AUTH_OLDREVEMU; }
					else { Buf[0] = DP_AUTH_STEAM; }
				} else {
					Buf[0] = DP_AUTH_DPROTO;
				}
				g_engfuncs.pfnCvar_DirectSet(pcv_dp_r_id_provider, Buf);
				return;
			}
			g_engfuncs.pfnCvar_DirectSet(pcv_dp_r_protocol, "0");
			g_engfuncs.pfnCvar_DirectSet(pcv_dp_r_id_provider, "0");
			return;
		}
	}
	g_engfuncs.pfnCvar_DirectSet(pcv_dp_r_protocol, "-1");
	g_engfuncs.pfnCvar_DirectSet(pcv_dp_r_id_provider, "-1");
}

void dproto_PostInit_shared() {
	if (MainConfig.SubServer_Enable) {
		if (RedirServer.Init(MainConfig.SubServer_IP, MainConfig.SubServer_Port, MainConfig.SubServer_MasterClient ? 1 : 0, MainConfig.SubServer_AnswerType)) {
			RedirServer.SetRedirCmd(MainConfig.RedirectCmd);
			if (MainConfig.SubServer_MasterClient) {
				RedirServer.MClient.AddMasterServer(inet_addr("68.142.72.250"), 27010);
				RedirServer.MClient.AddMasterServer(inet_addr("69.28.151.162"), 27010);
			}
		} else {
			LCPrintf(true, "[DPROTO]: Failed to initialize subserver.\n");
		}

	}

	if (MainConfig.MasterClient) {
		PrimaryMasterClient.AddMasterServer(inet_addr("68.142.72.250"), 27010);
		PrimaryMasterClient.AddMasterServer(inet_addr("69.28.151.162"), 27010);
	}

	g_engfuncs.pfnCvar_RegisterVariable(&cv_dp_r_protocol);
	g_engfuncs.pfnCvar_RegisterVariable(&cv_dp_r_id_provider);
	
	g_engfuncs.pfnCvar_RegisterVariable(&cv_dp_rejmsg_steam);
	g_engfuncs.pfnCvar_RegisterVariable(&cv_dp_rejmsg_nosteam47);
	g_engfuncs.pfnCvar_RegisterVariable(&cv_dp_rejmsg_nosteam48);
	g_engfuncs.pfnCvar_RegisterVariable(&cv_dp_rejmsg_hltv);
	g_engfuncs.pfnCvar_RegisterVariable(&cv_dp_rejmsg_pending);
	g_engfuncs.pfnCvar_RegisterVariable(&cv_dp_rejmsg_revemu);
	g_engfuncs.pfnCvar_RegisterVariable(&cv_dp_rejmsg_steamemu);
	g_engfuncs.pfnCvar_RegisterVariable(&cv_dp_rejmsg_oldrevemu);
	g_engfuncs.pfnCvar_RegisterVariable(&cv_dp_clientbanner);
	

	cv_dp_version.string = Plugin_info.version;
	if (MainConfig.ExportVersion) {
		cv_dp_version.flags |= FCVAR_SERVER;
	}
	g_engfuncs.pfnCvar_RegisterVariable(&cv_dp_version);

	pcv_dp_r_protocol = g_engfuncs.pfnCVarGetPointer("dp_r_protocol");
	pcv_dp_r_id_provider = g_engfuncs.pfnCVarGetPointer("dp_r_id_provider");

	pcv_dp_rejmsg_steam = g_engfuncs.pfnCVarGetPointer("dp_rejmsg_steam");
	pcv_dp_rejmsg_nosteam47 = g_engfuncs.pfnCVarGetPointer("dp_rejmsg_nosteam47");
	pcv_dp_rejmsg_nosteam48 = g_engfuncs.pfnCVarGetPointer("dp_rejmsg_nosteam48");
	pcv_dp_rejmsg_hltv = g_engfuncs.pfnCVarGetPointer("dp_rejmsg_hltv");
	pcv_dp_rejmsg_pending = g_engfuncs.pfnCVarGetPointer("dp_rejmsg_pending");
	pcv_dp_rejmsg_revemu = g_engfuncs.pfnCVarGetPointer("dp_rejmsg_revemu");
	pcv_dp_rejmsg_steamemu = g_engfuncs.pfnCVarGetPointer("dp_rejmsg_steamemu");
	pcv_dp_rejmsg_oldrevemu = g_engfuncs.pfnCVarGetPointer("dp_rejmsg_oldrevemu");
	pcv_dp_clientbanner = g_engfuncs.pfnCVarGetPointer("dp_clientbanner");

	g_engfuncs.pfnAddServerCommand("dp_clientinfo", &DP_ClientInfo_Disp);
}

void HookFunctionEx(void *OrigAddr, void* NewAddr, unsigned int OrigBytes, const char* Info) {
	unsigned int NOrig = HookFunction(OrigAddr, NewAddr);
	if (NOrig != OrigBytes) {
		LCPrintf(true, "[DPROTO]: WARNING: Original data mismatch on patch %s at %p\n", Info, OrigAddr);
		LCPrintf(true, "[DPROTO]: Real: 0x%.8X; Need: 0x%.8X\n", NOrig, OrigBytes);
	}
}

qboolean dp_ClientConnect( edict_t *pEntity, const char *pszName, const char *pszAddress, char szRejectReason[ 128 ] ) {
	if (pcv_dp_clientbanner && pcv_dp_clientbanner->string && pcv_dp_clientbanner->string[0]) {
		static float tmpf[3] = {0,0,0};
		g_engfuncs.pfnMessageBegin(MSG_ONE, 0x38, tmpf, pEntity);
		char *cc = pcv_dp_clientbanner->string;
		while (*cc) {
			g_engfuncs.pfnWriteByte(*cc);
			cc++;
		}
		g_engfuncs.pfnWriteByte('$');
		g_engfuncs.pfnWriteByte(0);
		g_engfuncs.pfnMessageEnd();
	}
	SET_META_RESULT(MRES_IGNORED);
	return 1;
}

void dp_ServerActivate (edict_t *pEdictList, int edictCount, int clientMax) {
	g_HaveAmxx = (g_engfuncs.pfnCVarGetPointer("amxmodx_version") != NULL);
	SET_META_RESULT(MRES_HANDLED);
}

void CDECL Netchan_CreateFragments__hooked(int bIsServer, void* nchan, sizebuf_t* sbuf) {
	static int RecCounter = 0;
	static byte TmpMsgKeeper[131072];
	//LCPrintf(false, "[DPROTO]: %s: I'm here (%d 0x%.8X 0x%.8X)\n", __FUNCTION__, bIsServer, nchan, sbuf);
	if (RecCounter) {
		Netchan_CreateFragments__func(bIsServer, nchan, sbuf);
		return;
	}
	RecCounter++;
	int KeepSz = sbuf->cursize;
	if (KeepSz > sizeof(TmpMsgKeeper))
		KeepSz = sizeof(TmpMsgKeeper);
	memcpy(TmpMsgKeeper, sbuf->data, KeepSz);
	Netchan_CreateFragments__func(bIsServer, nchan, sbuf);
	memcpy(sbuf->data, TmpMsgKeeper, KeepSz);
	sbuf->cursize = KeepSz;
	RecCounter--;
}