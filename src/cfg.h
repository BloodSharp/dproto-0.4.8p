#ifndef __CFG_H__
#define __CFG_H__
#include "osconfig.h"
#include <stdio.h>
#include <string.h>

#include <extdll.h>
#include <meta_api.h>

#define DPROTO_CFG "dproto.cfg"

void LCPrintf(bool Critical, char *fmt, ... );
const char* GetAuthIidDescr(int id);

extern plugin_info_t Plugin_info;

class Cfg {
	public:
		int LoggingMode;
		
		int SubServer_Enable;
		unsigned int SubServer_IP;
		int SubServer_Port;
		int SubServer_MasterClient;
		int SubServer_AnswerType;
		int MasterClient;
		int HLStatsPlayerIdFix;
		
		int CurBuild;
		int SrvPort;
		
		int DisableNativeAuth;
		int ServerInfoAnswerType;
		int IPGen_Prefix1;
		int IPGen_Prefix2;

		char RedirectCmd[128];
		char Master_GameVersion[128];
		char AltGameName[128];
		int cid_HLTV;
		int cid_NoSteam47;
		int cid_NoSteam48;
		int cid_Steam;
		int cid_SteamPending;
		int cid_RevEmu;
		int cid_SteamEmu;
		int cid_OldRevEmu;
		int cid_Setti;

		int ExportVersion;
		int eSTCompat;
		int SteamEmuCompatMode;

		char GameDir[128];
		char VVF_Name[128];

		Cfg();
		bool LoadCfg();
		bool ParseValidInfos(char* InfoLine, char *Buf, int BufSize, char** InfoFields, int MaxSz);
		bool ParseParam(char* param, char* value);
};

struct PCharPair {
	char *Field;
	char *Value;
};

extern Cfg MainConfig;
extern int ParseInfoLine(char *infoline, char** InfoDatas, int MaxCount);
const char* GetStrAnswerType(int atid);

#endif //__CFG_H__
