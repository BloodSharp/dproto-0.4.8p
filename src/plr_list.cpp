#include "osconfig.h"
#include "plr_list.h"
#include "dproto.h"
#include "cfg.h"

#include <extdll.h>
#include <meta_api.h>

#ifdef _WIN32	//WINDOWS

	#include "swds_data.h"
	#include "windows.h"
	#include "winsock.h"

#elif defined(linux) //LINUX

	#include "engine_data.h"

#endif

cvar_t* cv_hostname;
cvar_t* cv_sv_password;
cvar_t init_sv_chlversion;
cvar_t* cv_sv_chlversion;
cvar_t* cv_sv_visiblemaxplayers;

bool PlrList_Init() {
	cv_hostname = g_engfuncs.pfnCVarGetPointer("hostname");
	if (!cv_hostname)
		return false;

	cv_sv_visiblemaxplayers = g_engfuncs.pfnCVarGetPointer("sv_visiblemaxplayers");
	if (!cv_sv_visiblemaxplayers)
		return false;

	cv_sv_password = g_engfuncs.pfnCVarGetPointer("sv_password");
	if (!cv_sv_password)
		return false;

	init_sv_chlversion.name = "sv_chlversion";
	init_sv_chlversion.string = "1.1.2.6/Stdio";
	g_engfuncs.pfnCVarRegister(&init_sv_chlversion);

	cv_sv_chlversion = g_engfuncs.pfnCVarGetPointer("sv_chlversion");
	if (!cv_sv_chlversion)
		return false;

	return true;
}

int CountActivePlayers() {
	int res = 0;
	int i;
	for (i = 0; i < psvs->max_clients; i++) {
		if (VA_Funcs.IsClientActive(i))
			res++;
	}
	return res;
}

void SendRules_Native(int ip, int port) {
	unsigned char RulesBuf[8192];
	int i;
	netadr_t toaddr;

	i = Rules_Build(RulesBuf, sizeof(RulesBuf));

	toaddr.type = NA_IP;
	ip = ntohl(ip);
	memcpy(&toaddr.ip_addr, &ip, 4);
	toaddr.port = htons(port);
	
	NET_SendPacket_func(1, i, RulesBuf, toaddr);
}

void SendRules_FromSocket(int Socket, int ip, int port) {
	unsigned char RulesBuf[8192];
	int i;
	sockaddr_in saddr;

	i = Rules_Build(RulesBuf, sizeof(RulesBuf));

	SIN_SET_ADDR(&saddr.sin_addr, ip)
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(port);
	
	sendto(Socket, (char*)RulesBuf, i, 0, (sockaddr*) &saddr, sizeof(saddr));
}

void SendPlayersList_FromSocket(int Socket, int ip, int port) {
	char SendBuf[1500];
	int res;
	sockaddr_in saddr;

	res = PlayersList_Build(SendBuf);

	SIN_SET_ADDR(&saddr.sin_addr, ip)
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(port);

	sendto(Socket, SendBuf, res, 0, (sockaddr*) &saddr, sizeof(saddr));
}

void SendSrvInfo_FromSocket(int Socket, int ip, int port, int AnswerType, int ServerPort) {
	unsigned char SendBuf[1500];
	int res;
	sockaddr_in saddr;

	SIN_SET_ADDR(&saddr.sin_addr, ip)
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(port);

	switch (AnswerType) {
		case 0:
			res = SrvInfo_Build(SendBuf, 0, ServerPort);
			sendto(Socket, (char*)SendBuf, res, 0, (sockaddr*) &saddr, sizeof(saddr));
			break;

		case 1:
			res = SrvInfo_Build(SendBuf, 1, ServerPort);
			sendto(Socket, (char*)SendBuf, res, 0, (sockaddr*) &saddr, sizeof(saddr));
			break;

		case 2:
			res = SrvInfo_Build(SendBuf, 1, ServerPort);
			sendto(Socket, (char*)SendBuf, res, 0, (sockaddr*) &saddr, sizeof(saddr));

			res = PlayersList_Build((char*)SendBuf);
			sendto(Socket, (char*)SendBuf, res, 0, (sockaddr*) &saddr, sizeof(saddr));

			res = SrvInfo_Build(SendBuf, 0, ServerPort);
			sendto(Socket, (char*)SendBuf, res, 0, (sockaddr*) &saddr, sizeof(saddr));
			break;

		case 3:
			res = SrvInfo_Build(SendBuf, 0, ServerPort);
			sendto(Socket, (char*)SendBuf, res, 0, (sockaddr*) &saddr, sizeof(saddr));

			res = PlayersList_Build((char*)SendBuf);
			sendto(Socket, (char*)SendBuf, res, 0, (sockaddr*) &saddr, sizeof(saddr));

			res = SrvInfo_Build(SendBuf, 1, ServerPort);
			sendto(Socket, (char*)SendBuf, res, 0, (sockaddr*) &saddr, sizeof(saddr));
			break;

	}
}

void SendPlayersList_Native(int ip, int port) {
	char SendBuf[1500];
	int res;
	netadr_t toaddr;

	res = PlayersList_Build(SendBuf);

	toaddr.type = NA_IP;
	ip = ntohl(ip);
	memcpy(&toaddr.ip_addr, &ip, 4);
	toaddr.port = htons(port);

	NET_SendPacket_func(1, res, SendBuf, toaddr);
}

void SendSrvInfo_Native(int ip, int port, int AnswerType) {
	unsigned char SendBuf[1500];
	int res;
	netadr_t toaddr;
	toaddr.type = NA_IP;
	ip = ntohl(ip);
	memcpy(&toaddr.ip_addr, &ip, 4);
	toaddr.port = htons(port);

	switch (AnswerType) {
		case 0:
			res = SrvInfo_Build(SendBuf, 0, MainConfig.SrvPort);
			NET_SendPacket_func(1, res, SendBuf, toaddr);
			break;

		case 1:
			res = SrvInfo_Build(SendBuf, 1, MainConfig.SrvPort);
			NET_SendPacket_func(1, res, SendBuf, toaddr);
			break;

		case 2:
			res = SrvInfo_Build(SendBuf, 1, MainConfig.SrvPort);
			NET_SendPacket_func(1, res, SendBuf, toaddr);

			res = PlayersList_Build((char*)SendBuf);
			NET_SendPacket_func(1, res, SendBuf, toaddr);

			res = SrvInfo_Build(SendBuf, 0, MainConfig.SrvPort);
			NET_SendPacket_func(1, res, SendBuf, toaddr);
			break;

		case 3:
			res = SrvInfo_Build(SendBuf, 0, MainConfig.SrvPort);
			NET_SendPacket_func(1, res, SendBuf, toaddr);

			res = PlayersList_Build((char*)SendBuf);
			NET_SendPacket_func(1, res, SendBuf, toaddr);

			res = SrvInfo_Build(SendBuf, 1, MainConfig.SrvPort);
			NET_SendPacket_func(1, res, SendBuf, toaddr);
			break;

	}

}


int SrvInfo_Build(unsigned char *SendBuf, int AnswerType, int ServerPort) {
	unsigned char* csbuf = SendBuf;
	const char* mapName = STRING(gpGlobals->mapname);
	int res = 0xFFFFFFFF;
	const char* gameName;
	if (MainConfig.AltGameName[0]) {
		gameName = MainConfig.AltGameName;
	} else	{
		if (gOrigEntityInterface) {
			gameName = gOrigEntityInterface->pfnGetGameDescription();
		} else {
			gameName = MDLL_GetGameDescription();
		}
	}
	
	int IsSecure = (VA_Funcs.IsServerSecure())?(1):(0);

	memcpy(csbuf, &res, 4);
	csbuf+=4;
	switch (AnswerType) {
		case 0:
			res = sprintf((char*)csbuf, "I0%s", cv_hostname->string );
			csbuf += res + 1;
			res = sprintf((char*)csbuf, "%s", mapName);
			csbuf += res + 1;

			res = sprintf((char*)csbuf, "%s", MainConfig.GameDir);
			csbuf += res + 1;

			res = sprintf((char*)csbuf, "%s", gameName);
			csbuf += res + 1;

			//unk
			res = sprintf((char*)csbuf, "\n");
			csbuf += res + 1;
			break;

		case 1:
			res = sprintf((char*)csbuf, "m127.0.0.1:%i", ServerPort);
			csbuf += res + 1;
			// Server name
			res = sprintf((char*)csbuf, "%s", cv_hostname->string);
			csbuf += res + 1;
			// Mapname
			res = sprintf((char*)csbuf, "%s", mapName);
			csbuf += res + 1;
			// Game dir
			res = sprintf((char*)csbuf, "%s", MainConfig.GameDir);
			csbuf += res + 1;
			// Game name
			res = sprintf((char*)csbuf, "%s", gameName);
			csbuf += res + 1;
			break;
	}

	// Current players
	res = CountActivePlayers();
	*(csbuf++) = res;
	// Max players
	res = atoi(cv_sv_visiblemaxplayers->string);
	if (res < 0) 
		res = psvs->max_clients;
	*(csbuf++) = (unsigned char) res;

	switch (AnswerType) {
		case 0:
			*(csbuf++) = 0;
			break;
		case 1:
			// Protocol version
			*(csbuf++) = 0x2F;
			break;
		}

	// Server type
	*(csbuf++) = 'd'; //dedicated

	// Server OS
#ifdef _WIN32
	*(csbuf++) = 'w'; //windows
#elif defined(linux)
	*(csbuf++) = 'l'; //linux
#endif

	// Server locked (password protected)
	*(csbuf++) = (strlen(cv_sv_password->string))?(1):(0);


	switch (AnswerType) {
		case 0:
			*(csbuf++) = IsSecure;
			res = sprintf((char*)csbuf, "%s", cv_sv_chlversion->string);
			csbuf += res + 1;
			// TODO: Check this info. Look at: http://developer.valvesoftware.com/wiki/Server_Queries
			*(csbuf++) = 0x80;
			res = ServerPort;
			memcpy(csbuf, &res, 2);
			csbuf += 2;
			break;

		case 1:
			// Is Mod running
			char modrunning = 1;
			*(csbuf++) = modrunning;
			if (modrunning != 0)
			{
				// Mod Info URL
				res = sprintf((char*)csbuf, "%s", "");
				csbuf += res + 1;
				// Mod Download URL
				res = sprintf((char*)csbuf, "%s", "");
				csbuf += res + 1;
				// Null
				*(csbuf++) = 0x00;
				// Mod version (major)
				*(csbuf++) = 0x01;
				*(csbuf++) = 0x00;
				// Mod version (minor)
				*(csbuf++) = 0x00;
				*(csbuf++) = 0x00;
				// Mod size
				*(csbuf++) = 0x00;
				*(csbuf++) = 0x00;
				*(csbuf++) = 0x00;
				*(csbuf++) = 0x00;
				// Mod Server only
				*(csbuf++) = 0x01;
				// Mod client Dll
				*(csbuf++) = 0x00;
			}
			// VAC secured
			*(csbuf++) = IsSecure;
			// Bots count
			// TODO: Set proper bots count
			*(csbuf++) = 0x00;
			break;
	}

	res = csbuf - SendBuf;
	return res;
}

int PlayersList_Build(char *SendBuf) {
	char* csbuf = SendBuf;
	int res = 0xFFFFFFFF;
	int j;
	int i;
	int k = 1;
	int nplrs = 0;
	edict_t* cpl;
	float cTime;
	char* InfoBuf;
	char* Tmp;
	const char* ctmp;
	float RTime = g_engfuncs.pfnTime();

	memcpy(csbuf, &res, 4);
	csbuf += 4;
	*(csbuf++) = 'D';
	*(csbuf++) = 0; //will set it later
	for (i = 0; i < psvs->max_clients; i++) {
		if (!VA_Funcs.IsClientPlaying(i))
			continue;
		cpl = INDEXENT(i+1);
		if (cpl == NULL)
			continue;
		nplrs++;
		cTime = *VA_Funcs.GetClientConnTime(i);
		cTime = RTime - cTime;
		
		InfoBuf = g_engfuncs.pfnGetInfoKeyBuffer(cpl);
		j = (int) cpl->v.frags;
		Tmp = g_engfuncs.pfnInfoKeyValue(InfoBuf, "name");

		if (MainConfig.HLStatsPlayerIdFix) {
			*(csbuf++) = k++;
		} else {
			*(csbuf++) = 0;
		}
		res = sprintf(csbuf, "%s", Tmp);
		csbuf += res + 1;
		memcpy(csbuf, &j, 4);
		csbuf += 4;
		memcpy(csbuf, &cTime, 4);
		csbuf += 4;
		ctmp = g_engfuncs.pfnGetPlayerAuthId(cpl);
	}

	res = csbuf - SendBuf;
	SendBuf[5] = nplrs;
	return res;
}

int Rules_Build(unsigned char* RulesBuf, int BufLen) {
	cvar_t *ccv;
	unsigned char *cbuf = RulesBuf;
	unsigned char *bufend = RulesBuf + BufLen - 3;
	int i, j;
	
	if (cvar_vars_v == NULL) return 0;
	
	//Write header to buffer. The last 2 bytes are the count of cvars, we'll set them later
	sprintf((char*)cbuf, "%c%c%c%c%c%c%c", 0xFF, 0xFF, 0xFF, 0xFF, 0x45, 0x00, 0x00);
	cbuf += 7;
	j = 0;

	//look through cvar list
	for (ccv = *cvar_vars_v; ccv; ccv=ccv->next) {

		//cvars with FCVAR_SERVER flag should be exported to rules
		if (ccv->flags & FCVAR_SERVER) {

			//check for overflow
			i = strlen(ccv->name);
			if (bufend - cbuf <= i)
				break;

			//copy name to buffer
			strcpy((char*)cbuf, ccv->name);
			cbuf += i + 1;
			
			//Mask protected cvars
			i = strlen(ccv->string);
			if (ccv->flags & FCVAR_PROTECTED) {

				//overflow check
				if (bufend - cbuf <= 2)
					break;
				if(i > 0 && strcasecmp(ccv->string, "none"))
					i = 1;
				else
					i = 0;
				*(cbuf++) = i + '0';
				*(cbuf++) = 0;
			} else {

				//copy value to buffer (for non-protected cvars)
				if (bufend - cbuf <= i) break;
				strcpy((char*)cbuf, ccv->string);
				cbuf += i + 1;
			}
			j++;
		}
	}

	//Set the actual cvars count
	*((short*) &RulesBuf[5]) = (short) j;
	
	//return actual length of buffer
	i = cbuf - RulesBuf;
	return i;
}
