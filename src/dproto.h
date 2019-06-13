#ifndef __DPROTO_H__
#define __DPROTO_H__
#include "osconfig.h"

#include <extdll.h>
#include <meta_api.h>
#include "subserver.h"
#include "dynpatcher_base.h"

#define DP_SLEEP_PATCH
#define DPROTO_VERSION "0.4.8p"

struct eclientdata_t {
	int iId;
	int Proto;
	int AuthId;
	int IP;
	void* cl;
	int IP2;
	bool isHLTV;
	int isAuthFailed;
	int isOldRevEmu;
	int isRevEmu;
	int isSteamEmu;
	int isBanned;
	bool bHasFuckedUserinfo;
};

struct clientid_t {
	unsigned int ID_Type;

	#if defined(linux)
	#else
		unsigned int ID_Pad;
	#endif

	unsigned int ID_Ident1;
	unsigned int ID_Ident2;

	#if defined(linux)
	#else
		unsigned int ID_Pad2;
	#endif

	unsigned int ID_Addr;
};

struct bannedid_t {
	clientid_t cid;
	float UnbanTime;
	union {
		float fBanTime;
		int iBanTime;
	};
};

enum netadrtype_t {
	NA_UNUSED = 0x0,
	NA_LOOPBACK = 0x1,
	NA_BROADCAST = 0x2,
	NA_IP = 0x3,
	NA_IPX = 0x4,
	NA_BROADCAST_IPX = 0x5,
};

struct netadr_t {
  netadrtype_t type;
  char ip_addr[4];
  char ipx_addr[10];
  unsigned short port;
};

struct net_message_t {
	int field_0;
	int field_4;
	int *buffer;
	int field_C;
	int msg_len;
};

struct svs_t {
  int field_0;
  int *clients;
  int max_clients;
  int field_C;
};

struct sizebuf_t {
	const char *descr;
	qboolean OverflowFlags;
	byte *data;
	int maxsize;
	int cursize;
};

typedef int (CDECL *SV_CheckProtocol_proto)(netadr_t *addr, int proto);
typedef void (CDECL *SV_RejectConnection_proto)(netadr_t *addr, char *Format, ...);
typedef int (CDECL *SV_CheckCDKey_proto) (netadr_t *addr, int auth_type, char *cdkey, char *userinfo);
typedef char* (CDECL *SV_GetIDString_proto) (clientid_t *cid);
typedef char* (CDECL *Info_ValueForKey_proto) (char *info, char *key);
typedef void (CDECL *MSG_WriteLong_proto) (int* msg, int value);
typedef void (CDECL *ISMSU_HandlePacket_proto) (char* data, int len, int ip, int port);
typedef char* (CDECL *NCmd_Argv_proto) (int narg);
typedef void (CDECL *NET_SendPacket_proto) (int nSock, int length, void *data, netadr_t to);
typedef int (CDECL *Steam_GSBSecure_proto) ();
typedef int (CDECL *Steam_NotifyClientConnect_proto) (void* cl, char* key, int data);
typedef int (CDECL *SV_StartSteamValidation_proto) (void* cl, netadr_t *addr, char* key, int len, int auth_type);
typedef void (CDECL *SV_ConnectionlessPacket_proto)();
typedef void (CDECL *Netchan_CreateFragments__proto)(int bIsServer, void* nchan, sizebuf_t* sbuf);


typedef int (CDECL *DP_GetMaxClients_proto)();
typedef clientid_t* (CDECL *DP_GetCIDByClient_proto)(void* cl);
typedef void* (CDECL *DP_GetClientByCID_proto)(clientid_t* cid);
typedef int (CDECL *DP_GetClientID_proto)(void* cl);
typedef bool (CDECL *DP_IsClientActive_proto)(int clid);
typedef bool (CDECL *DP_IsClientPlaying_proto)(int clid);
typedef float* (CDECL *DP_GetClientConnTime_proto)(int clid);
typedef int (CDECL *DP_IsServerSecure_proto)(void);
typedef int (CDECL *DP_StartAuth_proto)(void* cl, netadr_t* addr, char* key, int len, int auth_type);
typedef void (CDECL *DP_ISMSHandle_proto)(char* data, int len, int ip, int port);

typedef int (CDECL *SteamInitializeUserIDTicketValidator_proto)(int a1, int a2, int a3, int a4, int a5, int a6, int a7);
typedef int (CDECL *SteamAbortOngoingUserIDTicketValidation_proto)(void* hValidation);
typedef int (CDECL *SteamStartValidatingUserIDTicket_proto)(char* Data, int sz, int UserIP, void** phValidation);
typedef int (CDECL *SteamProcessOngoingUserIDTicketValidation_proto)(void* hValidation, unsigned int *pSteamId, int *pUnkInt, int a4, int a5, int a6);

extern DLL_FUNCTIONS *gOrigEntityInterface;

struct VA_Funcs_t {
	DP_GetMaxClients_proto GetMaxClients;
	DP_GetCIDByClient_proto GetCIDByClient;
	DP_GetClientByCID_proto GetClientByCID;
	DP_GetClientID_proto GetClientID;
	DP_IsClientActive_proto IsClientActive;
	DP_IsClientPlaying_proto IsClientPlaying;
	DP_GetClientConnTime_proto GetClientConnTime;
	DP_IsServerSecure_proto IsServerSecure;
	DP_StartAuth_proto StartAuth;
	DP_ISMSHandle_proto ISMSHandle;
};

extern VA_Funcs_t VA_Funcs;

extern int curProto;
extern int curAuthType;

extern bool curIsHltv;
extern int curAuthFail;
extern eclientdata_t eCliData[64];
extern bannedid_t *p_userfilters;
extern int* p_numuserfilters;
extern double *prealtime;
extern int g_HaveAmxx;

extern "C" {
	int CDECL SV_CheckProtocol_rev(netadr_t *addr, int proto);
	int CDECL SV_CheckCDKey_rev(netadr_t *addr, int auth_type, char *cdkey, char *userinfo);
	char* CDECL SV_GetIDString_rev(clientid_t *cid);
	char* CDECL SV_GetClientIDString_rev(size_t caddr, void *cl);
	void STDCALL SendSrvInfo_WriteProto(void *cl, int* Msg);
	int CDECL ISMSU_HandlePacket_hook(char* data, int len, int ip, int port);
	int STDCALL CheckUserInfo(netadr_t *addr, char* uinfo);
	void CDECL SVC_GetChallenge_hook(int nSock, int length, void *data, netadr_t to);
	int CDECL SteamConnect_hook(void* cl, unsigned char* key, int data);
	int CDECL StartSteamAuth_hook(void* cl, netadr_t *addr, unsigned char *key, int len, int auth_type);
	void CDECL SV_ReadPackets_old_hook();
	void CDECL GetClientIDString_Helper();
	extern char* LastUserInfo;
};

void HookFunctionEx(void *OrigAddr, void* NewAddr, unsigned int OrigBytes, const char* Info);

int dproto_init();
bool dproto_init_shared();
void dproto_PostInit_shared();
void StartFrame_fwd();
extern qboolean dp_ClientConnect ( edict_t *pEntity, const char *pszName, const char *pszAddress, char szRejectReason[ 128 ] );
extern void dp_ServerActivate(edict_t *pEdictList, int edictCount, int clientMax);
extern enginefuncs_t meta_engfuncs_post;
extern Netchan_CreateFragments__proto Netchan_CreateFragments__func;
extern void CDECL Netchan_CreateFragments__hooked(int bIsServer, void* nchan, sizebuf_t* sbuf);

extern generic_dlldata_t GenericEngineData;

#ifdef _WIN32
	struct DSEngineData_Win_t {
		uint32_t Q_strcpy_addr;
		uint32_t SV_ParseCvarValue2_addr;
		uint32_t SV_CheckProtocol_addr;
		uint32_t SV_RejectConnection_addr;
		uint32_t svs_addr;
		uint32_t MSG_WriteString_addr;
		uint32_t MSG_WriteByte_addr;
		uint32_t MSG_WriteLong_addr;
		uint32_t AuthProtoValidation__LongJZ_haddr;
		uint32_t AuthProtoValidation__LongJZ_GoodAddr;
		uint32_t Steam_NotifyClientConnect_addr;
		uint32_t SteamValidation_NotifyCC_haddr;
		uint32_t ChallengeGen_SendPacket_haddr;
		uint32_t NET_SendPacket_addr;
		uint32_t GS_ClientDenyHelper_addr;
		uint32_t gEntityInterface_addr;
		uint32_t cvars_vars_addr;
		uint32_t numuserfilters_addr;
		uint32_t userfilters_addr;
		uint32_t client_t_size;
		uint32_t realtime_addr;
		uint32_t SV_GetClientIDString_addr;
		uint32_t SV_GetIDString_addr;
		uint32_t SV_CheckCDKey_addr;
		uint32_t SV_CheckUserInfo_addr;
		uint32_t ClientID_off;
		uint32_t ReadPackets__ISMSU_HandleIncoming__haddr;
		uint32_t SendServerInfo_WriteLongProto_haddr;
		uint32_t Host_Error_addr;
		uint32_t ParseVoiceData_HostError_haddr;
		uint32_t Netchan_CreateFragments__addr;
		uint32_t SV_CheckCertificate_addr;
		uint32_t SV_CheckIPRestrictions_addr;
		uint32_t ParseCvarValue2_StrCpy_haddr;

		CFuncAddr* CreateFragments__Calls;
	};

	extern DSEngineData_Win_t DSEngineData;
#else
	struct DSEngineData_Lin_t {
		void* hLib;
		void* libBase;
		uint32_t Q_strcpy_addr;
		uint32_t Q_strcpy_jaddr;
		uint32_t SV_ConnectClient_addr;
		uint32_t MSG_WriteLong_addr;
		uint32_t SV_RejectConnection_addr;
		uint32_t MSG_WriteLong_jaddr;
		uint32_t SV_ParseCvarValue2_addr;
		uint32_t SV_RejectConnection_jaddr;
		uint32_t SV_CheckUserInfo_addr;
		uint32_t SV_CheckUserInfo_jaddr;
		uint32_t Info_ValueForKey_addr;
		uint32_t Info_ValueForKey_jaddr;
		uint32_t Steam_NotifyClientConnect_addr;
		uint32_t Steam_NotifyClientConnect_jaddr;
		uint32_t SV_ConnectionlessPacket_addr;
		uint32_t SV_ConnectionlessPacket_jaddr;
		uint32_t SVC_GetChallenge_addr;
		uint32_t SVC_GetChallenge_jaddr;
		uint32_t NET_SendPacket_addr;
		uint32_t NET_SendPacket_jaddr;
		uint32_t Host_Error_addr;
		uint32_t Host_Error_jaddr;
		uint32_t SV_ParseVoiceData_addr;
		uint32_t Netchan_CreateFragments__addr;
		uint32_t Netchan_CreateFragments__jaddr;
		uint32_t SV_CheckKeyInfo_addr;
		uint32_t SV_CheckKeyInfo_jaddr;

		uint32_t GSClientDenyHelper_addr;
		uint32_t GSClientDenyHelper_jaddr;
		uint32_t net_from_addr;

		uint32_t SV_SendServerInfo_addr;
		uint32_t SV_ReadPackets_addr;
		uint32_t SV_CheckTimeouts_addr;
		uint32_t SV_GetClientIDString_addr;
		uint32_t SV_GetIDString_addr;


		uint32_t CheckProto_GoodRet_addr;
		uint32_t CheckProto_BadRet_addr;
		uint32_t CheckProto_haddr;

		uint32_t CheckCDKey_haddr;
		uint32_t CheckCDKey_GoodRet_addr;

		uint32_t ValidationChecking_haddr;
		uint32_t ValidationChecking_GoodRet_addr;

		uint32_t SteamValidationCheck_haddr;

		uint32_t ProtocolWriteCode_haddr;

		uint32_t ISMSU_HandlePacket_haddr;

		uint32_t GetChallenge_SendPacket_haddr;

		uint32_t ConnectClient_AuthProto_soff;
		uint32_t ConnectClient_CDKey_soff;

		uint32_t ParseVoiceData_HostError_haddr;

		uint32_t ParseCvarValue2_StrCpy_haddr;

		uint32_t ConnectClient_IPRangeChecking_haddr;
		uint32_t ConnectClient_IPRangeChecking_GoodRet_addr;;

		uint32_t client_t_size;
		uint32_t ClientID_off;
	};

	extern DSEngineData_Lin_t DSEngineData;

#endif 

#endif //__DPROTO_H__
