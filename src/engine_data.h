#ifndef __ENGINEDATA_H__
#define __ENGINEDATA_H__

#include "osconfig.h"
#include <extdll.h>
#include <meta_api.h>
#include "dproto.h"
#include "cfg.h"

typedef int (CDECL *COM_BuildNumber_proto)(void);
typedef int (CDECL *CheckUserInfo_proto)(netadr_t *client_addr, char *UInfo, int bIsReconnecting, int UserSlot, char* ResultName);

extern SV_RejectConnection_proto SV_RejectConnection_func;
extern svs_t *psvs;
extern MSG_WriteLong_proto MSG_WriteLong_func;
extern ISMSU_HandlePacket_proto ISMSU_HandlePacket_func;
extern NET_SendPacket_proto NET_SendPacket_func;
extern Steam_GSBSecure_proto Steam_GSBSecure_func;
extern Steam_NotifyClientConnect_proto Steam_NotifyClientConnect_func;
extern cvar_t** cvar_vars_v;
extern SV_StartSteamValidation_proto SV_StartSteamValidation_func;
extern SV_ConnectionlessPacket_proto SV_ConnectionlessPacket_func;
extern net_message_t* pnet_message;
extern netadr_t* pnet_from;
extern COM_BuildNumber_proto COM_BuildNumber_func;
extern CheckUserInfo_proto CheckUserInfo_func;

extern size_t SV_ConnectClient_addr;
extern size_t SV_GetClientIDString_addr;
extern size_t SV_GetIDString_addr;
extern size_t SV_SendServerInfo_addr;
extern size_t SV_ReadPackets_addr;
extern size_t SV_CheckUserInfo_addr;
extern size_t SV_CheckForDuplicateNames_addr;
extern size_t SVC_GetChallenge_addr;
extern size_t COM_Munge2_addr;
extern size_t gEntityInterface_addr;

extern size_t Info_ValueForKey_addr;
extern size_t Info_SetValueForStarKey_addr;
extern size_t Info_RemoveKey_addr;
extern size_t Info_RemovePrefixedKeys_addr;

//for old servers
extern size_t SV_FinishCertificateCheck_addr;
extern size_t ValveAuth_Init_addr;
extern size_t SV_StartSteamValidation_addr;
extern size_t SV_StartSteamValidation_jmp;

//for new servers
extern size_t Steam_NotifyClientConnect_addr;
extern size_t Steam_GSBSecure_addr;
extern size_t ISMSU_HandlePacket_addr;
extern size_t GSClientDenyHelper_addr;


int EngineData_Init(int build);
bool FindSymbol(void* hlib, const char* sName, uint32_t* pSym);

void SteamConnect_Helper();
void SVC_GetChallenge_Helper();
void CheckForDuplicateNames_Helper();
void ReadPackets_Helper();
void WriteProto_Helper();
void CheckUserInfo_Helper();
void ValidationCheck_Helper();
void CheckCDKey_Helper();
void CheckProtocol_Helper();

#endif //__ENGINEDATA_H__
