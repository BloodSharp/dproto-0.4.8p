#ifndef __SWDSDATA_H__
#define __SWDSDATA_H__
#include "osconfig.h"
#include <extdll.h>
#include <meta_api.h>
#include "dproto.h"

extern size_t SV_CheckProtocol_off;
extern size_t SV_GetClientIDString_off;
extern size_t SV_GetIDString_off;
extern size_t SV_RejectConnection_off;
extern size_t svs_off;
extern size_t SV_CheckCDKey_off;
extern size_t SV_ConnectClient_off;
extern size_t SV_SendServerInfo_off;
extern size_t MSG_WriteLong_off;
extern size_t ISMSU_HandlePacket_ioff;
extern size_t NCmd_Argv_off;
extern size_t NET_SendPacket_off;
extern size_t RealTime_off;
extern size_t SV_CheckUserInfo_off;
extern size_t Steam_GSBSecure_off;
extern size_t gEntityInterface_off;

extern  size_t Info_ValueForKey_off;
extern  size_t Info_SetValueForStarKey_off;
extern  size_t Info_RemoveKey_off;


extern size_t cvar_vars_off;
extern size_t SVC_GetChallenge_off;
extern size_t Steam_NotifyClientConnect_off;
extern size_t GSClientDenyHelper_off;
extern size_t realtime_off;
extern size_t userfilters_off;
extern size_t numuserfilters_off;

typedef int (CDECL *SV_CheckProtocol_proto)(netadr_t *addr, int proto);
typedef void (CDECL *SV_RejectConnection_proto)(netadr_t *addr, char *Format, ...);
typedef int (CDECL *SV_CheckCDKey_proto) (netadr_t *addr, int auth_type, char *cdkey, char *userinfo);
typedef char* (CDECL *SV_GetIDString_proto) (clientid_t *cid);
typedef void (CDECL *MSG_WriteLong_proto) (int* msg, int value);
typedef void (CDECL *ISMSU_HandlePacket_proto) (char* a1, int a2, int ip, int port);
typedef char* (CDECL *NCmd_Argv_proto) (int narg);
typedef void (CDECL *NET_SendPacket_proto) (int nSock, int length, void *data, netadr_t to);
typedef int (CDECL *Steam_GSBSecure_proto) ();

extern size_t SV_CheckIp_addr;
extern size_t SV_CheckProtocol_addr;
extern size_t SV_GetClientIDString_addr;
extern size_t SV_GetIDString_addr;
extern size_t SV_RejectConnection_addr;
extern size_t svs_addr;
extern size_t SV_CheckCDKey_addr;
extern size_t SV_ConnectClient_addr;
extern size_t SV_SendServerInfo_addr;
extern size_t ISMSU_HandlePacket_iaddr;
extern size_t SV_CheckUserInfo_addr;
extern size_t SVC_GetChallenge_addr;
extern size_t SV_ConnectionlessPacket_addr;


extern size_t cvar_vars_addr;
extern size_t MSG_WriteLong_addr;
extern size_t NET_SendPacket_addr;
extern size_t userfilters_addr;
extern size_t numuserfilters_addr;
extern size_t realtime_addr;


/* For Unicode patch */
extern size_t Info_ValueForKey_addr;
extern size_t Info_SetValueForStarKey_addr;
extern size_t Info_RemoveKey_addr;
extern size_t Info_RemovePrefixedKeys_addr;


extern SV_RejectConnection_proto SV_RejectConnection_func;
extern SV_GetIDString_proto SV_GetIDString_func;
extern MSG_WriteLong_proto MSG_WriteLong_func;
extern ISMSU_HandlePacket_proto ISMSU_HandlePacket_func;
extern NET_SendPacket_proto NET_SendPacket_func;
extern Steam_GSBSecure_proto Steam_GSBSecure_func;
extern SV_ConnectionlessPacket_proto SV_ConnectionlessPacket_func;
extern Steam_NotifyClientConnect_proto Steam_NotifyClientConnect_func;

extern svs_t *psvs;
extern cvar_t** cvar_vars_v;
extern net_message_t* pnet_message;
extern netadr_t* pnet_from;

extern size_t ISMSU_HandlePacket_iaddr;
extern size_t Steam_NotifyClientConnect_addr;
extern size_t Steam_GSBSecure_addr;
extern size_t ISMSU_HandlePacket_addr;

extern size_t GSClientDenyHelper_addr;
extern size_t gEntityInterface_addr;

bool SwdsData_Init(int build);

#endif //__SWDSDATA_H__