#pragma once
#include "osconfig.h"

extern size_t gISteamGS_BSecure_addr;
extern size_t gISteamMSU_HandleIncomingPacket_addr;
extern size_t gpISteamMSU_HandleIncomingPacket_addr;

extern bool Parse_Imports();
extern bool Parse_CheckCertificate();
extern bool Parse_CheckProtocol();
extern bool Parse_SendServerInfo();
extern bool Parse_ConnectClient();
extern bool Parse_GetChallenge();
extern bool Parse_GSClientDenyHelper();
extern bool Parse_EntityInterface();
extern bool Parse_LogPrintServerVars();
extern bool Parse_ListId();
extern bool Parse_CheckTimeouts();
extern bool Parse_GetClientIDString();
extern bool Parse_GetIDString();
extern bool Parse_CheckCDKey();
extern bool Parse_CheckUserInfo();
extern bool Parse_ReadPackets();
extern bool Parse_HostError();
extern bool Parse_ParseVoiceData();
extern bool Parse_NetchanCreateFragments_();
extern bool Parse_QStrCpy();
extern bool Parse_ParseCvarValue2();