#pragma once
#include "osconfig.h"
#include "dproto.h"

extern bool Parse_ConnectClient();
extern bool Parse_BaseFunctions();
extern bool Parse_Jumps();
extern bool Parse_SendServerInfo();
extern bool Parse_ReadPackets();
extern bool Parse_GetChallenge();
extern bool Parse_GetClientIDString();
extern bool Parse_CheckTimeouts();
extern bool Parse_ParseVoiceData();
extern bool Parse_ParseCvarValue2();

