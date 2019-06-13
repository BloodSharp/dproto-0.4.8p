#ifndef __PLR_LIST_H__
#define __PLR_LIST_H__

bool PlrList_Init();
int CountActivePlayers();

int SrvInfo_Build(unsigned char *SendBuf, int AnswerType, int ServerPort);
int PlayersList_Build(char *SendBuf);
int Rules_Build(unsigned char* RulesBuf, int BufLen);

void SendSrvInfo_Native(int ip, int port, int AnswerType);
void SendPlayersList_Native(int ip, int port);
void SendRules_Native(int ip, int port);


void SendRules_FromSocket(int Socket, int ip, int port);
void SendPlayersList_FromSocket(int Socket, int ip, int port);
void SendSrvInfo_FromSocket(int Socket, int ip, int port, int AnswerType, int ServerPort);

#endif //__PLR_LIST_H__
