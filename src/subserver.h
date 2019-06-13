#ifndef __SUBSERVER_H__
#define __SUBSERVER_H__
#include "osconfig.h"
#include "memu.h"

class CSubServer {
	public:
		unsigned long IP;
		unsigned int Port;
		int Socket;
		char ExecCmd[256];
		int CFrame;
		bool MClient_Active;
		CMasterClient MClient;
		int AnswerType;

		CSubServer();
		bool Init(unsigned long ip, unsigned int port, bool mclient_enable, int ansType);
		void Think();
		void SendData(char* buf, int len, unsigned int ip, unsigned int port);
		void ParseIncoming(char* buf, int len, unsigned int ip, unsigned int port);
		void ParseGetChallenge(char* buf, int len, unsigned int ip, unsigned int port);
		void ParseConnect(char* buf, int len, unsigned int ip, unsigned int port);
		void ProcessSocket();
		void SetRedirCmd(const char* cmd) {
			strcpy(ExecCmd, cmd);
		}

};


#endif //__SUBSERVER_H__
