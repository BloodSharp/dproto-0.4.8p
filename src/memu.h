#ifndef __MEMU_H__
#define __MEMU_H__
#include "osconfig.h"
#include <time.h>

#define MAX_MASTER_SERVERS 32
#define MEMU_RETRY_TIME 10
#define MEMU_UPDATE_TIME 800

#ifdef _WIN32
	#pragma pack(push, 1)
#else
	#pragma push()
	#pragma pack(1)
#endif

struct TMasterChallenge {
	int id; //0xFFFFFFFF
	unsigned char opc1;
	unsigned char opc2;
	int chid;
};

#ifdef _WIN32
	#pragma pack(pop)
#else
	#pragma pop()
#endif

#define MSD_STATE_IDLE 0
#define MSD_STATE_HELLO_SENT 1
#define MSD_STATE_ACTIVE 2
#define MSD_STATE_OUTDATED 3

struct TMasterServerData {
	unsigned int IP;
	unsigned int Port;
	int Challenge;
	bool Alive;
	int State;
	time_t SendTime;
};

class CMasterClient {
	public:
		char CurMapName[256];
		TMasterServerData Servers[MAX_MASTER_SERVERS];
		int NServers;
		int CSocket;
		unsigned int CFrame;

		CMasterClient();
		bool AddMasterServer(unsigned int ip, unsigned int port);
		TMasterServerData* FindMasterServer(unsigned int ip, unsigned int port);
		void SendData(char* buf, int len, unsigned int ip, unsigned int port);
		void Activate();
		void SendHello(TMasterServerData* msd);
		void SendBye(TMasterServerData* msd);
		void SendInfo(TMasterServerData* msd);
		void HandleOutdated(TMasterServerData* msd);
		void HandleBadChallenge(TMasterServerData* msd);
		bool ParseIncoming(char* buf, int len, unsigned int ip, unsigned int port);
		void OnThink(bool NoMiss);
		void HeartBeat();


};

#endif //__MEMU_H__

