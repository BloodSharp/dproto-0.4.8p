#include "osconfig.h"
#include "memu.h"
#include "cfg.h"
#include "dproto.h"
#include "plr_list.h"

#ifdef _WIN32	//WINDOWS
	#include "swds_data.h"
	#include "windows.h"
	#include "winsock.h"
#elif defined(linux) //LINUX
	#include "engine_data.h"
#endif

CMasterClient::CMasterClient() {
	memset(Servers, 0, sizeof(Servers));
	memset(CurMapName, 0, sizeof(CurMapName));
	NServers = 0;
	CSocket = -1;
	CFrame = 0;
}

bool CMasterClient::AddMasterServer(unsigned int ip, unsigned int port) {
	if (NServers+1 >= MAX_MASTER_SERVERS) {
		LCPrintf(true, "[DPROTO]: CMasterClient::AddMasterServer: Trying to add more than %d master servers\n", MAX_MASTER_SERVERS);
		return false;
	}
	Servers[NServers].IP = ip;
	Servers[NServers].Port = port;
	Servers[NServers].Alive = false;
	Servers[NServers].State = MSD_STATE_IDLE;
	NServers++;
	return true;
}

TMasterServerData* CMasterClient::FindMasterServer(unsigned int ip, unsigned int port) {
	int i;
	for (i = 0; i < NServers; i++) {
		if (Servers[i].IP == ip && Servers[i].Port == port)
			return &Servers[i];
	}
	return NULL;
}

void CMasterClient::SendData(char* buf, int len, unsigned int ip, unsigned int port) {
	netadr_t toaddr;
	sockaddr_in saddr;
	if (CSocket == -1) {
		toaddr.type = NA_IP;
		memcpy(&toaddr.ip_addr, &ip, 4);
		toaddr.port = htons(port);
		NET_SendPacket_func(1, len, buf, toaddr);
	} else {
		saddr.sin_family = AF_INET;
		SIN_SET_ADDR(&saddr.sin_addr, ip)
		saddr.sin_port = htons(port);
		sendto(CSocket, buf, len, 0, (sockaddr*)&saddr, sizeof(saddr));
	}
}

void CMasterClient::SendHello(TMasterServerData* msd) {
	char buf[4];
	buf[0] = 'q';
	in_addr ia;
	SIN_SET_ADDR(&ia, msd->IP)
	SendData(buf, 1, msd->IP, msd->Port);
	msd->SendTime = time(NULL);
	msd->State = MSD_STATE_HELLO_SENT;
	LCPrintf(false, "[MEMU]: Hello sent to %s:%d\n", inet_ntoa(ia), msd->Port);
}

void CMasterClient::SendInfo(TMasterServerData* msd) {
	char buf[512];
	int res;
	in_addr ia;
	SIN_SET_ADDR(&ia, msd->IP)
	res = sprintf(buf, "0\n\\protocol\\47\\challenge\\%d\\players\\%d\\max\\%d\\bots\\0\\gamedir\\%s\\map\\%s\\type\\d\\password\\0\\os\\l\\secure\\0\\lan\\0\\version\\%s\\region\\255\\product\\valve\n", msd->Challenge, CountActivePlayers(), VA_Funcs.GetMaxClients(), MainConfig.GameDir, CurMapName, MainConfig.Master_GameVersion);
	SendData(buf, res, msd->IP, msd->Port);
	msd->SendTime = time(NULL);
	msd->State = MSD_STATE_ACTIVE;
	LCPrintf(false, "[MEMU]: Info sent to %s:%d\n", inet_ntoa(ia), msd->Port);
}

void CMasterClient::SendBye(TMasterServerData* msd) {
	char buf[4];
	buf[0] = 'b'; buf[1] = 0x0a;
	SendData(buf, 2, msd->IP, msd->Port);
	msd->SendTime = time(NULL);
	msd->State = MSD_STATE_HELLO_SENT;
}

void CMasterClient::HandleOutdated(TMasterServerData* msd) {
	in_addr sa;
	SIN_SET_ADDR(&sa, msd->IP)
	LCPrintf(true, "[DPROTO]: MasterClient: Server %s reports that you game version outdated\n", inet_ntoa(sa));
	msd->State = MSD_STATE_OUTDATED;
}

void CMasterClient::HandleBadChallenge(TMasterServerData* msd) {
	in_addr sa;
	SIN_SET_ADDR(&sa, msd->IP)
		LCPrintf(true, "[DPROTO]: MasterClient: Server %s:%d: Bad Challenge\n", inet_ntoa(sa), msd->Port);
	msd->State = MSD_STATE_HELLO_SENT;
}

void CMasterClient::Activate() {
	int i;
	for (i = 0; i < NServers; i++) {
		if (Servers[i].IP) {
			if (Servers[i].State == MSD_STATE_ACTIVE) {
				SendBye(&Servers[i]);
			}
			SendHello(&Servers[i]);
		}
	}
}

bool CMasterClient::ParseIncoming(char* buf, int len, unsigned int ip, unsigned int port) {
	TMasterChallenge *mc = (TMasterChallenge*) buf;
	TMasterServerData *msd;
	if (len < 6) return false;
	if (mc->id != 0xFFFFFFFF) return false;
	switch (mc->opc1) {
		case 's':
			msd = FindMasterServer(ip, port);
			if (!msd) return false;
			msd->Challenge = mc->chid;
			SendInfo(msd);
			return true;

		case 'O':
			msd = FindMasterServer(ip, port);
			if (!msd) return false;
			HandleOutdated(msd);
			return true;

		case 'l':
			msd = FindMasterServer(ip, port);
			if (!msd) return false;
			HandleBadChallenge(msd);
			return true;

	}
	return false;
}

void CMasterClient::HeartBeat() {
	int i;
	time_t ctime = time(NULL);
	for (i = 0; i < NServers; i++) {
		if (Servers[i].IP) {
			if (Servers[i].State == MSD_STATE_HELLO_SENT && difftime(ctime, Servers[i].SendTime) >= MEMU_RETRY_TIME) {
				SendHello(&Servers[i]);
			} else if (Servers[i].State == MSD_STATE_ACTIVE && difftime(ctime, Servers[i].SendTime) >= MEMU_UPDATE_TIME) {
				SendBye(&Servers[i]);
				SendHello(&Servers[i]);
			}
		}
	}
	
}

void CMasterClient::OnThink(bool NoMiss) {
	const char* mapName;
	if (!NoMiss) {
		if (++CFrame & 0x1F) 
			return;
	}

	mapName = STRING(gpGlobals->mapname);

	if (strlen(CurMapName) == 0 || strcmp(CurMapName, mapName)) {
		strcpy(CurMapName, mapName);
		Activate();
		return;
	}
	HeartBeat();
}
