#include "osconfig.h"
#include "subserver.h"
#include "cfg.h"
#include "dproto.h"
#include "plr_list.h"

unsigned char mungify_table2[16] = {0x05, 0x61, 0x7A, 0xED, 0x1B, 0xCA, 0x0D, 0x9B, 0x4A, 0xF1, 0x64, 0xC7, 0xB5, 0x8E, 0xDF, 0xA0};

union ChInt {
	int iPart;
	unsigned char chPart[4];
};

void Munge2(int *iBuf, signed int Len, int Seq) {
	int i; // edi@1
	signed int nSeq; // ebp@2
	int *pcInt; // esi@3
	unsigned int v6; // edx@3
	signed int q_len; // [sp+18h] [bp-14h]@1
	ChInt CurInt;

	q_len = Len >> 2;
	i = 0;
	nSeq = ~Seq;
	while ( i < q_len ) {
    
		pcInt = &iBuf[i];
		v6 = *pcInt ^ nSeq;
		
		CurInt.iPart = (v6 >> 24) + ((v6 >> 8) & 0xFF00) + ((v6 << 8) & 0xFF0000) + (v6 << 24);

		CurInt.chPart[0] ^= mungify_table2[i & 0xF] | 0xA5;
		CurInt.chPart[1] ^= mungify_table2[(i + 1) & 0xF] | 0xA7;
		CurInt.chPart[2] ^= mungify_table2[(i + 2) & 0xF] | 0xAF;
		CurInt.chPart[3] ^= mungify_table2[(i + 3) & 0xF] | 0xBF;
		*pcInt = CurInt.iPart ^ Seq;
		++i;
	}
}

CSubServer::CSubServer() {
	memset(ExecCmd, 0, sizeof(ExecCmd));
	Socket = -1;
	IP = 0;
	Port = 0;
	CFrame = 0;
	MClient_Active = false;
}

bool CSubServer::Init(unsigned long ip, unsigned int port, bool mclient_enable, int ansType) {
	int res;
	sockaddr_in saddr;
	IP = ip;
	Port = port;
	MClient_Active = mclient_enable;
	AnswerType = ansType;
	int bcast = 1;

	memset(&saddr, 0, sizeof(saddr));
	Socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (Socket == -1) {
		LCPrintf(true, "[DPROTO]: CSubServer: Cannot create UDP socket\n");
		return false;
	}

#if defined(linux)
	if (ioctl(Socket, FIONBIO, &bcast) == -1) {
#else
	if (ioctlsocket(Socket, FIONBIO, (u_long*) &bcast) == -1)	{
#endif
		LCPrintf(true, "WARNING: UDP_OpenSocket: ioctl FIONBIO failed\n");
		return false;
	}

	bcast = 1;
	if (setsockopt(Socket, SOL_SOCKET, SO_BROADCAST, (const char*) &bcast, sizeof(bcast)) == -1) {
		LCPrintf(true, "[DPROTO]: CSubServer: Cant turn on broadcast mode\n");
	}

	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(Port);
	SIN_SET_ADDR(&saddr.sin_addr, INADDR_ANY)
	res = bind(Socket, (sockaddr*) &saddr, sizeof(saddr));
	if (res) {
		LCPrintf(true, "[DPROTO]: CSubServer: Cannot bind UDP socket to port %d\n", Port);
		SOCKET_CLOSE(Socket)
		Socket = -1;
		return false;
	}

	if (MClient_Active) {
		MClient.CSocket = Socket;
	}
	return true;
}

void CSubServer::SendData(char* buf, int len, unsigned int ip, unsigned int port) {
	sockaddr_in saddr;
	saddr.sin_family = AF_INET;
	SIN_SET_ADDR(&saddr.sin_addr, ip)
	saddr.sin_port = htons(port);
	sendto(Socket, buf, len, 0, (sockaddr*)&saddr, sizeof(saddr));
}

void CSubServer::ParseGetChallenge(char* buf, int len, unsigned int ip, unsigned int port) {
	char* cbuf = buf + 4;
	int ctype = 0;
	char SBuf[1500];
	int res;
	//LCPrintf(false, "CSubServer::GetChallenge(); len=%d\n", len);
	if (len < 16) return;
	if (strncmp(cbuf, "getchallenge", 12)) return;
	
	buf[len] = 0;
	cbuf = buf + 17;
	//LCPrintf(false, "CSubServer::GetChallenge2(); buf='%s'\n", cbuf);
	if (!strcmp(cbuf, "valve\n")) {
		ctype = 2;
	} else if (!strcmp(cbuf, "steam\n")) {
		ctype = 3;
	} else 
		return;

	cbuf = SBuf;
	res = sprintf(cbuf, "%c%c%c%c%c%s", 0xFF, 0xFF, 0xFF, 0xFF, 'A', "00000000 ");
	cbuf += res;
	res = (rand() | (rand() << 16)) & 0x7FFFFFFF;
	res = sprintf(cbuf, "%u %d", res, ctype);
	cbuf += res;
	switch (ctype) {
		case 2:
			res = sprintf(cbuf, "\n");
			cbuf += res + 1;
			break;

		case 3:
			res = sprintf(cbuf, " %dm %s\n", 1, "30819d300d06092a864886f70d010101050003818b0030818702818100b5a614e896036cc9f9bd6d13f2f5c79fbb5f925e8dbb50f0b9ee9a5499f535978fe60c188e4f8872160d86b76b80f1ba82333d586b32692ffa31e1dd59a603dc6370004566afa54830898d4ff210c738deb059e0a94a87dd85be28668793681a4ecf647fa1b5294a73927f23ffba0c6a9140922d27002012fed2b4a898aa7811020111"); 
			cbuf += res + 1;
			break;
	}
	res = cbuf - SBuf;
	//LCPrintf(false, "CSubServer::GetChallenge_Send(); ip=%.8X; port=%d\n", ip, port);
	SendData(SBuf, res, ip, port);
}

void CSubServer::ParseConnect(char* buf, int len, unsigned int ip, unsigned int port) {
	char* cbuf = buf + 4;
	char SBuf[1500];
	in_addr ina;
	int res;
	if (len < 11) return;
	if (strncmp(cbuf, "connect", 7)) return;
	cbuf = SBuf;
	SIN_SET_ADDR(&ina, ip);
	res = sprintf(cbuf, "%c%c%c%c%c %d \"%s:%d\" %d", 0xFF, 0xFF, 0xFF, 0xFF, 'B', 1, inet_ntoa(ina), port, 0);
	cbuf += res;

	res = cbuf - SBuf;
	SendData(SBuf, res, ip, port);

	cbuf = SBuf;
	res = sprintf(cbuf, "%c%c%c%c%c%c%c%c", 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0);
	cbuf += res;
	res = sprintf(cbuf, "%cecho \"* Redirecting...\"; %s\n", 0x9, MainConfig.RedirectCmd);
	cbuf += res + 1;

	res = cbuf - SBuf;
	while (res % 4) {
		SBuf[res++] = 1;
	}

	Munge2((int*)(SBuf+8), res-8, 0);
	SendData(SBuf, res, ip, port);
}


void CSubServer::ParseIncoming(char* buf, int len, unsigned int ip, unsigned int port) {
	int *pAck = (int*) buf;
	
	if (len < 4 || *pAck != 0xFFFFFFFF) return;
	switch (buf[4]) {
		case 'g':
			ParseGetChallenge(buf, len, ip, port);
			break;

		case 'c':
			ParseConnect(buf, len, ip, port);
			break;

		case 'T':
			SendSrvInfo_FromSocket(Socket, ip, port, AnswerType, Port);
			break;
		case 'U':
			SendPlayersList_FromSocket(Socket, ip, port);
			break;
		case 'V':
			SendRules_FromSocket(Socket, ip, port);
			break;

		default:
			if (MClient_Active) 
				MClient.ParseIncoming(buf, len, ip, port);

	}
}

void CSubServer::ProcessSocket() {
	char Buf[2048];
	int res = 0;
	sockaddr_in saddr;
	socklen_t alen = sizeof(saddr);
	unsigned int ip;
	if (Socket == -1)
		return;
	res = recvfrom(Socket, Buf, 2046, 0, (sockaddr*) &saddr, &alen);
	while (res > 0) {
		alen = sizeof(saddr);
		SIN_GET_ADDR(&saddr.sin_addr, ip)
		ParseIncoming(Buf, res, ip, ntohs(saddr.sin_port));
		res = 0;
		res = recvfrom(Socket, Buf, 2046, 0, (sockaddr*) &saddr, &alen);
	}
}

void CSubServer::Think() {
	ProcessSocket();
	if (MClient_Active) 
		MClient.OnThink(false);
}
