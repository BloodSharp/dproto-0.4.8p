#include "osconfig.h"
#include "HookTools.h"


#ifdef _WIN32	//WINDOWS
#include "windows.h"

#pragma pack(push, 1)
struct FuncHook2_s {
	unsigned char _jmp; //e9
	int addr;
};
#pragma pack(pop)

#elif defined(linux) //LINUX

#pragma push()
#pragma pack(1)
struct FuncHook2_s {
	unsigned char _jmp; //e9
	int addr;
};
#pragma pop()

#endif

#ifdef _WIN32	//WINDOWS

unsigned int HookFunction(void *OrigAddr, void* NewAddr) {
	FuncHook2_s* hook = (FuncHook2_s*) OrigAddr;
	unsigned int OrigVal = *(unsigned int*)OrigAddr;
	DWORD Oldp;
	VirtualProtect(OrigAddr, 8, PAGE_EXECUTE_READWRITE, &Oldp);
	hook->_jmp = 0xe9;
	hook->addr = (size_t)NewAddr - (size_t)OrigAddr - 5;

	VirtualProtect(OrigAddr, 8, Oldp, &Oldp);
	return OrigVal;
}

unsigned int HookDWord(uint32_t *OrigAddr, uint32_t NewDWord) {
	DWORD Oldp;
	int OrigVal = *OrigAddr;
	VirtualProtect(OrigAddr, 8, PAGE_EXECUTE_READWRITE, &Oldp);
	*OrigAddr = NewDWord;
	VirtualProtect(OrigAddr, 8, Oldp, &Oldp);
	return OrigVal;
}

unsigned int HookFunction_call(void *OrigAddr, void* NewAddr) {
	FuncHook2_s* hook = (FuncHook2_s*) OrigAddr;
	unsigned int OrigVal = *(unsigned int*)OrigAddr;
	DWORD Oldp;
	VirtualProtect(OrigAddr, 8, PAGE_EXECUTE_READWRITE, &Oldp);
	hook->_jmp = 0xe8;
	hook->addr = (size_t)NewAddr - (size_t)OrigAddr - 5;

	VirtualProtect(OrigAddr, 8, Oldp, &Oldp);
	return OrigVal;
}

void PatchNOPs(void* OrigAddr, int Cnt) {
	DWORD Oldp;
	VirtualProtect(OrigAddr, 8, PAGE_EXECUTE_READWRITE, &Oldp);
	memset(OrigAddr, 0x90, Cnt);
	VirtualProtect(OrigAddr, 8, Oldp, &Oldp);
}

#elif defined(linux) //LINUX

bool MProtect_Ex(void *addr, int npages) {
	void *paddr;
	paddr = (void *)(((size_t)addr) & ~(PAGESIZE-1));
	return !mprotect(paddr, PAGESIZE*(npages+1), PROT_READ | PROT_WRITE | PROT_EXEC);
}

unsigned int HookFunction(void *OrigAddr, void* NewAddr) {
	FuncHook2_s* hook = (FuncHook2_s*) OrigAddr;
	unsigned int OrigVal = *((unsigned int*)OrigAddr);
	MProtect_Ex(OrigAddr, 1);
	hook->_jmp = 0xe9;
	hook->addr = (int)NewAddr - (int)OrigAddr - 5;
	return OrigVal;
}

unsigned int HookFunction_call(void *OrigAddr, void* NewAddr) {
	FuncHook2_s* hook = (FuncHook2_s*) OrigAddr;
	unsigned int OrigVal = *((unsigned int*)OrigAddr);
	MProtect_Ex(OrigAddr, 1);
	hook->_jmp = 0xe8;
	hook->addr = (int)NewAddr - (int)OrigAddr - 5;
	return OrigVal;
}

unsigned int HookDWord(uint32_t *OrigAddr, uint32_t NewDWord) {
	unsigned int OrigVal = (unsigned int)*OrigAddr;
	MProtect_Ex(OrigAddr, 1);
	return OrigVal;
}

void PatchNOPs(void* OrigAddr, int Cnt) {
	MProtect_Ex(OrigAddr, 1);
	memset(OrigAddr, 0x90, Cnt);
}

#endif
