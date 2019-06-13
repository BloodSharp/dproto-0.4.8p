#pragma once

#include "osconfig.h"

struct generic_dlldata_t;

struct sectiondata_t {
	uint32_t start;
	uint32_t end;
	sectiondata_t *NextSection;
	generic_dlldata_t* ParentGenericData;
};

struct generic_dlldata_t {
	void* DllBase;
	sectiondata_t code;
	sectiondata_t *rdata;
	sectiondata_t *vdata;

	/* Linux Only */
	uint32_t GlobalsBase;
	sectiondata_t sect_got;
	sectiondata_t sect_plt;
};


class CFuncAddr {
public:
	uint32_t Addr;
	CFuncAddr * Next;

	CFuncAddr(uint32_t addr) {
		Addr = addr;
		Next = NULL;
	}

	~CFuncAddr() {
		if (Next) {
			delete Next;
			Next = NULL;
		}
	}
};

#ifdef _WIN32
	extern bool ParseGenericDllData_PE(void* dllBase, generic_dlldata_t* gendlldata);
#else
	bool ParseGenericDllData_ELF(void* dllBase, void* FileData, uint32_t FileSize, generic_dlldata_t* gendlldata);
#endif


extern uint32_t Dll_FindString(generic_dlldata_t* gendlldata, uint32_t StartAddr, const char* str, bool FullMatch);
extern uint32_t Dll_ScanForTemplate_Backward(generic_dlldata_t* gendlldata, const unsigned char* Templ, const unsigned char *Mask, int TemplSize, uint32_t Code_Start, uint32_t Code_Size);
extern uint32_t Dll_ScanForTemplate_Forward(generic_dlldata_t* gendlldata, const unsigned char* Templ, const unsigned char *Mask, int TemplSize, uint32_t Code_Start, uint32_t Code_Size);
extern uint32_t Dll_FindRef_Push(sectiondata_t* sdata, uint32_t StartAddr, uint32_t RefAddress);
extern uint32_t Dll_FindDataRef(generic_dlldata_t* gendlldata, uint32_t StartAddr, uint32_t RefAddr);
extern bool IsRangeInSections(sectiondata_t* sdata, uint32_t Addr, uint32_t Size);
extern uint32_t Dll_FindRef_Prefix1(sectiondata_t* sdata, uint32_t StartAddr, uint32_t RefAddress, uint8_t PrefixValue, bool Relative);
extern uint32_t Dll_FindRef_Prefix2(sectiondata_t* sdata, uint32_t StartAddr, uint32_t RefAddress, uint16_t PrefixValue, bool Relative);
extern uint32_t Dll_FindDataRefInSection(sectiondata_t* sdata, uint32_t RefAddr, uint32_t addr);

#if defined(linux)
	extern bool Dll_FindJumpToPtr(sectiondata_t* sd, uint32_t ptr_addr, uint32_t *pJumpAddr);
	extern bool Dll_FindJumpToFunc(generic_dlldata_t* gendlldata, uint32_t FuncAddr, uint32_t* pPointerAddr, uint32_t *pJumpAddr);
#endif