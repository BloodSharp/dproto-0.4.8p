#include "osconfig.h"
#include "cfg.h"
#include "dynpatcher_base.h"


#ifdef _WIN32
bool ParseGenericDllData_PE(void* dllBase, generic_dlldata_t* gendlldata) {
	int i = 0;
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER) dllBase;
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		LCPrintf(true, "[DPROTO]: %s: Invalid dos header signature", __FUNCTION__);
		return false;
	}

	PIMAGE_NT_HEADERS NTHeaders = (PIMAGE_NT_HEADERS) ((size_t)dllBase + dosHeader->e_lfanew);
	if (NTHeaders->Signature != 0x4550) {
		LCPrintf(true, "[DPROTO]: %s: Invalid NT Headers signature", __FUNCTION__);
		return false;
	}

	PIMAGE_SECTION_HEADER cSection = (PIMAGE_SECTION_HEADER) ((size_t)(&NTHeaders->OptionalHeader) + NTHeaders->FileHeader.SizeOfOptionalHeader);

	PIMAGE_SECTION_HEADER CodeSection = NULL;
	gendlldata->rdata = NULL;

	for (i = 0; i < NTHeaders->FileHeader.NumberOfSections; i++, cSection++) {
		if (cSection->VirtualAddress == NTHeaders->OptionalHeader.BaseOfCode)
			CodeSection = cSection;
		if (cSection->VirtualAddress >= NTHeaders->OptionalHeader.BaseOfData) {
			sectiondata_t *sd = (sectiondata_t*) malloc(sizeof(sectiondata_t));
			sd->start = (uint32_t)dllBase + cSection->VirtualAddress;
			sd->end = sd->start + cSection->SizeOfRawData;
			sd->NextSection = gendlldata->rdata;
			sd->ParentGenericData = gendlldata;
			gendlldata->rdata = sd;

			sd = (sectiondata_t*) malloc(sizeof(sectiondata_t));
			sd->start = (uint32_t)dllBase + cSection->VirtualAddress;
			sd->end = sd->start + cSection->Misc.VirtualSize;
			sd->NextSection = gendlldata->vdata;
			sd->ParentGenericData = gendlldata;
			gendlldata->vdata = sd;
		}
			
	}

	if (CodeSection == NULL) {
		LCPrintf(true, "[DPROTO]: %s: Code section not found");
		return false;
	}

	if (gendlldata->rdata == NULL) {
		LCPrintf(true, "[DPROTO]: %s: RData sections not found");
		return false;
	}

	if (gendlldata->vdata == NULL) {
		LCPrintf(true, "[DPROTO]: %s: VData sections not found");
		return false;
	}

	gendlldata->code.start = (uint32_t)dllBase + CodeSection->VirtualAddress;
	gendlldata->code.end = gendlldata->code.start + CodeSection->Misc.VirtualSize;
	gendlldata->code.NextSection = NULL;
	gendlldata->code.ParentGenericData = gendlldata;


	//we need to sort sections in rdata (using bubble sorting)
	bool Have_Changes = true;
	while (Have_Changes) {
		Have_Changes = false;
		sectiondata_t *prev = NULL;
		sectiondata_t *cur = gendlldata->rdata;
		while (cur) {
			if (prev) {
				if (prev->start > cur->start) {
					size_t tmp;
					tmp = prev->start; prev->start = cur->start; cur->start = tmp;
					tmp = prev->end; prev->end = cur->end; cur->end = tmp;
					Have_Changes = true;
				}
			}
			prev = cur;
			cur = cur->NextSection;
		}
	}

	//And in vdata too
	Have_Changes = true;
	while (Have_Changes) {
		Have_Changes = false;
		sectiondata_t *prev = NULL;
		sectiondata_t *cur = gendlldata->vdata;
		while (cur) {
			if (prev) {
				if (prev->start > cur->start) {
					size_t tmp;
					tmp = prev->start; prev->start = cur->start; cur->start = tmp;
					tmp = prev->end; prev->end = cur->end; cur->end = tmp;
					Have_Changes = true;
				}
			}
			prev = cur;
			cur = cur->NextSection;
		}
	}

	gendlldata->DllBase = dllBase;
	return true;
}
#else //linux

bool ParseGenericDllData_ELF(void* dllBase, void* FileData, uint32_t FileSize, generic_dlldata_t* gendlldata) {
	if (FileSize < sizeof(Elf32_Ehdr)) {
		LCPrintf(true, "[DPROTO]: %s: bad engine library file (header)\n", __FUNCTION__);
		return false;
	}

	Elf32_Ehdr* ehdr = (Elf32_Ehdr*) FileData;
	if (ehdr->e_ident[0] != 0x7F ||
		ehdr->e_ident[1] != 'E' ||
		ehdr->e_ident[2] != 'L' ||
		ehdr->e_ident[3] != 'F') {

			LCPrintf(true, "[DPROTO]: %s: ELF Signature mismatch (got %.2X %.2X %.2X %.2X)\n", __FUNCTION__, ehdr->e_ident[0], ehdr->e_ident[1], ehdr->e_ident[2], ehdr->e_ident[3]);
			return false;
	}

	int i;

	if (sizeof(Elf32_Phdr) > ehdr->e_phentsize)
		return false;

	if (sizeof(Elf32_Shdr) > ehdr->e_shentsize)
		return false;

	if (FileSize < (ehdr->e_phoff + ehdr->e_phentsize * ehdr->e_phnum)) {
		LCPrintf(true, "[DPROTO]: %s: bad engine library file (program headers)\n", __FUNCTION__);
		return false;
	}

	if (FileSize < (ehdr->e_shoff + ehdr->e_shentsize * ehdr->e_shnum)) {
		LCPrintf(true, "[DPROTO]: %s: bad engine library file (section headers)\n", __FUNCTION__);
		return false;
	}

	Elf32_Phdr* cpHdr = (Elf32_Phdr*)((size_t)FileData + ehdr->e_phoff);
	for (i = 0; i < ehdr->e_phnum; i++) {
		sectiondata_t *sd = (sectiondata_t*) malloc(sizeof(sectiondata_t));
		sd->start = (uint32_t)dllBase + cpHdr->p_vaddr;
		sd->end = sd->start + cpHdr->p_filesz;
		sd->NextSection = gendlldata->rdata;
		sd->ParentGenericData = gendlldata;
		gendlldata->rdata = sd;

		sd = (sectiondata_t*) malloc(sizeof(sectiondata_t));
		sd->start = (uint32_t)dllBase + cpHdr->p_vaddr;
		sd->end = sd->start + cpHdr->p_memsz;
		sd->NextSection = gendlldata->vdata;
		sd->ParentGenericData = gendlldata;
		gendlldata->vdata = sd;

		cpHdr = (Elf32_Phdr*)((size_t)cpHdr + ehdr->e_phentsize);
	}


	//LCPrintf(false, "[DPROTO]: %s: e_shstrndx = 0x%.8X; e_shoff=0x%.8X;\n", __FUNCTION__, ehdr->e_shstrndx, ehdr->e_shoff);
	uint32_t StringSectionHdrOff = ehdr->e_shoff + ehdr->e_shstrndx * ehdr->e_shentsize;
	if (FileSize < (StringSectionHdrOff + ehdr->e_shentsize)) {
		LCPrintf(true, "[DPROTO]: %s: bad engine library file (string section not found)\n", __FUNCTION__);
		return false;
	}
	Elf32_Shdr* shstrHdr = (Elf32_Shdr*) ((size_t)FileData + StringSectionHdrOff);
	char* StringTable = (char*) ((size_t)FileData + shstrHdr->sh_offset);
	gendlldata->code.start = 0;
	gendlldata->code.NextSection = NULL;
	gendlldata->sect_got.start = 0;
	gendlldata->sect_got.NextSection = NULL;
	gendlldata->sect_plt.start = 0;
	gendlldata->sect_plt.NextSection = NULL;

	

	gendlldata->GlobalsBase = 0;
	Elf32_Shdr* csHdr = (Elf32_Shdr*)((size_t)FileData + ehdr->e_shoff);
	for (i = 0; i < ehdr->e_shnum; i++) {
		const char* sname = StringTable + csHdr->sh_name;
		
		//LCPrintf(false, "Seg[%d].name = 0x%.8X\n", i, csHdr->sh_name);
		//LCPrintf(false, "Seg[%d].name = '%s'\n", i, sname);

		if (!strcmp(sname, ".got")) {
			gendlldata->sect_got.start = (uint32_t)dllBase + csHdr->sh_addr;
			gendlldata->GlobalsBase = gendlldata->sect_got.start;
			gendlldata->sect_got.end = gendlldata->sect_got.start + csHdr->sh_size;
		} else if (!strcmp(sname, ".text")) {
			gendlldata->code.start = (uint32_t)dllBase + csHdr->sh_addr;
			gendlldata->code.end = gendlldata->code.start + csHdr->sh_size;
		} else if (!strcmp(sname, ".plt")) {
			gendlldata->sect_plt.start = (uint32_t)dllBase + csHdr->sh_addr;
			gendlldata->sect_plt.end = gendlldata->sect_plt.start + csHdr->sh_size;
		}

		
		csHdr = (Elf32_Shdr*)((size_t)csHdr + ehdr->e_shentsize);
	}
		
	if (gendlldata->GlobalsBase == 0) {
		LCPrintf(true, "[DPROTO]: %s: bad engine library file (.got section not found)\n", __FUNCTION__);
		return false;
	}

	if (gendlldata->code.start == 0) {
		LCPrintf(true, "[DPROTO]: %s: bad engine library file (.text section not found)\n", __FUNCTION__);
		return false;
	}

	if (gendlldata->sect_plt.start == 0) {
		LCPrintf(true, "[DPROTO]: %s: bad engine library file (.plt section not found)\n", __FUNCTION__);
		return false;
	}

	gendlldata->sect_got.ParentGenericData = gendlldata;
	gendlldata->sect_plt.ParentGenericData = gendlldata;
	gendlldata->code.ParentGenericData = gendlldata;

	/*
	LCPrintf(false, "[DPROTO]: %s: .plt section 0x%.8X - 0x%.8X\n", __FUNCTION__, gendlldata->sect_plt.start, gendlldata->sect_plt.end);
	FILE *fl = fopen("pltdump.bin", "wb");
	fwrite((void*)gendlldata->sect_plt.start, 1, (gendlldata->sect_plt.end-gendlldata->sect_plt.start), fl);
	fclose(fl);
	*/

	return true;
}
#endif //linux

#if defined(linux)
bool Dll_FindJumpToPtr(sectiondata_t* sd, uint32_t ptr_addr, uint32_t *pJumpAddr) {
	uint32_t j_addr = 0;
	uint32_t tmp;

	/* Try search for "jmp [???]" instruction
		FF25 ???????? jmp [????????]
	*/

	j_addr = Dll_FindRef_Prefix2(sd, j_addr, ptr_addr, 0x25FF, false);
	if (j_addr) {
		if (pJumpAddr)
			*pJumpAddr = j_addr;
		return true;
	}

	/* If nothing found, try search "jmp [ebx+?]" 
		FFA3 ???????? jmp [ebx+??]
	*/

	tmp = ptr_addr - sd->ParentGenericData->GlobalsBase;
	j_addr = Dll_FindRef_Prefix2(sd, j_addr, tmp, 0xA3FF, false);
	if (j_addr) {
		if (pJumpAddr)
			*pJumpAddr = j_addr;
		return true;
	}

	return false;
}

bool Dll_FindJumpToFunc(generic_dlldata_t* gendlldata, uint32_t FuncAddr, uint32_t* pPointerAddr, uint32_t *pJumpAddr) {
	/* Search in .got section for pointer to function */
	uint32_t ptr_addr = 0;
	uint32_t j_addr;
	uint32_t tmp;
	ptr_addr = Dll_FindDataRefInSection(&gendlldata->sect_got, FuncAddr, ptr_addr);
	
	while (ptr_addr) {
		//LCPrintf(false, "[DPROTO]: %s: Found ptr in .got section: 0x%.8X\n", __FUNCTION__, ptr_addr);
		if (Dll_FindJumpToPtr(&gendlldata->sect_plt, ptr_addr, &j_addr)) {
			if (pPointerAddr)
				*pPointerAddr = ptr_addr;
			if (pJumpAddr)
				*pJumpAddr = j_addr;
			return true;
		}

		ptr_addr = Dll_FindDataRefInSection(&gendlldata->sect_got, FuncAddr, ptr_addr + 1);
	}

	return false;
}

#endif //defined(linux)

bool IsRangeInSections(sectiondata_t* sdata, uint32_t Addr, uint32_t Size) {
	uint32_t Addr_End = Addr + Size - 1;
	while (sdata) {
		if (Addr >= sdata->start && Addr_End <= sdata->end)
			return true;
		sdata = sdata->NextSection;
	}
	return false;
}

uint32_t Dll_FindStringInSection(sectiondata_t* sdata, const char* str, uint32_t addr, bool FullMatch) {
	int slen = strlen(str);
	if (FullMatch)
		slen += 1;
	char* cs_end = (char*) (sdata->end - slen);
	char* cs = (char*) addr;
	
	if (cs >= cs_end)
		return NULL;

	while (memcmp(str, cs, slen)) {
		if (cs >= cs_end)
			return NULL;
		cs++;
	}
	return (uint32_t)cs;
}

uint32_t Dll_FindDataRefInSection(sectiondata_t* sdata, uint32_t RefAddr, uint32_t addr) {
	uint32_t* cs_end = (uint32_t*) (sdata->end - 4);
	uint32_t* cs = (uint32_t*) addr;
	if ((uint32_t)cs < sdata->start)
		cs = (uint32_t*)sdata->start;
	
	if (cs >= cs_end)
		return NULL;

	while (*cs != RefAddr) {
		if (cs >= cs_end)
			return NULL;
		cs = (uint32_t*) ((size_t)cs + 1);
	}
	return (uint32_t)cs;
}

uint32_t Dll_FindString(generic_dlldata_t* gendlldata, uint32_t StartAddr, const char* str, bool FullMatch) {
	sectiondata_t* csect = NULL;
	uint32_t cs;
	if (StartAddr == 0) {
		cs = gendlldata->rdata->start;
		csect = gendlldata->rdata;
	}
	else {
		cs = StartAddr + 1;
		sectiondata_t *cur = gendlldata->rdata;
		while (cur) {
			if (cur->start >= StartAddr) {
				csect = cur;
				break;
			}
			cur = cur->NextSection;
		}
	}

	while (csect) {
		cs = Dll_FindStringInSection(csect, str, cs, FullMatch);
		if (cs)
			return cs;

		csect = csect->NextSection;
		if (csect)
			cs = csect->start;
	}
	return NULL;
}

uint32_t Dll_FindDataRef(generic_dlldata_t* gendlldata, uint32_t StartAddr, uint32_t RefAddr) {
	sectiondata_t* csect = NULL;
	uint32_t cs;
	if (StartAddr == 0) {
		cs = gendlldata->rdata->start;
		csect = gendlldata->rdata;
	}
	else {
		cs = StartAddr + 1;
		//we need to find ourself x_x
		sectiondata_t *cur = gendlldata->rdata;
		while (cur) {
			if (cur->start >= StartAddr) {
				csect = cur;
				break;
			}
			cur = cur->NextSection;
		}
	}

	while (csect) {
		cs = Dll_FindDataRefInSection(csect, RefAddr, cs);
		if (cs)
			return cs;

		csect = csect->NextSection;
		if (csect)
			cs = csect->start;
	}
	return NULL;
}

uint32_t Dll_FindRef_Prefix1(sectiondata_t* sdata, uint32_t StartAddr, uint32_t RefAddress, uint8_t PrefixValue, bool Relative) {
	#pragma pack(push ,1)
	struct prefix8ref_t {
		uint8_t prefix;
		uint32_t Addr;
	};
	#pragma pack(pop)

	prefix8ref_t *CurInstr;

	if (StartAddr == 0)
		StartAddr = sdata->start;
	else
		StartAddr++;

	
	size_t EndAddr = sdata->end - sizeof(prefix8ref_t);

	while (StartAddr < EndAddr) {
		CurInstr = (prefix8ref_t*) StartAddr;
		if (CurInstr->prefix == PrefixValue) {
			if (!Relative) {
				if (CurInstr->Addr == RefAddress)
					return StartAddr;
			} else {
				if ( (StartAddr + 5 + CurInstr->Addr) == RefAddress)
					return StartAddr;
			}
		}
		StartAddr++;
	}

	return 0;
}

uint32_t Dll_FindRef_Prefix2(sectiondata_t* sdata, uint32_t StartAddr, uint32_t RefAddress, uint16_t PrefixValue, bool Relative) {
	#pragma pack(push ,1)
	struct prefix16ref_t {
		uint16_t prefix;
		uint32_t Addr;
	};
	#pragma pack(pop)

	prefix16ref_t *CurInstr;

	if (StartAddr == 0)
		StartAddr = sdata->start;
	else
		StartAddr++;

	
	size_t EndAddr = sdata->end - sizeof(prefix16ref_t);

	while (StartAddr < EndAddr) {
		CurInstr = (prefix16ref_t*) StartAddr;
		if (CurInstr->prefix == PrefixValue) {
			if (!Relative) {
				if (CurInstr->Addr == RefAddress)
					return StartAddr;
			} else {
				if ( (StartAddr + 6 + CurInstr->Addr) == RefAddress)
					return StartAddr;
			}
		}
		StartAddr++;
	}

	return 0;
}


uint32_t Dll_FindRef_Push(sectiondata_t* sdata, uint32_t StartAddr, uint32_t RefAddress) {
	return Dll_FindRef_Prefix1(sdata, StartAddr, RefAddress, 0x68, false);
}

uint32_t Dll_ScanForTemplate_Backward(generic_dlldata_t* gendlldata, const unsigned char* Templ, const unsigned char *Mask, int TemplSize, uint32_t Code_Start, uint32_t Code_Size) {
	uint8_t* Code_End = (uint8_t*) (Code_Start - Code_Size);
	uint8_t* Code_Cur = (uint8_t*) (Code_Start - TemplSize);
	if ((uint32_t)Code_End < gendlldata->code.start)
		Code_End = (uint8_t*) gendlldata->code.start;

	size_t Result = 0;
	int i;
	bool not_match;

	while (Code_Cur >= Code_End && !Result) {
		not_match = false;
		for (i = 0; i < TemplSize; i++) {
			if ((Code_Cur[i] & Mask[i]) != (Templ[i] & Mask[i])) {
				not_match = true;
				break;
			}
		}
		if (!not_match) {
			Result = (uint32_t) Code_Cur;
		}
		Code_Cur--;
	}

	return Result;
}

uint32_t Dll_ScanForTemplate_Forward(generic_dlldata_t* gendlldata, const unsigned char* Templ, const unsigned char *Mask, int TemplSize, uint32_t Code_Start, uint32_t Code_Size) {
	uint8_t* Code_End = (uint8_t*) (Code_Start + Code_Size);
	uint8_t* Code_Cur = (uint8_t*) (Code_Start);
	if ((uint32_t)Code_End > gendlldata->code.end)
		Code_End = (uint8_t*) gendlldata->code.end;

	Code_End -= TemplSize;

	size_t Result = 0;
	int i;
	bool not_match;

	while (Code_Cur <= Code_End && !Result) {
		not_match = false;
		for (i = 0; i < TemplSize; i++) {
			if ((Code_Cur[i] & Mask[i]) != (Templ[i] & Mask[i])) {
				not_match = true;
				break;
			}
		}
		if (!not_match) {
			Result = (size_t) Code_Cur;
		}
		Code_Cur++;
	}

	return Result;
}

