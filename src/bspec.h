#ifndef __BSPEC_H__
#define __BSPEC_H__
#include "osconfig.h"

struct ProbeData_t {
	void* hLib;
	void* libBase;
	void* libFileBase;
	uint32_t libFileSize;
};

typedef const char* (CDECL *PFP_GetBuildDescr)();
typedef bool (CDECL *PFP_Probe)(const ProbeData_t* prData);
typedef void (CDECL *PFP_PreInit)();
typedef bool (CDECL *PFP_Init)(void* hLib);
typedef bool (CDECL *PFP_Patch)();

#define MAX_PATCHING_DATA 64

struct PatchingFuncs_s {
	PFP_GetBuildDescr GetBuildDescription;
	PFP_Probe Probe;
	PFP_PreInit PreInit;
	PFP_Init Init;
	PFP_Patch Patch;
};

extern PatchingFuncs_s *CurPatchData;
extern PatchingFuncs_s PFData[MAX_PATCHING_DATA];
extern int PFDataCount;
void RegisterPFuncs(PatchingFuncs_s *pfuncs);
void BSpec_Init();

#ifdef _WIN32	//WINDOWS

#include "swds_data.h"
#include "b-spec/BS_Win_Dynamic.h"

#elif defined(linux) //LINUX

#include "engine_data.h"
#include "b-spec/BS_Linux_Dynamic.h"

#endif



#endif //__BSPEC_H__
