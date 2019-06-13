#include "osconfig.h"
#include "bspec.h"

PatchingFuncs_s *CurPatchData = NULL;
PatchingFuncs_s PFData[MAX_PATCHING_DATA];
int PFDataCount = 0;

void RegisterPFuncs(PatchingFuncs_s *pfuncs) {
	memcpy(PFData + (PFDataCount++), pfuncs, sizeof(PatchingFuncs_s));
}

void BSpec_Init() {
#ifdef _WIN32
	BS_Register_WDyn();
#else
	BS_Register_LDyn();
#endif
}
