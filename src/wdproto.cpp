#include "dproto.h"
#include "HookTools.h"
#include "swds_data.h"
#include "windows.h"
#include <stdio.h>
#include <stddef.h>

#include "cfg.h"
#include "plr_list.h"

#include "bspec.h"


inline void HookDWordEx(uint32_t *OrigAddr, uint32_t NewData, uint32_t OrigBytes, const char* Info) {
	uint32_t NOrig = HookDWord(OrigAddr, NewData);
	if (NOrig != OrigBytes) {
		LCPrintf(true, "[DPROTO]: WARNING: Original data mismatch on patch %s\n", Info);
		LCPrintf(true, "[DPROTO]: Real: 0x%.8X; Need: 0x%.8X\n", Info, NOrig, OrigBytes);
	}
}


int dproto_init() {
	MainConfig.CurBuild = 4382;
	if (!dproto_init_shared())
		return 0;

	if (!SwdsData_Init(MainConfig.CurBuild))
		return 0;

	LCPrintf(false, "[DPROTO]: Patching for: %s\n", CurPatchData->GetBuildDescription());
	if (!CurPatchData->Patch()) {
		LCPrintf(true, "[DPROTO]: Patching failed\n");
	}

	dproto_PostInit_shared();
	LCPrintf(true, "[DPROTO]: Done.\n");
	return 1;
}