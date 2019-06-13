#include "osconfig.h"
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <limits.h>
#include <time.h>

#include <extdll.h>
#include <meta_api.h>
#include "pm_shared/pm_defs.h"

#include "dproto.h"
#include "cfg.h"
//#include "memu.h"
#include "engine_data.h"
#include "HookTools.h"
#include "plr_list.h"

//b-spec
#include "bspec.h"

int dproto_init() {
	bool pres = false;
	MainConfig.CurBuild = 0;
	if (!dproto_init_shared()) {
		return 0;
	}

	if (!EngineData_Init(MainConfig.CurBuild)) {
		return false;
	}

	LCPrintf(false, "[DPROTO]: Patching for: %s...\n", CurPatchData->GetBuildDescription());
	pres = CurPatchData->Patch();

	if (pres) {
		dproto_PostInit_shared();
		LCPrintf(true, "[DPROTO]: Done.\n");
		return 1;
	}
	return 0;
}
