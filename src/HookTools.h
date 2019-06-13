#pragma once
#include "osconfig.h"

unsigned int HookFunction(void *OrigAddr, void* NewAddr);
unsigned int HookFunction_call(void *OrigAddr, void* NewAddr);
unsigned int HookDWord(uint32_t *OrigAddr, uint32_t NewDWord);
extern void PatchNOPs(void* OrigAddr, int Cnt);

