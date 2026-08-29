/*
 * byovd.h  --  DMA build: redirect to dma_mem.hpp
 *
 * Shadows Loader/byovd.h so `#include "byovd.h"` pulls in the DMA memory
 * engine + macros (BYOVD_WriteVA → DMA_WriteVA, etc.) plus the DMA keyboard
 * wrappers (BYOVD_IsKeyDown → DMA_IsKeyDown).
 *
 * All feature .c files compile unchanged — no Loader/byovd.h is used in DMA
 * builds because /I"DMA" comes before /I"Loader" in the include path.
 */
#pragma once
#include "dma_mem.hpp"

/* g_byovdDiagStep — used by gui.c for loading-screen diagnostics.
 * Defined in dma_mem.cpp (line 33) as "DMA Engine Active" for DMA builds. */
extern volatile const char *g_byovdDiagStep;
