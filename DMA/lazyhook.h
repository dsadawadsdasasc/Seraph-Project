/*
 * lazyhook.h  --  DMA build: redirect to dma_lazyhook.h
 *
 * Shadows Loader/lazyhook.h so `#include "lazyhook.h"` resolves the DMA
 * implementation.  API is identical — all feature files compile unchanged.
 */
#pragma once
#include "dma_lazyhook.h"
