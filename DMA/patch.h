/*
 * patch.h  --  DMA build: redirect to dma_patch.h
 *
 * Shadows Loader/patch.h so `#include "patch.h"` in any feature file
 * picks up the DMA implementation's header, which has an identical API.
 */
#pragma once
#include "dma_patch.h"
