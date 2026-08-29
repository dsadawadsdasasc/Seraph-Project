/*
 * attach.h  --  DMA build: redirect to dma_attach.h
 *
 * Shadows Loader/attach.h so `#include "attach.h"` resolves the DMA
 * implementation.  API is identical — all feature files compile unchanged.
 */
#pragma once
#include "dma_attach.h"
