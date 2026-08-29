/*
 * cave_finder.h  --  DMA build: redirect to dma_cave_finder.h
 *
 * Shadows Loader/cave_finder.h so `#include "cave_finder.h"` resolves the
 * DMA implementation.  API is identical — all feature files compile unchanged.
 */
#pragma once
#include "dma_cave_finder.h"
