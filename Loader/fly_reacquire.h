#pragma once

#include <windows.h>

typedef struct FlyLocalEntityCandidate {
    UINT64 candidate_body;
    UINT64 candidate_owner;
    UINT64 candidate_world;
    UINT64 cached_world;
    UINT64 lp_entity;
    BOOL death_guard_active;
    BOOL tl_valid;
    float tl_dist2;
} FlyLocalEntityCandidate;

static inline BOOL Fly_IsCanonicalUserPtr(UINT64 ptr)
{
    return (ptr >= 0x10000ULL && ptr < 0x7FFFFFFFFFFFFULL);
}

static inline BOOL Fly_ShouldAcceptLocalEntityCandidate(const FlyLocalEntityCandidate *c)
{
    if (!c) return FALSE;
    if (!Fly_IsCanonicalUserPtr(c->candidate_body)) return FALSE;
    if (!Fly_IsCanonicalUserPtr(c->candidate_owner)) return FALSE;

    if (c->candidate_world && c->cached_world && c->candidate_world != c->cached_world)
        return FALSE;

    if (c->lp_entity && c->candidate_owner == c->lp_entity)
        return TRUE;

    if (c->tl_valid && c->tl_dist2 > 100.0f)
        return FALSE;

    if (c->death_guard_active && !c->tl_valid)
        return FALSE;

    return TRUE;
}

static inline BOOL Fly_ShouldKeepStableEpOnTlMismatch(BOOL fly_active,
                                                      BOOL death_guard_active,
                                                      float tl_dist2)
{
    if (fly_active) return TRUE;
    if (death_guard_active) return TRUE;
    return tl_dist2 <= 100.0f;
}

static inline BOOL Fly_ShouldAcceptTicketResolvedCandidate(UINT64 candidate_body,
                                                           UINT64 candidate_owner,
                                                           UINT64 candidate_world,
                                                           UINT64 cached_world)
{
    if (!Fly_IsCanonicalUserPtr(candidate_body)) return FALSE;
    if (!Fly_IsCanonicalUserPtr(candidate_owner)) return FALSE;
    if (candidate_world && cached_world && candidate_world != cached_world) return FALSE;
    return TRUE;
}
