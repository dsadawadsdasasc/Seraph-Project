#define SERAPH_MARATHON
/* ── esp_overlay.cpp ──────────────────────────────────────────────────────── *
 * Dedicated layered, transparent, click-through full-screen window for ESP
 * rendering — independent of the main menu HWND. See esp_overlay.h.
 *
 * Design notes:
 * - WS_EX_LAYERED + LWA_COLORKEY (magenta) for transparency. We deliberately
 *   avoid per-pixel alpha (UpdateLayeredWindow / DComp) to keep the surface
 *   strategy identical to the menu HWND (D2D HwndRenderTarget, alpha-ignore).
 * - WS_EX_TRANSPARENT + WS_EX_NOACTIVATE so input passes through to the game.
 * - WDA_EXCLUDEFROMCAPTURE applied so the overlay is invisible to OBS/screen
 *   capture (matches behavior of the menu HWND).
 * - Lives on its own thread with its own D2D factory + render target so the
 *   menu and ESP render loops never share state.                            */
#include <windows.h>
#include <d2d1.h>
#include <dwrite.h>
#include <malloc.h>
#include <dwmapi.h>
#include <math.h>
#include "esp_overlay.h"
#include "esp.h"
#include "aimbot.h"
#include "debug.h"
#include "skeleton.h"
#include "matchmaking.h"
#include "fly.h"  /* Fly_GetCamWorldPos() — camera world pos in Havok units */
#include "marathon_game.h"

#ifdef SERAPH_DMA_BUILD
#include "seraph_fuser.h"
#endif

extern "C" void Overlay_SetStreamProofWindow(HWND hWnd, BOOL isEsp);
extern "C" bool Overlay_GetMatchmakingActive(void);

#pragma comment(lib, "d2d1.lib")
#pragma comment(lib, "dwrite.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "dwmapi.lib")


/* Color-key transparent pixel.  Picked as pure magenta — improbable to be
 * drawn accidentally by ESP elements (which use green/red).                 */
#define ESP_OVERLAY_COLORKEY        RGB(255, 0, 255)
#define ESP_OVERLAY_CLEAR_R         1.0f
#define ESP_OVERLAY_CLEAR_G         0.0f
#define ESP_OVERLAY_CLEAR_B         1.0f

/* Render cadence: target the display refresh rate.
 * With timeBeginPeriod(1) the Sleep(1) wakes up within ~1ms so we spin
 * the remainder with GetTickCount to land on the exact frame boundary.
 * At 144Hz the budget is 6.94ms per frame; at 240Hz it is 4.17ms.
 * We aim for 144Hz (6ms) which gives the smoothest box motion on any
 * high-refresh monitor while keeping CPU usage lower than a busy-loop. */
#define ESP_OVERLAY_FRAME_US    6944  /* 144Hz frame budget in microseconds */

static HWND                      g_espHwnd      = NULL;
static ID2D1Factory*             g_espD2dF      = NULL;
ID2D1HwndRenderTarget*    g_espRT        = NULL;
static HANDLE                    g_espThread    = NULL;
static volatile LONG             g_espRunning   = 0;
static volatile LONG             g_espMaster    = 0; /* 1 = master toggle enabled */
static volatile LONG             g_espDrawBoxes = 0; /* 1 = draw ESP boxes, 0 = aimbot-only */
static volatile LONG             g_espDrawSkeleton = 0; /* 1 = draw TL skeleton dots (DEV) */
static volatile LONG             g_espHideAllies   = 0; /* 1 = skip rendering ally (team==0) boxes */
static volatile LONG             g_espDrawHealth   = 0; /* 0 = off by default, toggle via menu */
static volatile LONG             g_espDrawShield   = 0; /* 0 = off by default, toggle via menu */
static volatile LONG             g_espDrawDistance = 0; /* 0 = off by default, toggle via menu */
static volatile LONG             g_espDrawName     = 0; /* 0 = off by default, toggle via menu */
static int                       g_espScreenW   = 0;
static int                       g_espScreenH   = 0;
static IDWriteFactory*           g_espDWF       = NULL;
static IDWriteTextFormat*        g_espTF        = NULL;
ID2D1SolidColorBrush*     g_espBrushEnemy   = NULL;
ID2D1SolidColorBrush*     g_espBrushAlly    = NULL;
static ID2D1SolidColorBrush*     g_espBrushUnknown = NULL;
static ID2D1SolidColorBrush*     g_espBrushSkeleton = NULL;
ID2D1SolidColorBrush*     g_espBrushFov      = NULL;
static ID2D1BitmapBrush*         g_espBrushBgChecker = NULL;
ID2D1SolidColorBrush*     g_espBrushOutline  = NULL;
static ID2D1SolidColorBrush*     g_espBrushHpBg     = NULL; /* dark bg for health/shield bars */
static ID2D1SolidColorBrush*     g_espBrushHpDynamic = NULL; /* reusable HP brush — color set via SetColor() */
static ID2D1SolidColorBrush*     g_espBrushShDynamic = NULL; /* reusable Shield brush — color set via SetColor() */



/* ESP box snapshot — written by background thread, read by render thread.
 * Protected by a spinlock so render thread never touches game memory. */
static volatile LONG  g_boxSnapLock  = 0;
static EspBox         g_boxSnap[ESP_MAX_BOXES];
static int            g_boxSnapN     = 0;
static void _bsl(void) { while (InterlockedCompareExchange(&g_boxSnapLock, 1, 0)) { YieldProcessor(); } }
static void _bsu(void) { InterlockedExchange(&g_boxSnapLock, 0); }

static DWORD s_lastBoxSnapTick = 0;

/* Called from the background skeleton thread to feed the box snapshot.
 * MUST NOT be called from the render thread. */
extern "C" void EspOverlay_PushBoxSnapshot(const EspBox *boxes, int n)
{
    if (!boxes || n < 0) return;
    if (n > ESP_MAX_BOXES) n = ESP_MAX_BOXES;
    _bsl();
    DWORD nowTick = GetTickCount();
    if (n > 0) {
        g_boxSnapN = n;
        memcpy(g_boxSnap, boxes, (size_t)n * sizeof(EspBox));
        s_lastBoxSnapTick = nowTick;
    } else if (nowTick - s_lastBoxSnapTick > 1000) {
        g_boxSnapN = 0;
    }
    _bsu();
}


static LRESULT CALLBACK EspWndProc(HWND h, UINT m, WPARAM w, LPARAM l)
{
    /* Click-through window — nothing to handle besides destroy. */
    if (m == WM_DESTROY) { PostQuitMessage(0); return 0; }
    if (m == WM_NCHITTEST) { return HTTRANSPARENT; }
    return DefWindowProcW(h, m, w, l);
}

/* Generate a benign-looking random class name so we don't leave an obvious
 * "ESP_OVERLAY" string in the binary / window list. */
static void EspOverlay_RandClass(WCHAR out[32])
{
    UINT64 s = (UINT64)GetTickCount() ^ ((UINT64)GetCurrentThreadId() << 32);
    s ^= 0x9E3779B97F4A7C15ULL;
    for (int i = 0; i < 31; i++) {
        s = s * 6364136223846793005ULL + 1442695040888963407ULL;
        out[i] = L'a' + (WCHAR)((s >> 33) % 26);
    }
    out[31] = 0;
}

static BOOL EspOverlay_InitD2D(void)
{
    if (g_espRT) return TRUE;
    if (FAILED(D2D1CreateFactory(D2D1_FACTORY_TYPE_SINGLE_THREADED, &g_espD2dF))) {
        DEBUG_ESP("EspOverlay: D2D1CreateFactory failed");
        return FALSE;
    }
    if (!g_espDWF) {
        DWriteCreateFactory(DWRITE_FACTORY_TYPE_SHARED,
                            __uuidof(IDWriteFactory),
                            reinterpret_cast<IUnknown**>(&g_espDWF));
        if (g_espDWF)
            g_espDWF->CreateTextFormat(L"Arial", NULL,
                DWRITE_FONT_WEIGHT_BOLD, DWRITE_FONT_STYLE_NORMAL,
                DWRITE_FONT_STRETCH_NORMAL, 12.0f, L"en-us", &g_espTF);
        if (g_espTF) g_espTF->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_CENTER);
    }
    D2D1_RENDER_TARGET_PROPERTIES rtp = D2D1::RenderTargetProperties(
        D2D1_RENDER_TARGET_TYPE_DEFAULT,
        D2D1::PixelFormat(DXGI_FORMAT_B8G8R8A8_UNORM, D2D1_ALPHA_MODE_PREMULTIPLIED)
    );
    D2D1_HWND_RENDER_TARGET_PROPERTIES hrtp = D2D1::HwndRenderTargetProperties(
        g_espHwnd, D2D1::SizeU(g_espScreenW, g_espScreenH),
        D2D1_PRESENT_OPTIONS_IMMEDIATELY  /* Don't block EndDraw waiting for DWM VSync.
         * IMMEDIATELY returns as soon as GPU accepts the work; DWM composites
         * at its own VSync interval regardless. NONE was creating backpressure
         * on the GPU pipeline that competed with the game's render thread. */
    );
    HRESULT hr = g_espD2dF->CreateHwndRenderTarget(&rtp, &hrtp, &g_espRT);
    if (FAILED(hr)) {
        DEBUG_ESP("EspOverlay: CreateHwndRenderTarget hr=0x%08lX", (unsigned long)hr);
        return FALSE;
    }
    /* Premium anti-aliased rendering: since we now use native alpha blending
     * instead of color-key magenta, edges blend smoothly with the game. */
    /* Aliased rendering: prevents edge pixels from blending with the magenta
     * color-key background, which would produce purple/orange tint on boxes. */
    g_espRT->SetAntialiasMode(D2D1_ANTIALIAS_MODE_ALIASED);
    g_espRT->SetTextAntialiasMode(D2D1_TEXT_ANTIALIAS_MODE_ALIASED);
    /* Per-team brushes — device resources tied to this render target. */
    g_espRT->CreateSolidColorBrush(D2D1::ColorF(1.0f,  0.0f,  0.0f,  1.0f), &g_espBrushEnemy);
    g_espRT->CreateSolidColorBrush(D2D1::ColorF(0.0f,  0.45f, 1.0f,  1.0f), &g_espBrushAlly);
    g_espRT->CreateSolidColorBrush(D2D1::ColorF(1.0f,  1.0f,  0.0f,  1.0f), &g_espBrushUnknown);
    g_espRT->CreateSolidColorBrush(D2D1::ColorF(1.0f,  1.0f,  1.0f,  1.0f), &g_espBrushSkeleton);
    g_espRT->CreateSolidColorBrush(D2D1::ColorF(1.0f,  1.0f,  1.0f,  0.85f), &g_espBrushFov);
    g_espRT->CreateSolidColorBrush(D2D1::ColorF(0.0f,  0.0f,  0.0f,  1.0f), &g_espBrushOutline);
    g_espRT->CreateSolidColorBrush(D2D1::ColorF(0.1f,  0.1f,  0.1f,  1.0f), &g_espBrushHpBg);
    /* Reusable dynamic brushes — color is overwritten each frame via SetColor().
     * Eliminates 12-24 Create/Release pairs per frame (HP + Shield per entity). */
    g_espRT->CreateSolidColorBrush(D2D1::ColorF(0.0f, 1.0f, 0.0f, 1.0f), &g_espBrushHpDynamic);
    g_espRT->CreateSolidColorBrush(D2D1::ColorF(0.0f, 0.75f, 1.0f, 1.0f), &g_espBrushShDynamic);

    /* Checkerboard brush for semi-transparent backgrounds without alpha blending */
    ID2D1Bitmap* pBitmap = NULL;
    UINT32 bitmapData[4] = { 0xFFFF00FF, 0xFF000000, 0xFF000000, 0xFFFF00FF };
    D2D1_BITMAP_PROPERTIES props = D2D1::BitmapProperties(D2D1::PixelFormat(DXGI_FORMAT_B8G8R8A8_UNORM, D2D1_ALPHA_MODE_IGNORE));
    if (SUCCEEDED(g_espRT->CreateBitmap(D2D1::SizeU(2, 2), bitmapData, 2 * sizeof(UINT32), &props, &pBitmap))) {
        D2D1_BITMAP_BRUSH_PROPERTIES bprops = D2D1::BitmapBrushProperties(D2D1_EXTEND_MODE_WRAP, D2D1_EXTEND_MODE_WRAP, D2D1_BITMAP_INTERPOLATION_MODE_NEAREST_NEIGHBOR);
        g_espRT->CreateBitmapBrush(pBitmap, &bprops, NULL, &g_espBrushBgChecker);
        pBitmap->Release();
    }

    return TRUE;
}

static void GetLogPath(char *outPath) {
    GetModuleFileNameA(NULL, outPath, MAX_PATH);
    char *p = strrchr(outPath, '\\');
    if (p) *p = '\0';
    lstrcatA(outPath, "\\seraph_overlay.log");
}

static void EspOverlay_Heartbeat(void)
{
#ifndef NDEBUG
    static DWORD s_hbMs = 0;
    DWORD now = GetTickCount();
    if (now - s_hbMs < 2000) return;
    s_hbMs = now;
    char path[MAX_PATH], buf[128];
    GetLogPath(path);
    wsprintfA(buf, "[%lu] overlay alive\r\n", now);
    HANDLE hF = CreateFileA(path, FILE_APPEND_DATA, FILE_SHARE_READ|FILE_SHARE_WRITE,
                            NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hF != INVALID_HANDLE_VALUE) {
        DWORD w; WriteFile(hF, buf, (DWORD)lstrlenA(buf), &w, NULL);
        CloseHandle(hF);
    }
#endif
}

static void EspOverlay_RenderFrame(void)
{
    if (!g_espRT) return;

#ifndef NDEBUG
    EspOverlay_Heartbeat();
#endif

    g_espRT->BeginDraw();
#ifdef SERAPH_DMA_BUILD
    if (SeraphFuser_IsEnabled()) {
        g_espRT->Clear(D2D1::ColorF(0.f, 0.f, 0.f, 1.f));
    } else {
        g_espRT->Clear(D2D1::ColorF(0.0f, 0.0f, 0.0f, 0.0f));
    }
#else
    g_espRT->Clear(D2D1::ColorF(0.0f, 0.0f, 0.0f, 0.0f));
#endif


    Marathon_Tick();
    Marathon_RenderESP((float)g_espScreenW, (float)g_espScreenH);
    g_espRT->EndDraw();
    return;
    /* The render thread must NEVER do game memory reads — only draw. */

    EspBox boxes[ESP_MAX_BOXES];
    int n;
    /* Consume snapshot written by the background ESP update thread.
     * The render thread must NEVER read game memory directly. */
    _bsl();
    n = g_boxSnapN;
    if (n > 0) memcpy(boxes, g_boxSnap, (size_t)n * sizeof(EspBox));
    _bsu();

    /* Aimbot: pass snapshot so it can aim at the real head bone */
    SkelEntity skel[SKEL_ENTITY_MAX];
    int ns = Skeleton_GetCached(skel, SKEL_ENTITY_MAX);
    Aimbot_Tick(boxes, n, g_espScreenW, g_espScreenH, skel, ns);

    /* FOV circle: drawn regardless of entity count */
    if (Aimbot_GetShowFov()) {
        float fovR = Aimbot_GetFovPx();
        float cx   = g_espScreenW * 0.5f;
        float cy   = g_espScreenH * 0.5f;
        if (g_espBrushFov)
            g_espRT->DrawEllipse(D2D1::Ellipse({cx, cy}, fovR, fovR), g_espBrushFov, 1.0f);
    }

    /* ── Box + Skeleton rendering ────────────────────────────────────────── */
    float view[16], proj[16];
    BOOL hasMatrix = Skeleton_GetCachedMatrices(view, proj);

    /* cornered box helper — draws 4 L-shaped corners.
     * Outline uses 1 DrawRectangle (bounding box) instead of 8 DrawLine calls,
     * reducing per-box draw calls from 16 to 9 (1 outline rect + 8 corner lines). */
    auto DrawCornerBox = [&](ID2D1SolidColorBrush *br, float stroke,
                             float l, float t, float r2, float b2) {
        float cw = (r2 - l) * 0.22f;   /* corner segment = 22% of width */
        float ch = (b2 - t) * 0.22f;   /* corner segment = 22% of height */

        /* Top-left */
        g_espRT->DrawLine({l,     t     }, {l+cw,  t     }, br, stroke);
        g_espRT->DrawLine({l,     t     }, {l,     t+ch  }, br, stroke);
        /* Top-right */
        g_espRT->DrawLine({r2,    t     }, {r2-cw, t     }, br, stroke);
        g_espRT->DrawLine({r2,    t     }, {r2,    t+ch  }, br, stroke);
        /* Bottom-left */
        g_espRT->DrawLine({l,     b2    }, {l+cw,  b2    }, br, stroke);
        g_espRT->DrawLine({l,     b2    }, {l,     b2-ch }, br, stroke);
        /* Bottom-right */
        g_espRT->DrawLine({r2,    b2    }, {r2-cw, b2    }, br, stroke);
        g_espRT->DrawLine({r2,    b2    }, {r2,    b2-ch }, br, stroke);
    };

    /* Cache these once — InterlockedCompareExchange is a memory barrier,
     * calling it per-box inside a tight loop is wasteful. */
    BOOL drawMaster  = (InterlockedCompareExchange(&g_espMaster,       0, 0) == 1);
    BOOL drawBoxes   = (InterlockedCompareExchange(&g_espDrawBoxes,    0, 0) == 1);
    BOOL hideAllies  = (InterlockedCompareExchange(&g_espHideAllies,   0, 0) == 1);
    BOOL drawSkel    = (InterlockedCompareExchange(&g_espDrawSkeleton, 0, 0) == 1);
    BOOL drawHealth  = (InterlockedCompareExchange(&g_espDrawHealth,   0, 0) == 1);
    BOOL drawShield  = (InterlockedCompareExchange(&g_espDrawShield,   0, 0) == 1);
    BOOL drawDistance= (InterlockedCompareExchange(&g_espDrawDistance, 0, 0) == 1);
    BOOL drawName    = (InterlockedCompareExchange(&g_espDrawName,     0, 0) == 1);

    /* ── 1. Skeletal Loop (Skeleton Points, Skeletal Boxes, HP/Shield, Name & Distance) ──────────────── */
    if (ns > 0 && hasMatrix && (drawSkel || drawBoxes || drawHealth || drawShield || drawDistance || drawName) && g_espBrushSkeleton) {
        /* Camera world position for distance checks extracted directly from view matrix via -R^T * t. */
        float camX = -(view[0]*view[12] + view[1]*view[13] + view[2]*view[14]);
        float camY = -(view[4]*view[12] + view[5]*view[13] + view[6]*view[14]);
        float camZ = -(view[8]*view[12] + view[9]*view[13] + view[10]*view[14]);




        for (int i = 0; i < ns; i++) {
            const SkelEntity &s = skel[i];
            if (s.isLocalPlayer) continue;
            if (s.team == 0 && hideAllies) continue;

            float edx = s.rootPos[0] - camX;
            float edy = s.rootPos[1] - camY;
            float edz = s.rootPos[2] - camZ;
            float edist = sqrtf(edx*edx + edy*edy + edz*edz);

            /* Pre-project all bones for the current player to draw lines */
            float projX[256];
            float projY[256];
            BOOL  projOk[256];
            int projectedBones = 0;

            if (drawSkel) {
                memset(projOk, 0, sizeof(projOk));
                for (UINT32 j = 0; j < s.boneCount; j++) {
                    if (s.bones[j].x == 0.0f && s.bones[j].y == 0.0f && s.bones[j].z == 0.0f) continue;
                    float sx, sy;
                    if (ESP_WorldToScreen(view, proj, s.bones[j].x, s.bones[j].y, s.bones[j].z, g_espScreenW, g_espScreenH, &sx, &sy)) {
                        projX[j] = sx;
                        projY[j] = sy;
                        projOk[j] = TRUE;
                        projectedBones++;
                    }
                }

                /* Draw skeletal connection lines dynamically using the hierarchy */
                if (projectedBones > 0) {
                    for (UINT32 j = 0; j < s.boneCount; j++) {
                        int p = s.boneParents[j];
                        if (p >= 0 && (UINT32)p < s.boneCount && (UINT32)p != j) {
                            if (projOk[j] && projOk[p]) {
                                g_espRT->DrawLine({projX[j], projY[j]}, {projX[p], projY[p]}, g_espBrushSkeleton, 2.2f);
                            }
                        }
                    }
                }
            }

            if (drawBoxes || drawHealth || drawShield || drawDistance || drawName) {
                float tx = 0.0f, ty = 0.0f, bx = 0.0f, by = 0.0f;
                BOOL topOk = FALSE;
                BOOL botOk = FALSE;

                if (s.boneCount > 18) {
                    topOk = ESP_WorldToScreen(view, proj, s.bones[18].x, s.bones[18].y, s.bones[18].z + 0.45f, g_espScreenW, g_espScreenH, &tx, &ty);
                }
                if (!topOk && s.boneCount > 13) {
                    topOk = ESP_WorldToScreen(view, proj, s.bones[13].x, s.bones[13].y, s.bones[13].z + 0.45f, g_espScreenW, g_espScreenH, &tx, &ty);
                }

                float botX = s.rootPos[0], botY = s.rootPos[1], botZ = s.rootPos[2];
                if (botX == 0.0f && botY == 0.0f && botZ == 0.0f) {
                    botX = s.worldPos[0]; botY = s.worldPos[1]; botZ = s.worldPos[2];
                }
                if (botX != 0.0f || botY != 0.0f || botZ != 0.0f) {
                    botOk = ESP_WorldToScreen(view, proj, botX, botY, botZ, g_espScreenW, g_espScreenH, &bx, &by);
                }

                if (topOk && botOk) {
                    float boxH = fabsf(by - ty);
                    if (boxH > 5.0f) {
                        float cx = (tx + bx) * 0.5f;
                        float w = boxH * 0.44f; /* 2 * 0.22f */
                        float l = cx - w * 0.5f;
                        float r2 = cx + w * 0.5f;
                        float t = (ty < by) ? ty : by;
                        float b2 = (ty > by) ? ty : by;

                        if (drawBoxes) {
                            ID2D1SolidColorBrush *brush = (s.team == 0) ? g_espBrushAlly : g_espBrushEnemy;
                            if (brush) {
                                float stroke = 1.5f;
                                DrawCornerBox(brush, stroke, l, t, r2, b2);
                            }
                        }

                        /* ── Health / Shield bars ─────────────────────────────────────
                         * Renders health (green->yellow->red) and/or shield (blue)
                         * side-by-side to the left of the ESP box if toggles are active. */
                        if (s.health >= 0.0f && (drawHealth || drawShield)) {
                            float hpRaw = s.health < 0.0f ? 0.0f : (s.health > 1.0f ? 1.0f : s.health);
                            float shRaw = s.shield < 0.0f ? 0.0f : (s.shield > 1.0f ? 1.0f : s.shield);

                            float nextR = l - 6.0f; /* 6px gap from left edge of box */

                            /* 1. Health Bar (rightmost of the bars) */
                            if (drawHealth) {
                                float barR = nextR;
                                float barL = barR - 4.0f; /* 4px thick */
                                nextR = barL - 2.0f; /* 2px gap between bars (30% closer) */

                                /* Background: dark opaque charcoal */
                                ID2D1Brush *bgBr = g_espBrushHpBg
                                    ? (ID2D1Brush*)g_espBrushHpBg
                                    : (ID2D1Brush*)g_espBrushOutline;
                                if (bgBr) g_espRT->FillRectangle({barL, t, barR, b2}, bgBr);

                                /* Colour: pure vibrant Green (full) → Yellow (half) → Red (empty) */
                                float r_col, g_col, b_col = 0.0f;
                                if (hpRaw >= 0.5f) {
                                    float k = (hpRaw - 0.5f) * 2.0f;
                                    r_col = 1.0f - k;
                                    g_col = 1.0f;
                                } else {
                                    float k = hpRaw * 2.0f;
                                    r_col = 1.0f;
                                    g_col = k;
                                }

                                if (g_espBrushHpDynamic) {
                                    g_espBrushHpDynamic->SetColor(D2D1::ColorF(r_col, g_col, b_col, 1.0f));
                                    float fillH   = (b2 - t) * hpRaw;
                                    float fillTop = b2 - fillH;
                                    g_espRT->FillRectangle({barL, fillTop, barR, b2}, g_espBrushHpDynamic);
                                }
                            }

                            /* 2. Shield Bar (leftmost of the bars) */
                            if (drawShield) {
                                float barR = nextR;
                                float barL = barR - 4.0f; /* 4px thick */

                                /* Background: dark opaque charcoal */
                                ID2D1Brush *bgBr = g_espBrushHpBg
                                    ? (ID2D1Brush*)g_espBrushHpBg
                                    : (ID2D1Brush*)g_espBrushOutline;
                                if (bgBr) g_espRT->FillRectangle({barL, t, barR, b2}, bgBr);

                                /* Shield bar: reuse g_espBrushShDynamic. */
                                if (g_espBrushShDynamic) {
                                    float fillH   = (b2 - t) * shRaw;
                                    float fillTop = b2 - fillH;
                                    g_espRT->FillRectangle({barL, fillTop, barR, b2}, g_espBrushShDynamic);
                                }
                            }
                        }

                        /* Draw decrypted player name above the box */
                        if (drawName && g_espTF && g_espBrushSkeleton) {
                            WCHAR wname[64] = {0};
                            /* Convert ASCII name to WCHAR */
                            MultiByteToWideChar(CP_UTF8, 0, s.name, -1, wname, 64);
                            if (wname[0] != L'\0') {
                                D2D1_RECT_F tr = { cx - 100.0f, t - 18.0f, cx + 100.0f, t - 3.0f };
                                /* Draw text centered horizontally */
                                g_espTF->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_CENTER);
                                g_espRT->DrawText(wname, (UINT32)lstrlenW(wname), g_espTF, tr, g_espBrushSkeleton);
                                g_espTF->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_LEADING);
                            }
                        }

                        /* Calculate Euclidean distance from camera */
                        if (drawDistance && g_espTF && g_espBrushSkeleton) {
                            float dx = s.rootPos[0] - camX;
                            float dy = s.rootPos[1] - camY;
                            float dz = s.rootPos[2] - camZ;
                            float dist = sqrtf(dx*dx + dy*dy + dz*dz);

                            if (dist > 0.1f) {
                                WCHAR wbuf[16];
                                wsprintfW(wbuf, L"%dm", (int)(dist + 0.5f));
                                D2D1_RECT_F tr = { cx - 30.0f, b2 + 3.0f, cx + 30.0f, b2 + 18.0f };
                                g_espTF->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_CENTER);
                                g_espRT->DrawText(wbuf, (UINT32)lstrlenW(wbuf), g_espTF, tr, g_espBrushSkeleton);
                                g_espTF->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_LEADING);
                            }
                        }
                    }
                }
            }
        }
    }

    /* ── Matchmaking UI ──────────────────────────────────────────────────── */
    if (Overlay_GetMatchmakingActive() && g_espTF && g_espBrushSkeleton) {
        MatchmakingPlayer players[MATCHMAKING_MAX_PLAYERS];
        int pm_count = Matchmaking_GetPlayers(players, MATCHMAKING_MAX_PLAYERS);
        
        float listX = 10.0f;
        float listY = 10.0f;
        float listW = 250.0f;
        int display_count = (pm_count > 0) ? pm_count : 1;
        float listH = 30.0f + (display_count * 18.0f);
        
        // Draw semi-transparent black background using dithered brush
        if (g_espBrushBgChecker) {
            g_espRT->FillRectangle({listX, listY, listX + listW, listY + listH}, g_espBrushBgChecker);
        }
        
        // Draw title
        g_espTF->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_LEADING);
        g_espRT->DrawText(L"Matchmaking List", 16, g_espTF, 
                          {listX + 10.0f, listY + 5.0f, listX + listW, listY + 25.0f}, 
                          g_espBrushSkeleton);
        
        // Draw players or status
        float currY = listY + 25.0f;
        if (pm_count > 0) {
            for (int i = 0; i < pm_count; i++) {
                WCHAR wbuf[150];
                wsprintfW(wbuf, L"[%S] %S", players[i].platform, players[i].name);
                g_espRT->DrawText(wbuf, (UINT32)lstrlenW(wbuf), g_espTF, 
                                  {listX + 10.0f, currY, listX + listW, currY + 18.0f}, 
                                  g_espBrushSkeleton);
                currY += 18.0f;
            }
        } else {
            WCHAR wstatus[128];
            if (!Matchmaking_IsReady()) {
                wsprintfW(wstatus, L"Scanning (AOB failed)...");
            } else {
                UINT64 baseVal = Matchmaking_GetLastDecryptedBase();
                if (baseVal == 0) {
                    wsprintfW(wstatus, L"Scanning (Base 0)...");
                } else {
                    int act = Matchmaking_GetLastActiveEntries();
                    if (act == 0) {
                        wsprintfW(wstatus, L"Scanning (Active: 0)...");
                    } else {
                        wsprintfW(wstatus, L"Scanning (Active: %d, Parsed: 0)...", act);
                    }
                }
            }
            g_espRT->DrawText(wstatus, (UINT32)lstrlenW(wstatus), g_espTF, 
                              {listX + 10.0f, currY, listX + listW, currY + 18.0f}, 
                              g_espBrushSkeleton);
        }
        g_espTF->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_CENTER); // restore
    }

    HRESULT hr = g_espRT->EndDraw();
    if (hr == D2DERR_RECREATE_TARGET) {
        /* RT lost — release brushes (device resources) together with the RT. */
        if (g_espBrushEnemy)     { g_espBrushEnemy->Release();     g_espBrushEnemy     = NULL; }
        if (g_espBrushAlly)      { g_espBrushAlly->Release();      g_espBrushAlly      = NULL; }
        if (g_espBrushUnknown)   { g_espBrushUnknown->Release();   g_espBrushUnknown   = NULL; }
        if (g_espBrushSkeleton)  { g_espBrushSkeleton->Release();  g_espBrushSkeleton  = NULL; }
        if (g_espBrushFov)       { g_espBrushFov->Release();       g_espBrushFov       = NULL; } /* FPS FIX #2 */
        if (g_espBrushBgChecker) { g_espBrushBgChecker->Release(); g_espBrushBgChecker = NULL; }
        if (g_espBrushOutline)   { g_espBrushOutline->Release();   g_espBrushOutline   = NULL; }
        if (g_espBrushHpBg)      { g_espBrushHpBg->Release();      g_espBrushHpBg      = NULL; }
        if (g_espBrushHpDynamic) { g_espBrushHpDynamic->Release(); g_espBrushHpDynamic = NULL; }
        if (g_espBrushShDynamic) { g_espBrushShDynamic->Release(); g_espBrushShDynamic = NULL; }
        g_espRT->Release();
        g_espRT = NULL;
    }
}

static DWORD WINAPI EspOverlay_Thread(LPVOID /*p*/)
{
    /* Cover entire virtual screen so multi-monitor setups work; for typical
     * single-monitor this is just the primary screen size. */
    g_espScreenW = GetSystemMetrics(SM_CXSCREEN);
    g_espScreenH = GetSystemMetrics(SM_CYSCREEN);

    WCHAR cls[32] = L"CEF-OSC-WIDGET";

    WNDCLASSEXW wc = { 0 };
    wc.cbSize        = sizeof(wc);
    wc.style         = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc   = EspWndProc;
    wc.hInstance     = GetModuleHandleW(NULL);
    wc.hCursor       = LoadCursorW(NULL, (LPCWSTR)IDC_ARROW);
    wc.hbrBackground = NULL;
    wc.lpszClassName = cls;
    if (!RegisterClassExW(&wc)) {
        DWORD err = GetLastError();
        if (err != ERROR_CLASS_ALREADY_EXISTS) {
            DEBUG_ESP("EspOverlay: RegisterClassExW failed err=%lu", err);
            return 0;
        }
    }

    /* WS_EX_LAYERED:    enables LWA_COLORKEY transparency.
     * WS_EX_TRANSPARENT: input click-through (mouse goes to game).
     * WS_EX_TOPMOST:    stay above game window.
     * WS_EX_NOACTIVATE: never steal focus.
     * WS_EX_TOOLWINDOW: don't appear in taskbar / Alt-Tab. */
    DWORD ex = WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOPMOST
             | WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW;

    g_espHwnd = CreateWindowExW(
        ex, cls, L"NVIDIA GeForce Overlay", WS_POPUP,
        0, 0, g_espScreenW, g_espScreenH,
        NULL, NULL, wc.hInstance, NULL
    );
    if (!g_espHwnd) {
        DEBUG_ESP("EspOverlay: CreateWindowExW failed err=%lu", GetLastError());
        return 0;
    }

    /* Make window fully transparent via DWM extend frame */
    MARGINS margins = { -1, -1, -1, -1 };
    DwmExtendFrameIntoClientArea(g_espHwnd, &margins);
    
    /* Set LWA_ALPHA to enable layering but keep it opaque (255) so DWM handles transparency.
     * This avoids costly LWA_COLORKEY per-pixel texture readbacks when moving the mouse. */
    SetLayeredWindowAttributes(g_espHwnd, 0, 255, LWA_ALPHA);

    /* Stream-proof affinity is applied via Overlay_SetStreamProofWindow() —
     * respects the global g_streamProof setting. */
    Overlay_SetStreamProofWindow(g_espHwnd, TRUE);

    /* Start hidden initially, will be shown by focus checking */
    ShowWindow(g_espHwnd, SW_HIDE);

    if (!EspOverlay_InitD2D()) {
        DestroyWindow(g_espHwnd);
        g_espHwnd = NULL;
        return 0;
    }

    DEBUG_ESP("EspOverlay: started %dx%d hwnd=%p", g_espScreenW, g_espScreenH, (void*)g_espHwnd);

    /* NOTE: timeBeginPeriod(1) is intentionally NOT called here.
     * The background ESP threads (_EspMatrixThread, _EspPlayerThread) already
     * call timeBeginPeriod(1) for their own Sleep(2) precision. Calling it
     * here too would be redundant but harmless IF this thread slept at 1ms.
     * More importantly: timeBeginPeriod(1) globally raises the OS scheduler
     * interrupt rate from ~64Hz to 1000Hz for the whole process, increasing
     * system CPU usage. We avoid it here since Sleep(16ms) doesn't need it. */

    /* Lower overlay thread priority so the game's render thread always wins
     * CPU/GPU scheduler contention. The overlay is purely cosmetic — a few
     * milliseconds of extra latency on a box draw is imperceptible. */
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);

    /* timeBeginPeriod(1) is managed centrally by ESP_StartUpdateThread.
     * Do NOT call it here — it would add a redundant OS ref-count increment
     * that would be unmatched if this thread exits before ESP_StopUpdateThread. */

    /* DWM composition interval — used to cap GPU presents to monitor refresh.
     * We skip BeginDraw/EndDraw if called faster than DWM can composite,
     * preventing wasted GPU submit calls above the monitor's actual refresh. */
    UINT dwmIntervalMs = 7; /* default 144Hz fallback */
    {
        DWM_TIMING_INFO ti = {};
        ti.cbSize = sizeof(ti);
        if (SUCCEEDED(DwmGetCompositionTimingInfo(NULL, &ti)) && ti.rateRefresh.uiDenominator > 0) {
            /* rateRefresh is a UNSIGNED_RATIO: numerator/denominator = Hz */
            UINT hz = (UINT)(ti.rateRefresh.uiNumerator / ti.rateRefresh.uiDenominator);
            if (hz > 0) dwmIntervalMs = 1000u / hz;
        }
    }
    DWORD s_lastRender = 0;

    BOOL wasVisible = FALSE;

    /* GetForegroundWindow / GetWindowThreadProcessId are Win32k syscalls.
     * Calling them every 4ms (~250Hz) is wasteful — focus changes happen
     * at human speed (<10Hz). Throttle to 33ms (30Hz). */
    DWORD s_lastFgCheck = 0;
    BOOL  shouldShow    = FALSE;

    while (InterlockedCompareExchange(&g_espRunning, 0, 0) == 1) {
        /* Pump messages so the window stays responsive (DWM, etc.). */
        MSG msg;
        while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }

        DWORD nowMs = GetTickCount();

        /* Throttled foreground check: 30Hz is more than enough to catch
         * Alt-Tab and game-focus changes. Was running at ~111Hz before. */
        if ((nowMs - s_lastFgCheck) >= 33u) {
            s_lastFgCheck = nowMs;
            HWND hForeground = GetForegroundWindow();
            DWORD fgPid = 0;
            GetWindowThreadProcessId(hForeground, &fgPid);

            static HWND hGame = NULL;
            static DWORD lastFindMs = 0;
            if (!hGame || !IsWindow(hGame)) {
                hGame = NULL;
                if (nowMs - lastFindMs >= 1000) {
                    lastFindMs = nowMs;
                    WCHAR szD2Title[16];
                    szD2Title[0] = L'M'; szD2Title[1] = L'a'; szD2Title[2] = L'r';
                    szD2Title[3] = L'a'; szD2Title[4] = L't'; szD2Title[5] = L'h';
                    szD2Title[6] = L'o'; szD2Title[7] = L'n'; szD2Title[8] = L'\0';
                    hGame = FindWindowW(NULL, szD2Title);
                }
            }
            shouldShow = (hGame && (hForeground == hGame)) || (fgPid == GetCurrentProcessId());
        }

        int sleepTime = 4;
        if (shouldShow) {
            if (!wasVisible) {
                ShowWindow(g_espHwnd, SW_SHOWNA);
                wasVisible = TRUE;
            }
            if (!g_espRT) EspOverlay_InitD2D();
            
            /* DWM composition throttle: only render if enough time has passed
             * since the last frame (matching the monitor's refresh rate).
             * This prevents GPU submit pile-ups that compete with the game. */
            if ((nowMs - s_lastRender) >= dwmIntervalMs) {
                s_lastRender = nowMs;
                EspOverlay_RenderFrame();
            }
        } else {
            if (wasVisible) {
                ShowWindow(g_espHwnd, SW_HIDE);
                wasVisible = FALSE;
            }
            sleepTime = 100; /* Throttle idle loop to 10Hz when hidden to save CPU */
        }

        /* 4ms = ~200Hz loop. At 144Hz DWM interval (6.94ms) the render
         * check above fires at most every 7ms, but the loop must be faster
         * than that to avoid missing a VSync window. Sleep(9) at 111Hz
         * could skip a 144Hz VSync by 2ms; Sleep(4) never does. */
        Sleep(sleepTime);
    }



    if (g_espBrushEnemy)     { g_espBrushEnemy->Release();     g_espBrushEnemy     = NULL; }
    if (g_espBrushAlly)      { g_espBrushAlly->Release();      g_espBrushAlly      = NULL; }
    if (g_espBrushUnknown)   { g_espBrushUnknown->Release();   g_espBrushUnknown   = NULL; }
    if (g_espBrushSkeleton)  { g_espBrushSkeleton->Release();  g_espBrushSkeleton  = NULL; }
    if (g_espBrushFov)       { g_espBrushFov->Release();       g_espBrushFov       = NULL; }
    if (g_espBrushBgChecker) { g_espBrushBgChecker->Release(); g_espBrushBgChecker = NULL; }
    if (g_espBrushOutline)   { g_espBrushOutline->Release();   g_espBrushOutline   = NULL; }
    if (g_espBrushHpBg)      { g_espBrushHpBg->Release();      g_espBrushHpBg      = NULL; }
    if (g_espBrushHpDynamic) { g_espBrushHpDynamic->Release(); g_espBrushHpDynamic = NULL; }
    if (g_espBrushShDynamic) { g_espBrushShDynamic->Release(); g_espBrushShDynamic = NULL; }
    if (g_espRT)   { g_espRT->Release();   g_espRT   = NULL; }
    if (g_espTF)   { g_espTF->Release();   g_espTF   = NULL; }
    if (g_espDWF)  { g_espDWF->Release();  g_espDWF  = NULL; }
    if (g_espD2dF) { g_espD2dF->Release(); g_espD2dF = NULL; }
    if (g_espHwnd) { DestroyWindow(g_espHwnd); g_espHwnd = NULL; }
    /* timeEndPeriod paired with ESP_StopUpdateThread — do NOT call here. */
    return 0;
}

static BOOL g_espTargetState = FALSE;
static BOOL g_espCurrentState = FALSE;
static HANDLE g_espManagerThread = NULL;

static DWORD WINAPI EspManagerThread(LPVOID param) {
    while (TRUE) {
        if (g_espTargetState && !g_espCurrentState) {
            if (InterlockedCompareExchange(&g_espRunning, 1, 0) == 0) {
                Skeleton_StartUpdateThread();
                ESP_AcquireUpdateThread();
                g_espThread = CreateThread(NULL, 0, EspOverlay_Thread, NULL, 0, NULL);
                if (!g_espThread) InterlockedExchange(&g_espRunning, 0);
            }
            g_espCurrentState = TRUE;
        } else if (!g_espTargetState && g_espCurrentState) {
            InterlockedExchange(&g_espRunning, 0);
            if (g_espThread) {
                WaitForSingleObject(g_espThread, 2000);
                CloseHandle(g_espThread);
                g_espThread = NULL;
            }
            Skeleton_StopUpdateThread();
            ESP_ReleaseUpdateThread();
            g_espCurrentState = FALSE;
        }
        Sleep(30);
    }
    return 0;
}

extern "C" void EspOverlay_Start(void)
{
    g_espTargetState = TRUE;
    if (!g_espManagerThread) g_espManagerThread = CreateThread(NULL, 0, EspManagerThread, NULL, 0, NULL);
}

extern "C" void EspOverlay_SetMaster(BOOL enable)
{
    InterlockedExchange(&g_espMaster, enable ? 1 : 0);
}

extern "C" void EspOverlay_SetDrawBoxes(BOOL draw)
{
    InterlockedExchange(&g_espDrawBoxes, draw ? 1 : 0);
}

extern "C" void EspOverlay_SetDrawSkeleton(BOOL draw)
{
    InterlockedExchange(&g_espDrawSkeleton, draw ? 1 : 0);
}

extern "C" void EspOverlay_SetHideAllies(BOOL hide)
{
    InterlockedExchange(&g_espHideAllies, hide ? 1 : 0);
}

extern "C" void EspOverlay_SetDrawHealth(BOOL draw)
{
    InterlockedExchange(&g_espDrawHealth, draw ? 1 : 0);
}

extern "C" void EspOverlay_SetDrawShield(BOOL draw)
{
    InterlockedExchange(&g_espDrawShield, draw ? 1 : 0);
}

extern "C" void EspOverlay_SetDrawDistance(BOOL draw)
{
    InterlockedExchange(&g_espDrawDistance, draw ? 1 : 0);
}

extern "C" void EspOverlay_SetDrawName(BOOL draw)
{
    InterlockedExchange(&g_espDrawName, draw ? 1 : 0);
}

extern "C" void EspOverlay_Stop(void)
{
    g_espTargetState = FALSE;
    if (!g_espManagerThread) g_espManagerThread = CreateThread(NULL, 0, EspManagerThread, NULL, 0, NULL);
}
