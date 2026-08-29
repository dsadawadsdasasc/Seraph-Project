#include "Overlay.h"
#include "Loader.h"
#include "gui_core.h"
static HWND g_hWnd=NULL;
static bool g_menuVisible=false;
LRESULT WINAPI WndProc(HWND hWnd,UINT msg,WPARAM wParam,LPARAM lParam){
    switch(msg){
        case WM_MOUSEMOVE:
            DX12Overlay::UpdateMouse(LOWORD(lParam),HIWORD(lParam),!!(GetKeyState(VK_LBUTTON)&0x8000));
            break;
        case WM_LBUTTONDOWN:
            DX12Overlay::UpdateMouse(LOWORD(lParam),HIWORD(lParam),true);
            /* Ensure overlay window has keyboard focus so text input (TP name, config name) works */
            SetFocus(hWnd);
            break;
        case WM_LBUTTONUP:
            DX12Overlay::UpdateMouse(LOWORD(lParam),HIWORD(lParam),false);
            break;
        case WM_KEYDOWN:
            if(Overlay_IsTextInputFocused()){
                if((int)wParam==VK_ESCAPE||(int)wParam==VK_RETURN){Overlay_TextInputDefocus();return 0;}
                if((int)wParam==VK_BACK){Overlay_TextInputBackspace();return 0;}
                return 0;
            }
            return DefWindowProc(hWnd,msg,wParam,lParam);
        case WM_CHAR:
            if(Overlay_IsTextInputFocused()){
                wchar_t c=(wchar_t)wParam;
                if(c!=L'\b'&&c!=L'\r'&&c!=L'\t')Overlay_TextInputChar(c);
                return 0;
            }
            return DefWindowProc(hWnd,msg,wParam,lParam);
        case WM_DESTROY:
            PostQuitMessage(0);
            break;
        default:
            return DefWindowProc(hWnd,msg,wParam,lParam);
    }
    return 0;
}
extern "C" void ToggleMenu(){g_menuVisible=!g_menuVisible;DX12Overlay::SetMenuVisible(g_menuVisible);}
extern "C" void __cdecl Overlay_SetMenuVisible(BOOL v){g_menuVisible=!!v;DX12Overlay::SetMenuVisible(g_menuVisible);}
extern "C" BOOL IsMenuVisible(){return g_menuVisible;}
