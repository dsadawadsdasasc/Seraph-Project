# Tasks

- [x] Analyze the provided logs and identify Direct2D EndDraw failure (hr=0x88990016 D2DERR_PUSH_POP_UNMATCHED)
- [x] **#14** Corrigida a aba de Matchmaking List: agora a inicialização/parada do overlay Direct2D considera a aba de Matchmaking ativa através da função `IsEspOverlayNeeded()`.
- [x] **#15** Adicionado o log detalhado de `camBase`, `pitch` e `yaw`, juntamente com um dump em floats de 512 bytes (128 floats) da região da câmera na versão Debug, facilitando a extração do offset NaN pelo usuário.
- [x] Identify brace mismatch at the end of the element rendering loop in `gui_core.cpp`
- [x] Fix the braces and place `POP_CLIP()` inside the correct loop scope
- [x] Compile Debug build (`b_debug.bat`)
- [x] Compile release build and verify compile succeeds
- [x] Change `L"waiting for game..."` to `L"Waiting for game..."` in `tbh_loader.cpp`
- [x] Add `TBH_Features_Cleanup` declaration to `tbh_features.h`
- [x] Implement reopening process handle in `TBH_SetProcess` in `tbh_features.c`
- [x] Implement `TBH_Features_Cleanup` in `tbh_features.c`
- [x] Call `TBH_Features_Cleanup` on menu exit in `tbh_loader.cpp`
- [x] Update `ResolveItemAdd` in `TBH_Hook/dllmain.cpp` to look up `ue` class name
- [x] Compile hook DLL and copy/integrate
- [x] Compile debug and release builds of the trainer and verify both builds succeed
