#include "dma_pe_loader.h"
#include <winnt.h>

struct PEModule {
    BYTE* baseAddress;
    IMAGE_NT_HEADERS64* ntHeaders;
    bool isDll;
};

HMEMORYMODULE DmaLoadPE(const void* peData, size_t peSize) {
    if (!peData || peSize < sizeof(IMAGE_DOS_HEADER)) return nullptr;

    const BYTE* src = static_cast<const BYTE*>(peData);
    auto dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(src);
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;

    if (peSize < dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS64)) return nullptr;
    auto ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS64*>(src + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return nullptr;
    if (ntHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return nullptr;

    // Allocate memory for the entire image
    BYTE* baseAddress = static_cast<BYTE*>(VirtualAlloc(
        nullptr,
        ntHeaders->OptionalHeader.SizeOfImage,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_EXECUTE_READWRITE
    ));
    if (!baseAddress) return nullptr;

    // Copy PE headers
    size_t sizeOfHeaders = ntHeaders->OptionalHeader.SizeOfHeaders;
    if (sizeOfHeaders > peSize) sizeOfHeaders = peSize;
    memcpy(baseAddress, src, sizeOfHeaders);

    // Update NT headers pointer to point to the loaded image
    auto loadedNtHeaders = reinterpret_cast<IMAGE_NT_HEADERS64*>(baseAddress + dosHeader->e_lfanew);

    // Copy sections
    auto sectionHeader = IMAGE_FIRST_SECTION(loadedNtHeaders);
    for (WORD i = 0; i < loadedNtHeaders->FileHeader.NumberOfSections; ++i) {
        if (sectionHeader[i].SizeOfRawData > 0) {
            // Safety boundary checks
            if (sectionHeader[i].PointerToRawData + sectionHeader[i].SizeOfRawData <= peSize &&
                sectionHeader[i].VirtualAddress + sectionHeader[i].SizeOfRawData <= loadedNtHeaders->OptionalHeader.SizeOfImage) {
                BYTE* dest = baseAddress + sectionHeader[i].VirtualAddress;
                const BYTE* srcSec = src + sectionHeader[i].PointerToRawData;
                memcpy(dest, srcSec, sectionHeader[i].SizeOfRawData);
            }
        }
    }

    // Apply Relocations
    ptrdiff_t delta = baseAddress - reinterpret_cast<BYTE*>(loadedNtHeaders->OptionalHeader.ImageBase);
    if (delta != 0) {
        auto relocDir = loadedNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (relocDir.Size > 0) {
            auto relocBlock = reinterpret_cast<IMAGE_BASE_RELOCATION*>(baseAddress + relocDir.VirtualAddress);
            BYTE* relocEnd = reinterpret_cast<BYTE*>(relocBlock) + relocDir.Size;
            while (reinterpret_cast<BYTE*>(relocBlock) < relocEnd && relocBlock->VirtualAddress != 0 && relocBlock->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION)) {
                WORD* relocEntry = reinterpret_cast<WORD*>(reinterpret_cast<BYTE*>(relocBlock) + sizeof(IMAGE_BASE_RELOCATION));
                DWORD numEntries = (relocBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

                for (DWORD i = 0; i < numEntries; ++i) {
                    WORD type = relocEntry[i] >> 12;
                    WORD offset = relocEntry[i] & 0x0FFF;

                    if (type == IMAGE_REL_BASED_DIR64) {
                        ULONGLONG* patchAddress = reinterpret_cast<ULONGLONG*>(baseAddress + relocBlock->VirtualAddress + offset);
                        *patchAddress += delta;
                    } else if (type == IMAGE_REL_BASED_HIGHLOW) {
                        DWORD* patchAddress = reinterpret_cast<DWORD*>(baseAddress + relocBlock->VirtualAddress + offset);
                        *patchAddress += static_cast<DWORD>(delta);
                    }
                }
                relocBlock = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(relocBlock) + relocBlock->SizeOfBlock);
            }
        }
    }

    // Resolve Imports
    auto importDir = loadedNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir.Size > 0) {
        auto importDesc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(baseAddress + importDir.VirtualAddress);
        while (importDesc->Name != 0) {
            const char* dllName = reinterpret_cast<const char*>(baseAddress + importDesc->Name);
            HMODULE hDll = LoadLibraryA(dllName);
            if (!hDll) {
                VirtualFree(baseAddress, 0, MEM_RELEASE);
                return nullptr;
            }

            auto thunkRef = reinterpret_cast<ULONGLONG*>(baseAddress + (importDesc->OriginalFirstThunk ? importDesc->OriginalFirstThunk : importDesc->FirstThunk));
            auto funcRef = reinterpret_cast<ULONGLONG*>(baseAddress + importDesc->FirstThunk);

            while (*thunkRef != 0) {
                FARPROC proc = nullptr;
                if (IMAGE_SNAP_BY_ORDINAL(*thunkRef)) {
                    ULONGLONG ordinal = IMAGE_ORDINAL(*thunkRef);
                    proc = GetProcAddress(hDll, reinterpret_cast<LPCSTR>(ordinal));
                } else {
                    auto importByName = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(baseAddress + *thunkRef);
                    proc = GetProcAddress(hDll, importByName->Name);
                }

                if (!proc) {
                    VirtualFree(baseAddress, 0, MEM_RELEASE);
                    return nullptr;
                }

                *funcRef = reinterpret_cast<ULONGLONG>(proc);
                thunkRef++;
                funcRef++;
            }
            importDesc++;
        }
    }

    // Call TLS Callbacks
    auto tlsDir = loadedNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (tlsDir.Size > 0) {
        auto tls = reinterpret_cast<IMAGE_TLS_DIRECTORY64*>(baseAddress + tlsDir.VirtualAddress);
        if (tls->AddressOfCallBacks != 0) {
            auto callback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(tls->AddressOfCallBacks);
            while (*callback != nullptr) {
                (*callback)(baseAddress, DLL_PROCESS_ATTACH, nullptr);
                callback++;
            }
        }
    }

    // Call DllMain if it is a DLL
    bool isDll = (loadedNtHeaders->FileHeader.Characteristics & IMAGE_FILE_DLL) != 0;
    if (isDll && loadedNtHeaders->OptionalHeader.AddressOfEntryPoint != 0) {
        typedef BOOL(WINAPI* LPFN_DLLMAIN)(HINSTANCE, DWORD, LPVOID);
        auto dllMain = reinterpret_cast<LPFN_DLLMAIN>(baseAddress + loadedNtHeaders->OptionalHeader.AddressOfEntryPoint);
        if (!dllMain(reinterpret_cast<HINSTANCE>(baseAddress), DLL_PROCESS_ATTACH, nullptr)) {
            VirtualFree(baseAddress, 0, MEM_RELEASE);
            return nullptr;
        }
    }

    PEModule* mod = new PEModule();
    mod->baseAddress = baseAddress;
    mod->ntHeaders = loadedNtHeaders;
    mod->isDll = isDll;

    return reinterpret_cast<HMEMORYMODULE>(mod);
}

FARPROC DmaGetPEProcAddress(HMEMORYMODULE module, const char* name) {
    if (!module || !name) return nullptr;
    auto mod = reinterpret_cast<PEModule*>(module);

    auto exportDirEntry = mod->ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDirEntry.Size == 0) return nullptr;

    auto exportDir = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(mod->baseAddress + exportDirEntry.VirtualAddress);
    auto names = reinterpret_cast<DWORD*>(mod->baseAddress + exportDir->AddressOfNames);
    auto functions = reinterpret_cast<DWORD*>(mod->baseAddress + exportDir->AddressOfFunctions);
    auto ordinals = reinterpret_cast<WORD*>(mod->baseAddress + exportDir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exportDir->NumberOfNames; ++i) {
        const char* funcName = reinterpret_cast<const char*>(mod->baseAddress + names[i]);
        if (strcmp(funcName, name) == 0) {
            WORD ordinal = ordinals[i];
            return reinterpret_cast<FARPROC>(mod->baseAddress + functions[ordinal]);
        }
    }
    return nullptr;
}

void DmaFreePE(HMEMORYMODULE module) {
    if (!module) return;
    auto mod = reinterpret_cast<PEModule*>(module);

    // Call TLS Callbacks for DETACH
    auto tlsDir = mod->ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (tlsDir.Size > 0) {
        auto tls = reinterpret_cast<IMAGE_TLS_DIRECTORY64*>(mod->baseAddress + tlsDir.VirtualAddress);
        if (tls->AddressOfCallBacks != 0) {
            auto callback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(tls->AddressOfCallBacks);
            while (*callback != nullptr) {
                (*callback)(mod->baseAddress, DLL_PROCESS_DETACH, nullptr);
                callback++;
            }
        }
    }

    if (mod->isDll && mod->ntHeaders->OptionalHeader.AddressOfEntryPoint != 0) {
        typedef BOOL(WINAPI* LPFN_DLLMAIN)(HINSTANCE, DWORD, LPVOID);
        auto dllMain = reinterpret_cast<LPFN_DLLMAIN>(mod->baseAddress + mod->ntHeaders->OptionalHeader.AddressOfEntryPoint);
        dllMain(reinterpret_cast<HINSTANCE>(mod->baseAddress), DLL_PROCESS_DETACH, nullptr);
    }

    VirtualFree(mod->baseAddress, 0, MEM_RELEASE);
    delete mod;
}
