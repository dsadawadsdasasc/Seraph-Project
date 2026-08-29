/*
 * Resource.h  --  DMA build resource IDs
 *
 * vmm.dll and leechcore.dll are embedded as RCDATA resources and extracted
 * to %TEMP% at startup by dma_dll_loader.h.
 *
 * IDs are chosen far from Loader's 300-302 range to avoid conflicts if
 * the two resource sets ever merge.
 */
#pragma once

#define IDR_VMM_DLL        401   /* vmm.dll       embedded as RCDATA */
#define IDR_LEECHCORE_DLL  402   /* leechcore.dll embedded as RCDATA */
#define IDR_FTD3XX_DLL     403   /* FTD3XX.dll    embedded as RCDATA */

#define IDD_LOGIN_DIALOG   501
#define IDC_KEY_EDIT       502
#define IDC_STATUS_TEXT    503

