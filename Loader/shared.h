#pragma once
/* shared.h — shared between driver.c and loader.c */

#define NONCE_SIZE      32
#define GCM_TAG_SIZE    16
#define GCM_IV_SIZE     12
#define KEY_SIZE        32
#define FIRMWARE_RESERVED 7

/* Encrypted message max: IV + SPFN_MESSAGE + TAG */
#define SPFN_MSG_PLAIN  (4 + 8*8 + 1024 + 4)   /* sizeof(SPFN_MESSAGE) */
#define SPFN_MSG_ENC    (GCM_IV_SIZE + SPFN_MSG_PLAIN + GCM_TAG_SIZE + 16)

/* Shared memory state machine */
#define SHM_MAGIC       0x43565348UL  /* generic */
#define SHM_STATE_IDLE  0
#define SHM_STATE_REQ   1
#define SHM_STATE_RSP   2

/* Registry value names written by driver, read by loader */
#define REG_VAL_KEY     "KeyMaterial"
#define REG_VAL_SHM     L"ShmName"
#define REG_VAL_U2K     L"EvtU2K"
#define REG_VAL_K2U     L"EvtK2U"

/*
   Shared memory layout (named section, Global\ namespace, random name).
   Both driver and loader map this section.
   All field accesses serialize through state + seq_* counters.
   Message data is always AES-GCM encrypted (except handshake nonces).
*/
typedef struct _SVC_SHM {
    volatile long magic;       /* SHM_MAGIC sanity check               */
    volatile long state;       /* SHM_STATE_*                           */
    volatile long seq_req;     /* client increments before each request */
    volatile long seq_rsp;     /* driver increments before each response*/
    unsigned long req_size;    /* byte length of req_data payload       */
    unsigned long rsp_size;    /* byte length of rsp_data payload       */
    unsigned char req_data[SPFN_MSG_ENC]; /* [IV][cipher][tag]          */
    unsigned char rsp_data[SPFN_MSG_ENC]; /* [IV][cipher][tag]          */
} SVC_SHM;

typedef enum _SPFN_COMMAND {
    SPFN_CMD_READ_MEMORY     = 0x2000,
    SPFN_CMD_WRITE_MEMORY    = 0x2001,
    SPFN_CMD_GET_MODULE_BASE = 0x2002,
    SPFN_CMD_HIDE_PROCESS    = 0x2003,
} SPFN_COMMAND;

typedef struct _SPFN_MESSAGE {
    SPFN_COMMAND  command;
    unsigned long long parameters[8];
    unsigned char data[1024];
    unsigned long data_size;
} SPFN_MESSAGE;

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS                  ((long)0x00000000L)
#endif
#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH     ((long)0xC0000004L)
#endif

typedef struct _EVASION_CONTEXT {
    unsigned long delay_ms;
    unsigned long msg_size;
    int is_vm;
    int is_sandbox;
    int is_debugged;
} EVASION_CONTEXT, *PEVASION_CONTEXT;

#ifndef _KERNEL_MODE
typedef struct _LOADER_CTX {
    void*  hAlgHash;   /* BCRYPT_ALG_HANDLE */
    void*  hAlgAes;    /* BCRYPT_ALG_HANDLE */
    unsigned char session_key[KEY_SIZE];
    EVASION_CONTEXT evasion_ctx;
} LOADER_CTX;
#endif
