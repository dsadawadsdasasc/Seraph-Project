#pragma once
#define _DEBUG_BUFFER_H_INCLUDED
/*
 * debug_buffer.h — Deferred logging system for Seraph.
 *
 * All log messages are written to an in-memory ring buffer.
 * The buffer is ONLY flushed to disk (.txt) when an error occurs.
 *
 * Normal operation = zero files on disk.
 * Error            = full log history dumped to seraph_crash.txt
 *
 * WriteLogFileEx — per-module log file writer.
 * Appends a message to a named log file immediately (thread-safe).
 * Used by DEBUG_FLY, DEBUG_HOOK, DEBUG_ESP, etc. macros.
 */

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Initialize the in-memory log buffer. Call once at startup. */
void DbgBuf_Init(void);

/* Append a message to the ring buffer (thread-safe). */
void DbgBuf_Write(const char* msg);

/* Flush the entire buffer to disk. Called automatically on error.
   Can also be called manually for debugging. */
void DbgBuf_Flush(const char* filename);

/* Flush + free the buffer. Call at shutdown. */
void DbgBuf_Free(void);

/* Returns TRUE if buffer has been initialized */
BOOL DbgBuf_IsReady(void);

/* Write a message to a per-module log file (appends with newline).
 * Thread-safe. Silently no-op in release builds (NDEBUG).
 * filename: relative or absolute path to log file
 * msg:      null-terminated message string */
void WriteLogFileEx(const char* filename, const char* msg);

/* Write a message to the legacy unified log file.
 * Same as WriteLogFileEx but uses a single default file. */
void WriteLogFile(const char* msg);

#ifdef __cplusplus
}
#endif
