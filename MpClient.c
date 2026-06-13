// Ejemplo conceptual de validación segura basada en descriptor de archivo (Handle)
HANDLE hFile = CreateFileW(
    L"C:\\Users\\Public\\FunnyTemp\\archivo.dat",
    GENERIC_READ,
    FILE_SHARE_READ,
    NULL,
    OPEN_EXISTING,
    FILE_FLAG_OPEN_REPARSE_POINT, // Abre el enlace, no el destino
    NULL
);

if (hFile != INVALID_HANDLE_VALUE) {
    // 1. Verificar si el archivo es en realidad un Reparse Point (Junction/Link)
    BY_HANDLE_FILE_INFORMATION fileInfo;
    if (GetFileInformationByHandle(hFile, &fileInfo)) {
        if (fileInfo.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
            // El entorno fue modificado concurrentemente. Abortar operación.
            CloseHandle(hFile);
            return ERROR_ACCESS_DENIED;
        }
    }
    
    // 2. Proceder con la lectura/escritura de forma segura a través de hFile
    // Nadie puede cambiar el destino de hFile una vez que el objeto está abierto en el Kernel
    CloseHandle(hFile);
}
