#include <windows.h>
#include <stdio.h>

int main() {
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

    printf("File mapped at: %p\n", pMapView);

    char* pData = (char*)pMapView; // Pointer to the start of the file
    IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)pData;
    IMAGE_NT_HEADERS* pNtHeader = (IMAGE_NT_HEADERS*)(pData + pDosHeader->e_lfanew); // e_lfanew offset to NT header
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
    
    for (int i = 0; i < textSizeRawData; i++) {
        if (textRawData[i] == 0x00) {
            printf("Found 0x00 at address: %p\n", textRawData + i);
        }
    }

    UnmapViewOfFile(pMapView);
    CloseHandle(hMapFile);
    CloseHandle(hFile);
    return 0;
}