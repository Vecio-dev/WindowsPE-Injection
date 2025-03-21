#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <binary file>\n", argv[0]);
        return 1;
    }

    FILE *fp = fopen(argv[1], "rb");
    if (!fp) {
        fprintf(stderr, "Failed to open %s\n", argv[1]);
        return 1;
    }

    // Determine the size of the file
    fseek(fp, 0, SEEK_END);
    long fileSize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    // Allocate a buffer to read the file
    unsigned char *buffer = (unsigned char*)malloc(fileSize);
    if (!buffer) {
        fprintf(stderr, "Failed to allocate memory.\n");
        fclose(fp);
        return 1;
    }

    // Read the entire file
    fread(buffer, 1, fileSize, fp);
    fclose(fp);

    // Print as a C array
    printf("unsigned char shellcode[] = {\n");
    for (long i = 0; i < fileSize; i++) {
        printf("0x%02X", buffer[i]);
        if (i < fileSize - 1) {
            printf(",");
        }
        // Optional: line-break every 16 bytes
        if ((i + 1) % 16 == 0) {
            printf("\n");
        }
    }
    printf("\n};\n\n");

    // Optionally print the size
    printf("unsigned int shellcode_len = %ld;\n", fileSize);

    free(buffer);
    return 0;
}