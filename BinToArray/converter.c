#include "converter.h"
#include <stdio.h>
#include <stdlib.h>

unsigned char* convert_bin_to_array(const char *filename, size_t *size) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        fprintf(stderr, "Failed to open %s\n", filename);
        return NULL;
    }
    
    // Determine the size of the file
    fseek(fp, 0, SEEK_END);
    long fileSize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    // Allocate a buffer to hold the file contents
    unsigned char *buffer = (unsigned char*)malloc(fileSize);
    if (!buffer) {
        fprintf(stderr, "Failed to allocate memory.\n");
        fclose(fp);
        return NULL;
    }
    
    // Read the entire file into the buffer
    fread(buffer, 1, fileSize, fp);
    fclose(fp);
    
    if (size) {
        *size = (size_t)fileSize;
    }
    
    return buffer;
}
