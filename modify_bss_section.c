#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    uint64_t sh_offset;
    uint64_t sh_size;
} Elf_Shdr;

typedef struct {
    char* file_sections[10];  
    Elf_Shdr s_hdr[10];       
    int e_shnum;             
} Elf_Manager;

Elf_Manager* load_elf_file(const char* file_path) {
    Elf_Manager* manager = malloc(sizeof(Elf_Manager));
    if (manager == NULL) {
        perror("Error allocating memory for Elf_Manager");
        return NULL;
    }

    for (int i = 0; i < 10; ++i) {
        manager->file_sections[i] = NULL;
    }

    manager->file_sections[0] = malloc(16); 
    if (manager->file_sections[0] == NULL) {
        perror("Error allocating memory for .bss section");
        free(manager);
        return NULL;
    }

    manager->s_hdr[0].sh_offset = 0;
    manager->s_hdr[0].sh_size = 16; 

    manager->e_shnum = 10;  

    return manager;
}

// modifyING .bss section
void modify_bss_section(Elf_Manager* manager) {
    printf("Modifying .bss section...\n");

    if (manager == NULL || manager->file_sections[0] == NULL) {
        fprintf(stderr, "Error: Null pointer encountered.\n");
        return;
    }

    int i = 0;  
    Elf_Shdr bss_section = manager->s_hdr[i];
    uint64_t start = bss_section.sh_offset;
    uint64_t end = start + bss_section.sh_size;

    // Modify .bss section by setting all bytes to 0xFF
    for (uint64_t j = start; j < end; ++j) {
        manager->file_sections[i][j] = 0xFF;
    }
}

void free_manager(Elf_Manager* manager) {
    if (manager == NULL) return;

    for (int i = 0; i < 10; ++i) {
        free(manager->file_sections[i]);
    }
    free(manager);
}

int main() {
    Elf_Manager* manager = load_elf_file("dummy_file.elf");
    if (manager == NULL) {
        fprintf(stderr, "Error loading ELF file\n");
        return 1;
    }

    // Print initial state of .bss section
    printf("Before modification:\n");
    for (int i = 0; i < manager->s_hdr[0].sh_size; ++i) {
        printf("%02X ", manager->file_sections[0][i]);
        if ((i + 1) % 8 == 0) {
            printf("\n");
        }
    }
    printf("\n");

    // Modify .bss section
    modify_bss_section(manager);

    // Print modified .bss section
    printf("After modification:\n");
    for (int i = 0; i < manager->s_hdr[0].sh_size; ++i) {
        printf("%02X ", manager->file_sections[0][i]);
        if ((i + 1) % 8 == 0) {
            printf("\n");
        }
    }
    printf("\n");

    // Free allocated memory
    free_manager(manager);

    return 0;
}
