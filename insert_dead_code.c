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

Elf_Manager* load_elf_file() {
    Elf_Manager* manager = malloc(sizeof(Elf_Manager));
    if (manager == NULL) {
        perror("Error allocating memory for Elf_Manager");
        return NULL;
    }

    for (int i = 0; i < 10; ++i) {
        manager->file_sections[i] = NULL;
    }

    manager->e_shnum = 10;

    return manager;
}

void insert_dead_code(Elf_Manager* manager, int section_index) {
    printf("Inserting dead code into section %d...\n", section_index);

    if (manager == NULL || manager->file_sections[section_index] == NULL) {
        fprintf(stderr, "Error: Null pointer encountered.\n");
        return;
    }

    uint64_t start = manager->s_hdr[section_index].sh_offset;
    uint64_t end = start + manager->s_hdr[section_index].sh_size;

    uint8_t prologue[] = {0x55, 0x48, 0x89, 0xE5};

    if (manager->s_hdr[section_index].sh_size < sizeof(prologue)) {
        fprintf(stderr, "Section size is too small for prologue.\n");
        return;
    }

    for (uint64_t j = start; j < end - sizeof(prologue); ++j) {
        if (memcmp(manager->file_sections[section_index] + j, prologue, sizeof(prologue)) == 0) {
            uint64_t insertion_point = j + sizeof(prologue);
            for (uint64_t k = 0; k < 16; ++k) {
                if (insertion_point + k < manager->s_hdr[section_index].sh_size) {
                    manager->file_sections[section_index][insertion_point + k] = 0x90;
                } else {
                    break;
                }
            }
            break;
        }
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
    Elf_Manager* manager = load_elf_file();
    if (manager == NULL) {
        fprintf(stderr, "Error loading ELF file\n");
        return 1;
    }

    // Example section index
    int section_index = 0;

    // Allocate memory for a section
    manager->file_sections[section_index] = malloc(64);
    if (manager->file_sections[section_index] == NULL) {
        perror("Error allocating memory for section");
        free_manager(manager);
        return 1;
    }

   
    manager->s_hdr[section_index].sh_offset = 0;
    manager->s_hdr[section_index].sh_size = 64;
    memset(manager->file_sections[section_index], 0x48, 64); // Fill with 0x48 (dummy data)

    // Insert dead code
    insert_dead_code(manager, section_index);

    // Print modified section
    printf("Modified section %d:\n", section_index);
    for (int i = 0; i < manager->s_hdr[section_index].sh_size; ++i) {
        printf("%02X ", manager->file_sections[section_index][i]);
        if ((i + 1) % 8 == 0) {
            printf("\n");
        }
    }
    printf("\n");

    // Free allocated memory
    free_manager(manager);

    return 0;
}
