
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

    
    manager->file_sections[0] = malloc(16);  // Adjust size as needed
    if (manager->file_sections[0] == NULL) {
        perror("Error allocating memory for .main section");
        free(manager);
        return NULL;
    }

  
    strcpy(manager->file_sections[0], "\x55\x48\x89\xE5\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90");


    manager->s_hdr[0].sh_offset = 0;
    manager->s_hdr[0].sh_size = 16;  

    manager->e_shnum = 10;

    return manager;
}

// Function to insert dead code (NOP instructions) into the prologue of the main function
void insert_dead_code(Elf_Manager* manager) {
    printf("Inserting dead code into the main function...\n");

    if (manager == NULL || manager->file_sections[0] == NULL) {
        fprintf(stderr, "Error: Null pointer encountered.\n");
        return;
    }

    int i = 0;  
    Elf_Shdr main_section = manager->s_hdr[i];
    uint64_t start = main_section.sh_offset;
    uint64_t end = start + main_section.sh_size;

    //  prologue sequence: push rbp, mov rbp, rsp
    uint8_t prologue[] = {0x55, 0x48, 0x89, 0xE5};

   
    if (end < sizeof(prologue)) {
        fprintf(stderr, "Section size is too small for prologue.\n");
        return;
    }

    // Search for the prologue sequence
    for (uint64_t j = start; j < end - sizeof(prologue); ++j) {
        if (memcmp(manager->file_sections[i] + j, prologue, sizeof(prologue)) == 0) {
            // Insert NOP instructions (0x90) after the prologue
            uint64_t insertion_point = j + sizeof(prologue);
            for (uint64_t k = 0; k < 8; ++k) { // Insert 8 NOPs as an example
                if (insertion_point + k < main_section.sh_size) {
                    manager->file_sections[i][insertion_point + k] = 0x90;
                } else {
                    // Handle if insertion goes beyond section size
                    break;
                }
            }
            break;
        }
    }
}

// Function to free allocated memory
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

    // Inserting dead code
    insert_dead_code(manager);

    // Print modified section
    printf("Modified .main section:\n");
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
