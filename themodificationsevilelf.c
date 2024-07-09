#include "elf_support.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>

// Function to insert dead code (NOP instructions)
void insert_dead_code(Elf_Manager* manager) {
    printf("Inserting dead code...\n");

    // Loop through sections to find .text section
    for (int i = 0; i < manager->ehdr->e_shnum; ++i) {
        if (strcmp(manager->s_hdr[i].sh_name + manager->file_data, ".text") == 0) {
            // Calculate start and end of .text section
            uint64_t start = manager->s_hdr[i].sh_offset;
            uint64_t end = start + manager->s_hdr[i].sh_size;

            // Insert NOP instructions (0x90 on x86) every 4 bytes
            for (uint64_t j = start; j < end; j += 4) {
                if (j + 4 <= end) {
                    *(uint32_t *)(manager->file_data + j) = 0x90909090; // NOP (x86)
                } else {
                    // Handle cases where section size isn't a multiple of 4 (pad with 0x90)
                    *(uint8_t *)(manager->file_data + j) = 0x90;
                }
            }
        }
    }
}

// Function to modify .strtab section
void modify_strtab_section(Elf_Manager* manager) {
    printf("Modifying .strtab section...\n");
    // Implement your .strtab alteration logic here
    for (int i = 0; i < manager->ehdr->e_shnum; ++i) {
        if (strcmp(manager->s_hdr[i].sh_name + manager->file_data, ".strtab") == 0) {
            for (int j = manager->s_hdr[i].sh_offset; j < manager->s_hdr[i].sh_offset + manager->s_hdr[i].sh_size; ++j) {
                manager->file_data[j]++;
            }
        }
    }
}

// Function to alter ELF header
void alter_elf_header(Elf_Manager* manager) {
    printf("Altering ELF header...\n");
    // Example: Modifying e_flags in ELF header
    manager->ehdr->e_flags = 0xFFFFFFFF;
}
