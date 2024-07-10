#include <stdio.h>
#include <stdlib.h>
#include "elf_support.h"
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdbool.h>

Elf_Manager* initialize_manager(int num_phdr, int num_shdr){
    Elf_Manager* manager = (Elf_Manager*) malloc(sizeof(Elf_Manager));
    manager->p_hdr = (Elf_Phdr*) malloc(sizeof(Elf_Phdr)* num_phdr); 
    manager->s_hdr = (Elf_Shdr*) malloc(sizeof(Elf_Shdr)* num_shdr); 
    manager->file_sections = (uint8_t**) malloc(sizeof(uint8_t*) * num_shdr);
    for(int i = 0; i < num_shdr;i++){
        manager->file_sections[i] = (uint8_t*) malloc(0);
    }
    return manager;
}

void free_manager(Elf_Manager* manager){
    for(int i = 0; i < manager->e_hdr.e_shnum; i++){
        free(manager->file_sections[i]);
    }
    free(manager->file_sections);
    free(manager->p_hdr);
    free(manager->s_hdr);
    free(manager);
}

void load_elf_file_sections(Elf_Manager* manager){
    FILE* fp = fopen(manager->file_path, "r+b"); 
    for(int i = 0; i < manager->e_hdr.e_shnum; i++){
        Elf_Off offset = manager->s_hdr[i].sh_offset;
        fseek(fp, offset, SEEK_SET);
        uint8_t* ptr = (uint8_t*) realloc(manager->file_sections[i], manager->s_hdr[i].sh_size);
        if (manager->s_hdr[i].sh_size == 0 && ptr == NULL && errno == ENOMEM){
            printf("Realloc failed because section %d is too large \n", i); // Could write to file instead to prevent this
            fclose(fp);
            return;
        }
        manager->file_sections[i] = ptr;
        fread(manager->file_sections[i], manager->s_hdr[i].sh_size, 1, fp);
    }
    fclose(fp);
}

void print_elf_header_table_overview(Elf_Manager* manager){
    Elf_Ehdr hdr = manager->e_hdr;
    printf("Number of program headers: %d\nNumber of section headers: %d\n", hdr.e_phnum, hdr.e_shnum);
    printf("Program Header Offset: %#lx, size %#x\n", hdr.e_phoff, hdr.e_phentsize * hdr.e_phnum);
    printf("Section Header Offset: %#lx, size %#x\n", hdr.e_shoff, hdr.e_shentsize * hdr.e_shnum);
}

Elf_Manager* load_elf_file(char* file_path){
    FILE* fp = fopen(file_path, "r+b");
    if(fp == NULL){
        printf("failed to load (likely invalid file path)\n");
        exit(1);
    }

    Elf_Ehdr hdr;
    if (1 != fread(&hdr, sizeof(hdr), 1, fp)){
        printf("failed to read elf header\n");
        exit(1);
    }

    Elf_Manager* manager = initialize_manager(hdr.e_phnum, hdr.e_shnum);
    strncpy(manager->file_path, file_path, 4095);
    manager->file_path[4095] = '\0';
    memcpy(&(manager->e_hdr), &hdr, sizeof(Elf_Ehdr));

    fseek(fp, hdr.e_phoff, SEEK_SET);
    
    for(int i = 0; i < hdr.e_phnum; i++){
        if (1 != fread(&(manager->p_hdr[i]), sizeof(Elf_Phdr), 1, fp)){
            printf("failed to read program header\n");
            exit(1);
        }
    }

    fseek(fp, hdr.e_shoff, SEEK_SET);

    for(int i = 0; i < hdr.e_shnum; i++){
        if (1 != fread(&(manager->s_hdr[i]), sizeof(Elf_Shdr), 1, fp)){
            printf("failed to read section header\n");
            exit(1);
        }
    }

    fclose(fp);

    load_elf_file_sections(manager);

    return manager;
}

int get_file_name_size_from_path(char* file_path){
    int length = strlen(file_path);
    for(int i = length - 1; i > 0; i--){
        if(file_path[i] == '/' || file_path[i] == '\\'){
            return length - i - 1;
        }
    }
    return length;
}

void print_elf_program_header(Elf_Manager* manager, int index){
    Elf_Phdr phdr = manager->p_hdr[index];

    char buffer[1024];
    printf("Program Index %d\n", index);
    get_program_type(buffer, phdr.p_type);
    printf("p_type: %d %s\n", phdr.p_type, buffer);
    printf("p_offset: %#lx\n", phdr.p_offset);
    printf("p_vaddr: %#lx\n", phdr.p_vaddr);
    printf("p_paddr: %#lx\n", phdr.p_paddr);
    printf("p_filesz: %#lx\n", phdr.p_filesz);
    printf("p_memsz: %#lx\n", phdr.p_memsz);
    get_program_flags(buffer, phdr.p_flags);
    printf("p_flags: %x %s\n", phdr.p_flags, buffer);
    printf("p_align: %#lx\n\n", phdr.p_align);
}

void print_all_elf_program_header(Elf_Manager* manager){
    for(int i = 0; i < manager->e_hdr.e_phnum; i++){
        print_elf_program_header(manager, i);
    }
}

void print_elf_section_header(Elf_Manager* manager, int index){
    FILE* fp = fopen(manager->file_path, "r+b");
    Elf_Shdr shdr = manager->s_hdr[index];
    Elf_Off string_table_offset = manager->s_hdr[manager->e_hdr.e_shstrndx].sh_offset;
    fseek(fp, string_table_offset + shdr.sh_name, SEEK_SET);

    char buffer[1024];
    fgets(buffer, 1024, fp);
    printf("Section Index %d\n", index);
    printf("sh_name: (offset) %d (entry in string table) %s\n", shdr.sh_name, buffer);
    get_section_type(buffer, shdr.sh_type);
    printf("sh_type: %d %s\n", shdr.sh_type, buffer);
    get_section_flags(buffer, shdr.sh_type);
    printf("sh_flags: %#lx %s\n", shdr.sh_flags, buffer);
    printf("sh_addr: %#lx\n", shdr.sh_addr);
    printf("sh_off: %#lx\n", shdr.sh_offset);
    printf("sh_size: %#lx\n", shdr.sh_size);
    printf("sh_link: %#x\n", shdr.sh_link);
    printf("sh_info: %#x\n", shdr.sh_info);
    printf("sh_addralign: %#lx\n", shdr.sh_addralign);
    printf("sh_entsize: %#lx\n\n", shdr.sh_entsize);

    fclose(fp);
}

void print_all_elf_section_header(Elf_Manager* manager){
    for(int i = 0; i < manager->e_hdr.e_shnum; i++){
        print_elf_section_header(manager, i);
    }
}

void get_program_type(char* string, Elf_Word value){
    switch (value) {
        case 0: strcpy(string, "PT_NULL"); break;
        case 1: strcpy(string, "PT_LOAD"); break;
        case 2: strcpy(string, "PT_DYNAMIC"); break;
        case 3: strcpy(string, "PT_INTERP"); break;
        case 4: strcpy(string, "PT_NOTE"); break;
        case 5: strcpy(string, "PT_SHLIB"); break;
        case 6: strcpy(string, "PT_PHDR"); break;
        case 0x70000000: strcpy(string, "PT_LOPROC"); break;
        case 0x7fffffff: strcpy(string, "PT_HIPROC"); break;
        default: strcpy(string, "UNKNOWN"); break;
    }
}

void get_program_flags(char* string, Elf_Word value){
    string[0] = '\0';
    if ((value & 0x1) != 0) strcat(string, "PF_X,");
    if ((value & 0x2) != 0) strcat(string, "PF_W,");
    if ((value & 0x4) != 0) strcat(string, "PF_R,");
    if ((value & 0xf0000000) != 0) strcat(string, "PF_MASKPROC,");
    return;
}

void get_section_flags(char* string, Elf_Word value){
    string[0] = '\0';
    if ((value & 0x1) != 0) strcat(string, "SHF_WRITE,");
    if ((value & 0x2) != 0) strcat(string, "SHF_ALLOC,");
    if ((value & 0x4) != 0) strcat(string, "SHF_EXECINSTR,");
    if ((value & 0xf0000000) != 0) strcat(string, "SHF_MASKPROC,");
    return;
}

void get_section_type(char* string, Elf_Word value){
    switch (value) {
        case 0: strcpy(string, "SHT_NULL"); break;
        case 1: strcpy(string, "SHT_PROGBITS"); break;
        case 2: strcpy(string, "SHT_SYMTAB"); break;
        case 3: strcpy(string, "SHT_STRTAB"); break;
        case 4: strcpy(string, "SHT_RELA"); break;
        case 5: strcpy(string, "SHT_HASH"); break;
        case 6: strcpy(string, "SHT_DYNAMIC"); break;
        case 7: strcpy(string, "SHT_NOTE"); break;
        case 8: strcpy(string, "SHT_NOBITS"); break;
        case 9: strcpy(string, "SHT_REL"); break;
        case 10: strcpy(string, "SHT_SHLIB"); break;
        case 11: strcpy(string, "SHT_DYNSYM"); break;
        case 14: strcpy(string, "SHT_INIT_ARRAY"); break;
        case 15: strcpy(string, "SHT_FINI_ARRAY"); break;
        case 16: strcpy(string, "SHT_PREINIT_ARRAY"); break;
        case 17: strcpy(string, "SHT_GROUP"); break;
        case 18: strcpy(string, "SHT_SYMTAB_SHNDX"); break;
        case 19: strcpy(string, "SHT_NUM"); break;
        case 0x60000000: strcpy(string, "SHT_LOPROC"); break;
        case 0x6fffffff: strcpy(string, "SHT_HIPROC"); break;
        case 0x70000000: strcpy(string, "SHT_LOUSER"); break;
        case 0x7fffffff: strcpy(string, "SHT_HIUSER"); break;
        default: strcpy(string, "UNKNOWN"); break;
    }
}

// New function implementations for manipulate_sections.c

void insert_dead_code(Elf_Manager* manager) {
    // Implementation for insert_dead_code
    // Example: This function could add dead code to the ELF sections
}

void modify_strtab_section(Elf_Manager* manager) {
    // Implementation for modify_strtab_section
    // Example: This function could modify the string table section of the ELF
}

void modify_bss_section(Elf_Manager* manager) {
    // Implementation for modify_bss_section
    // Example: This function could modify the BSS section of the ELF
}
