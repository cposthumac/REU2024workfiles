

void write_elf_file(Elf_Manager* manager, const char* filename) {
    FILE* fp = fopen(filename, "wb");
    if (!fp) {
        perror("Error opening file for writing");
        return;
    }

    // Write ELF header
    fwrite(manager->ehdr, sizeof(Elf_Ehdr), 1, fp);

    // Write program headers (if applicable)
    fwrite(manager->p_hdr, sizeof(Elf_Phdr), manager->ehdr->e_phnum, fp);

    // Write section headers
    fwrite(manager->s_hdr, sizeof(Elf_Shdr), manager->ehdr->e_shnum, fp);

    // Write section data
    for (int i = 0; i < manager->ehdr->e_shnum; ++i) {
        fwrite(manager->sections[i], 1, manager->s_hdr[i].sh_size, fp);
    }

    // Call modifications
    insert_dead_code(manager);
    alter_elf_header(manager);
    modify_strtab_section(manager);

    fclose(fp);
}
