#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <signal.h>
#include <syscall.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>

#include "elf64.h"

#define	ET_NONE	0	//No file type 
#define	ET_REL	1	//Relocatable file 
#define	ET_EXEC	2	//Executable file 
#define	ET_DYN	3	//Shared object file 
#define	ET_CORE	4	//Core file 


/* symbol_name		- The symbol (maybe function) we need to search for.
 * exe_file_name	- The file where we search the symbol in.
 * error_val		- If  1: A global symbol was found, and defined in the given executable.
 * 			- If -1: Symbol not found.
 *			- If -2: Only a local symbol was found.
 * 			- If -3: File is not an executable.
 * 			- If -4: The symbol was found, it is global, but it is not defined in the executable.
 * return value		- The address which the symbol_name will be loaded to, if the symbol was found and is global.
 */

unsigned long find_symbol(char* symbol_name, char* exe_file_name, int* error_val) {

    FILE* file = fopen(exe_file_name, "r");
    if (file == NULL) {
        *error_val = -3;
        return 0;
    }

    Elf64_Ehdr header;
    fread(&header, sizeof(header), 1, file);
    if(header.e_type != ET_EXEC) {
        *error_val = -3;
        return 0;
    }

    bool Global = false;
    bool Local = false;
    bool In_Exe = false;
    bool Found = false;
    long sym_addr = 0;

    fseek(file,header.e_shoff,SEEK_SET);
    Elf64_Shdr *section_header = (Elf64_Shdr*)malloc(sizeof(Elf64_Shdr)*  header.e_shnum);
    fread(section_header, sizeof(Elf64_Shdr), header.e_shnum, file);

    int sym_ndx = -1;
    int string_ndx = -1;
    Elf64_Half j;
    for( j = 0; j < header.e_shnum; j++) {
        if(section_header[j].sh_type == 2) {
            sym_ndx = j;
            break;
        }
    }

    if (sym_ndx == -1) {
        *error_val = -3;
        fclose(file);
        free(section_header);
        return 0;
    }

    for( j = 0; j < header.e_shnum; j++) {
        if(section_header[j].sh_type == 3) {
            string_ndx = j;
            break;
        }
    }



    int symbol_len = strlen(symbol_name) + 1;

    Elf64_Sym * sym_table = (Elf64_Sym*)malloc(sizeof(Elf64_Sym) * (section_header[sym_ndx].sh_size/section_header[sym_ndx].sh_entsize));
    fseek(file, section_header[sym_ndx].sh_offset, SEEK_SET);
    fread(sym_table, sizeof(Elf64_Sym), (section_header[sym_ndx].sh_size/section_header[sym_ndx].sh_entsize), file);


    Elf64_Xword i;
    Elf64_Xword index_of_our_symbol = -1;

    for( i = 0; i < (section_header[sym_ndx].sh_size/section_header[sym_ndx].sh_entsize); i++){
        fseek(file, section_header[section_header[sym_ndx].sh_link].sh_offset + sym_table[i].st_name, SEEK_SET);
        char* symbol_to_compare = (char *)malloc(sizeof(char ) * symbol_len);
        fread(symbol_to_compare, sizeof(char), symbol_len ,file);
        if(strcmp(symbol_to_compare, symbol_name) == 0) {
            index_of_our_symbol = i;
        }

        free(symbol_to_compare);
    }

    if(index_of_our_symbol != -1) {
        Found = true;
        if (ELF64_ST_BIND(sym_table[index_of_our_symbol].st_info) == 0) {
            Local = true;
        } else {
            Global = true;
            if (sym_table[index_of_our_symbol].st_shndx != SHN_UNDEF) {
                sym_addr = sym_table[index_of_our_symbol].st_value;
                In_Exe = true;
            }
        }
    }



    free(section_header);
    free(sym_table);
    fclose(file);


    if(Local && !Global && Found){
        *error_val = -2;
    }
    if(Global && In_Exe && Found){
        *error_val = 1;
        return sym_addr;
    }
    if(Global && !In_Exe && Found){
        *error_val = -4;
    }
    if (!Found){
        *error_val = -1;
    }

    return 0;
}


int main(int argc, char *const argv[]) {
	int err = 0;
	unsigned long addr = find_symbol(argv[1], argv[2], &err);

	if (addr > 0)
		printf("%s will be loaded to 0x%lx\n", argv[1], addr);
	else if (err == -2)
		printf("%s is not a global symbol! :(\n", argv[1]);
	else if (err == -1)
		printf("%s not found!\n", argv[1]);
	else if (err == -3)
		printf("%s not an executable! :(\n", argv[2]);
	else if (err == -4)
		printf("%s is a global symbol, but will come from a shared library\n", argv[1]);
	return 0;
}