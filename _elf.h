#ifndef ELF_H
#define ELF_H

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define EI_NIDENT	16
#define REMOVE_TYPE	0x01
#define INSERT_TYPE	0x02

struct Elf_obj {
	uint8_t elf_obj_t;
	struct Elf_hdr *elf_hdr;
	struct Elf_shdr_table *elf_shdr_table;
	struct Elf_phdr_table *elf_phdr_table;
	struct Elf_symtab *elf_symtab;
};

struct Elf32_Ehdr {
	uint8_t		e_ident [EI_NIDENT];
	uint16_t	e_type;
	uint16_t	e_machine;
	uint32_t	e_version;
	uint32_t	e_entry;
	uint32_t	e_phoff;
	uint32_t	e_shoff;
	uint32_t	e_flags;
	uint16_t	e_ehsize;
	uint16_t	e_phentsize;
	uint16_t	e_phnum;
	uint16_t	e_shentsize;
	uint16_t	e_shnum;
	uint16_t	e_shstrndx;
};
struct Elf32_Shdr {
	uint32_t	sh_name;
	uint32_t	sh_type;
	uint32_t	sh_flags;
	uint32_t	sh_addr;
	uint32_t	sh_offset;
	uint32_t	sh_size;
	uint32_t	sh_link;
	uint32_t	sh_info;
	uint32_t	sh_addralign;
	uint32_t	sh_entsize;
	uint8_t 	*section;
	uint8_t 	*name;
};
struct Elf32_Phdr {
	uint32_t	p_type;
	uint32_t	p_offset;
	uint32_t	p_vaddr;
	uint32_t	p_paddr;
	uint32_t	p_filesz;
	uint32_t	p_memsz;
	uint32_t	p_flags;
	uint32_t	p_align;
	uint8_t 	*segment;
};
struct Elf32_Symbol {
	uint32_t	st_name;
	uint32_t	st_value;
	uint32_t	st_size;
	uint8_t		st_info;
	uint8_t		st_other;
	uint16_t	st_shndx;
};

struct Elf64_Ehdr {	
	uint8_t		e_ident [EI_NIDENT];
	uint16_t	e_type;
	uint16_t	e_machine;
	uint32_t	e_version;
	uint64_t	e_entry;
	uint64_t	e_phoff;
	uint64_t	e_shoff;
	uint32_t	e_flags;
	uint16_t	e_ehsize;
	uint16_t	e_phentsize;
	uint16_t	e_phnum;
	uint16_t	e_shentsize;
	uint16_t	e_shnum;
	uint16_t	e_shstrndx;
};
struct Elf64_Shdr {
	uint32_t	sh_name;
	uint32_t	sh_type;
	uint64_t	sh_flags;
	uint64_t	sh_addr;
	uint64_t	sh_offset;
	uint64_t	sh_size;
	uint32_t	sh_link;
	uint32_t	sh_info;
	uint64_t	sh_addralign;
	uint64_t	sh_entsize;
	uint8_t 	*section;
	uint8_t 	*name;
};
struct Elf64_Phdr {		/* the p_flags field is in a different position in the 32 bits structure*/
	uint32_t	p_type;
	uint32_t	p_flags;
	uint64_t	p_offset;
	uint64_t	p_vaddr;
	uint64_t	p_paddr;
	uint64_t	p_filesz;
	uint64_t	p_memsz;
	uint64_t	p_align;
	uint8_t 	*segment;
};
struct Elf64_Symbol {
	uint32_t	st_name;
	uint64_t	st_value;
	uint32_t	st_size;
	uint8_t		st_info;
	uint8_t		st_other;
	uint16_t	st_shndx;
};

union Elf_hdrs {
	struct Elf32_Ehdr *elf32_hdr;
	struct Elf64_Ehdr *elf64_hdr;
};
union Elf_shdrs {
	struct Elf32_Shdr **elf32_shdr;
	struct Elf64_Shdr **elf64_shdr;
};
union Elf_phdrs {
	struct Elf32_Phdr **elf32_phdr;
	struct Elf64_Phdr **elf64_phdr;
};
union Elf_symbols {
	struct Elf64_Symbol **elf64_symbols;
	struct Elf32_Symbol **elf32_symbols;
};
struct Elf_hdr {
	uint16_t elf_hdr_t;
	union Elf_hdrs elf_hdr;
};
struct Elf_shdr_table {
	uint16_t elf_shdr_table_t;
	uint16_t e_shnum;
	union Elf_shdrs elf_shdrs;
};
struct Elf_phdr_table {
	uint16_t elf_phdr_table_t;
	uint16_t e_phnum;
	union Elf_phdrs elf_phdrs;
};
struct Elf_symtab {
	uint16_t elf_symtab_t;
	uint32_t sh_info;
	union Elf_symbols elf_symbols;
};

FILE *fopen_elf 		(char *);
struct Elf_obj *get_elf_obj 	(FILE *);
void close_elf_obj 		(FILE *, struct Elf_obj *);
void write_elf_object_file	(FILE *, struct Elf_obj *);

uint8_t *get_elf_shdr_section_by_name	(uint8_t *, const struct Elf_shdr_table *);
uint16_t get_elf_shdr_ndx_by_name 	(uint8_t *, const struct Elf_shdr_table *);
union Elf_shdrs *get_elf_shdr_by_name 	(uint8_t *, const struct Elf_shdr_table *);

void remove_elf_shdr_by_name	(uint8_t *, struct Elf_obj *);
void insert_elf_shdr_by_ndx 	(uint16_t, struct Elf_obj *, union Elf_shdrs *);

void print_elf_hdr 		(const struct Elf_hdr *);
void print_elf_shdr_table 	(const struct Elf_shdr_table *);
void prints_elf_shdr_table 	(const struct Elf_shdr_table *);
void print_elf_phdr_table 	(const struct Elf_phdr_table *);
void print_elf_symbol_table 	(const struct Elf_symtab *);

/*magic*/
#define ELFMAGIC	0x464C457f /*little endian*/

/*e_type*/
#define ET_NONE		0x0000
#define ET_REL		0x0001
#define ET_EXEC		0x0002
#define ET_DYN		0x0003
#define ET_CORE		0x0004
#define ET_LOPROC	0xff00
#define ET_HIPROC	0xffff

/*e_machine*/
#define EM_NONE		0x0000
#define EM_M32		0x0001
#define EM_SPARC	0x0002
#define EM_386		0x0003
#define EM_68K		0x0004
#define EM_88K		0x0005
#define EM_860		0x0007
#define EM_MIPS		0x0008
#define EM_IA_64	0x0032

/*e_class*/
#define ELFCLASSNONE	0x0000
#define ELFCLASS32	0x0001
#define ELFCLASS64	0x0002

/*e_version*/
#define EV_NONE		0x0000
#define EV_CURRENT	0x0001

/*e_data*/
#define ELFDATANONE	0x0000
#define ELFDATA2LSB	0x0001
#define ELFDATA2MSB	0x0002

/*p_type*/
#define PT_NULL		0x00000000
#define PT_LOAD		0x00000001
#define PT_DYNAMIC	0x00000002
#define PT_INTERP	0x00000003
#define PT_NOTE		0x00000004
#define PT_SHLIB	0x00000005
#define PT_PHDR		0x00000006
#define PT_LOPROC	0x00000000
#define PT_HIPROC	0x7fffffff

/*p_flags*/
#define PF_X		0x00000001
#define PF_W		0x00000002
#define PF_R		0x00000004
#define PF_MASKOS	0x0ff00000
#define PF_MASKPROC	0xf0000000

/*sh_flags*/
#define SHF_WRITE	0x00000001
#define SHF_ALLOC	0x00ee0002
#define SHF_EXECINSTR	0x00000004
#define SHF_MASKPROC	0xf0000000 /*all bits included in this mask are reserved for processor-specific semantics*/

/*sh_type*/
#define SHT_NULL	0x00000000
#define SHT_PROGBITS	0x00000001
#define SHT_SYMTAB	0x00000002
#define SHT_STRTAB	0x00000003
#define SHT_RELA	0x00000004
#define SHT_HASH	0x00000005
#define SHT_DYNAMIC	0x00000006
#define SHT_NOTE	0x00000007
#define SHT_NOBITS	0x00000008
#define SHT_REL		0x00000009
#define SHT_SHLIB	0x0000000a
#define SHT_DYNSYM	0x0000000b
#define SHT_LOPROC	0x70000000
#define SHT_HIPROC	0x7fffffff
#define SHT_LOUSER	0x80000000
#define SHT_HIUSER	0xffffffff

#endif
