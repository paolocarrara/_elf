#include "_elf.h"

static inline uint8_t verify_elf_file	(FILE *);

static inline uint8_t verify_elf_file (FILE *fp) 
{
	uint32_t magic;

	fread (&magic, 1, 4, fp);
	rewind (fp);
	
	if (magic == ELFMAGIC)
		return 1;
	else 
		return 0;
}
FILE *fopen_elf (char *file_name) 
{
	FILE *fp = fopen (file_name, "rb+");

	if (fp == NULL)
		printf ("Couldn't open the file!\n");
	else if ( verify_elf_file (fp) )
		return fp;
	return NULL;
}

static inline struct Elf_hdr *get_elf_hdr 		(FILE *);
static inline struct Elf_shdr_table *get_elf_shdr_table	(FILE *, struct Elf_hdr *);
static inline struct Elf_phdr_table *get_elf_phdr_table	(FILE *, struct Elf_hdr *);
static inline void get_elf_sections 			(FILE *, struct Elf_shdr_table *);
static inline void get_elf_segments			(FILE *, struct Elf_phdr_table *);
static inline void get_sections_name 			(struct Elf_shdr_table *, struct Elf_hdr *);
static inline struct Elf_symtab *get_elf_symbol_table 	(FILE *, struct Elf_shdr_table *);

struct Elf_obj *get_elf_obj (FILE *fp) 
{
	struct Elf_obj *elf_obj = NULL;

	elf_obj = malloc (sizeof(struct Elf_obj));

	elf_obj->elf_hdr = get_elf_hdr (fp);

	elf_obj->elf_obj_t = elf_obj->elf_hdr->elf_hdr_t;

	elf_obj->elf_shdr_table = get_elf_shdr_table (fp, elf_obj->elf_hdr);
	elf_obj->elf_phdr_table = get_elf_phdr_table (fp, elf_obj->elf_hdr);

	get_elf_sections (fp, elf_obj->elf_shdr_table);
	get_elf_segments (fp, elf_obj->elf_phdr_table);

	get_sections_name (elf_obj->elf_shdr_table, elf_obj->elf_hdr);

	elf_obj->elf_symtab = get_elf_symbol_table (fp, elf_obj->elf_shdr_table);

	return elf_obj;
}

static inline struct Elf32_Ehdr *get_elf32_header 	(FILE *);
static inline struct Elf64_Ehdr *get_elf64_header 	(FILE *);
static inline uint16_t get_elf_hdr_type 		(FILE *);

static inline struct Elf_hdr *get_elf_hdr (FILE *fp) 
{
	struct Elf_hdr *elf_hdr;

	elf_hdr = malloc (sizeof(struct Elf_hdr));
	elf_hdr->elf_hdr_t = get_elf_hdr_type (fp);

	if (elf_hdr->elf_hdr_t == ELFCLASS32)
		elf_hdr->elf_hdr.elf32_hdr = get_elf32_header (fp);
	else if (elf_hdr->elf_hdr_t == ELFCLASS64)
		elf_hdr->elf_hdr.elf64_hdr = get_elf64_header (fp);

	return elf_hdr;
}

static inline uint16_t get_elf_hdr_type (FILE *fp) 
{
	uint16_t type = 0;

	fseek (fp, 4, SEEK_SET);
	fread (&type, 1, 1, fp);
	rewind (fp);

	return type;
}

static inline void read_32_e_ident 	(FILE *, struct Elf32_Ehdr *);
static inline void read_32_e_type 	(FILE *, struct Elf32_Ehdr *);
static inline void read_32_e_machine 	(FILE *, struct Elf32_Ehdr *);
static inline void read_32_e_version 	(FILE *, struct Elf32_Ehdr *);
static inline void read_32_e_entry 	(FILE *, struct Elf32_Ehdr *);
static inline void read_32_e_phoff 	(FILE *, struct Elf32_Ehdr *);
static inline void read_32_e_shoff 	(FILE *, struct Elf32_Ehdr *);
static inline void read_32_e_flags 	(FILE *, struct Elf32_Ehdr *);
static inline void read_32_e_ehsize 	(FILE *, struct Elf32_Ehdr *);
static inline void read_32_e_phentsize 	(FILE *, struct Elf32_Ehdr *);
static inline void read_32_e_phnum 	(FILE *, struct Elf32_Ehdr *);
static inline void read_32_e_shentsize 	(FILE *, struct Elf32_Ehdr *);
static inline void read_32_e_shnum 	(FILE *, struct Elf32_Ehdr *);
static inline void read_32_e_shstrndx 	(FILE *, struct Elf32_Ehdr *);

static inline struct Elf32_Ehdr *get_elf32_header (FILE *fp) 
{
	struct Elf32_Ehdr *new_elf32_hdr;
	new_elf32_hdr = malloc (sizeof(struct Elf32_Ehdr));
	
	read_32_e_ident 		(fp, new_elf32_hdr);
	read_32_e_type 			(fp, new_elf32_hdr);
	read_32_e_machine 		(fp, new_elf32_hdr);
	read_32_e_version 		(fp, new_elf32_hdr);
	read_32_e_entry 		(fp, new_elf32_hdr);
	read_32_e_phoff 		(fp, new_elf32_hdr);
	read_32_e_shoff 		(fp, new_elf32_hdr);
	read_32_e_flags 		(fp, new_elf32_hdr);
	read_32_e_ehsize		(fp, new_elf32_hdr);
	read_32_e_phentsize		(fp, new_elf32_hdr);
	read_32_e_phnum 		(fp, new_elf32_hdr);
	read_32_e_shentsize		(fp, new_elf32_hdr);
	read_32_e_shnum 		(fp, new_elf32_hdr);
	read_32_e_shstrndx 		(fp, new_elf32_hdr);

	return new_elf32_hdr;	
}
static inline void read_32_e_ident (FILE *fp, struct Elf32_Ehdr *elf32_hdr) 
{ 	fread (&(elf32_hdr->e_ident), 16, 1, fp); }
static inline void read_32_e_type (FILE *fp, struct Elf32_Ehdr *elf32_hdr) 
{	fread (&(elf32_hdr->e_type), 2, 1, fp); }
static inline void read_32_e_machine (FILE *fp, struct Elf32_Ehdr *elf32_hdr) 
{	fread (&(elf32_hdr->e_machine), 2, 1, fp); }
static inline void read_32_e_version (FILE *fp, struct Elf32_Ehdr *elf32_hdr) 
{	fread (&(elf32_hdr->e_version), 4, 1, fp); }
static inline void read_32_e_entry (FILE *fp, struct Elf32_Ehdr *elf32_hdr) 
{	fread (&(elf32_hdr->e_entry), 4, 1, fp); }
static inline void read_32_e_phoff (FILE *fp, struct Elf32_Ehdr *elf32_hdr) 
{	fread (&(elf32_hdr->e_phoff), 4, 1, fp); }
static inline void read_32_e_shoff (FILE *fp, struct Elf32_Ehdr *elf32_hdr) 
{	fread (&(elf32_hdr->e_shoff), 4, 1, fp); }
static inline void read_32_e_flags (FILE *fp, struct Elf32_Ehdr *elf32_hdr) 
{	fread (&(elf32_hdr->e_flags), 4, 1, fp); }
static inline void read_32_e_ehsize (FILE *fp, struct Elf32_Ehdr *elf32_hdr) 
{	fread (&(elf32_hdr->e_ehsize), 2, 1, fp); }
static inline void read_32_e_phentsize (FILE *fp, struct Elf32_Ehdr *elf32_hdr) 
{	fread (&(elf32_hdr->e_phentsize), 2, 1, fp); }
static inline void read_32_e_phnum (FILE *fp, struct Elf32_Ehdr *elf32_hdr) 
{	fread (&(elf32_hdr->e_phnum), 2, 1, fp); }
static inline void read_32_e_shentsize (FILE *fp, struct Elf32_Ehdr *elf32_hdr) 
{	fread (&(elf32_hdr->e_shentsize), 2, 1, fp); }
static inline void read_32_e_shnum (FILE *fp, struct Elf32_Ehdr *elf32_hdr) 
{	fread (&(elf32_hdr->e_shnum), 2, 1, fp); }
static inline void read_32_e_shstrndx (FILE *fp, struct Elf32_Ehdr *elf32_hdr) 
{	fread (&(elf32_hdr->e_shstrndx), 2, 1, fp); }

static inline void read_64_e_ident 	(FILE *, struct Elf64_Ehdr *);
static inline void read_64_e_type 	(FILE *, struct Elf64_Ehdr *);
static inline void read_64_e_machine 	(FILE *, struct Elf64_Ehdr *);
static inline void read_64_e_version 	(FILE *, struct Elf64_Ehdr *);
static inline void read_64_e_entry 	(FILE *, struct Elf64_Ehdr *);
static inline void read_64_e_phoff 	(FILE *, struct Elf64_Ehdr *);
static inline void read_64_e_shoff 	(FILE *, struct Elf64_Ehdr *);
static inline void read_64_e_flags 	(FILE *, struct Elf64_Ehdr *);
static inline void read_64_e_ehsize 	(FILE *, struct Elf64_Ehdr *);
static inline void read_64_e_phentsize 	(FILE *, struct Elf64_Ehdr *);
static inline void read_64_e_phnum 	(FILE *, struct Elf64_Ehdr *);
static inline void read_64_e_shentsize 	(FILE *, struct Elf64_Ehdr *);
static inline void read_64_e_shnum 	(FILE *, struct Elf64_Ehdr *);
static inline void read_64_e_shstrndx 	(FILE *, struct Elf64_Ehdr *);

static inline struct Elf64_Ehdr *get_elf64_header (FILE *fp) 
{
	struct Elf64_Ehdr *new_elf64_hdr;
	new_elf64_hdr = malloc (sizeof(struct Elf64_Ehdr));
	
	read_64_e_ident 		(fp, new_elf64_hdr);
	read_64_e_type 			(fp, new_elf64_hdr);
	read_64_e_machine 		(fp, new_elf64_hdr);
	read_64_e_version 		(fp, new_elf64_hdr);
	read_64_e_entry 		(fp, new_elf64_hdr);
	read_64_e_phoff 		(fp, new_elf64_hdr);
	read_64_e_shoff 		(fp, new_elf64_hdr);
	read_64_e_flags 		(fp, new_elf64_hdr);
	read_64_e_ehsize		(fp, new_elf64_hdr);
	read_64_e_phentsize		(fp, new_elf64_hdr);
	read_64_e_phnum 		(fp, new_elf64_hdr);
	read_64_e_shentsize		(fp, new_elf64_hdr);
	read_64_e_shnum 		(fp, new_elf64_hdr);
	read_64_e_shstrndx 		(fp, new_elf64_hdr);

	return new_elf64_hdr;	
}
static inline void read_64_e_ident (FILE *fp, struct Elf64_Ehdr *elf64_hdr) 
{	fread (&(elf64_hdr->e_ident), 16, 1, fp); }
static inline void read_64_e_type (FILE *fp, struct Elf64_Ehdr *elf64_hdr) 
{	fread (&(elf64_hdr->e_type), 2, 1, fp); }
static inline void read_64_e_machine (FILE *fp, struct Elf64_Ehdr *elf64_hdr) 
{	fread (&(elf64_hdr->e_machine), 2, 1, fp); }
static inline void read_64_e_version (FILE *fp, struct Elf64_Ehdr *elf64_hdr) 
{	fread (&(elf64_hdr->e_version), 4, 1, fp); }
static inline void read_64_e_entry (FILE *fp, struct Elf64_Ehdr *elf64_hdr) 
{	fread (&(elf64_hdr->e_entry), 8, 1, fp); }
static inline void read_64_e_phoff (FILE *fp, struct Elf64_Ehdr *elf64_hdr) 
{	fread (&(elf64_hdr->e_phoff), 8, 1, fp); }
static inline void read_64_e_shoff (FILE *fp, struct Elf64_Ehdr *elf64_hdr) 
{	fread (&(elf64_hdr->e_shoff), 8, 1, fp); }
static inline void read_64_e_flags (FILE *fp, struct Elf64_Ehdr *elf64_hdr) 
{	fread (&(elf64_hdr->e_flags), 4, 1, fp); }
static inline void read_64_e_ehsize (FILE *fp, struct Elf64_Ehdr *elf64_hdr) 
{	fread (&(elf64_hdr->e_ehsize), 2, 1, fp); }
static inline void read_64_e_phentsize (FILE *fp, struct Elf64_Ehdr *elf64_hdr) 
{	fread (&(elf64_hdr->e_phentsize), 2, 1, fp); }
static inline void read_64_e_phnum (FILE *fp, struct Elf64_Ehdr *elf64_hdr) 
{	fread (&(elf64_hdr->e_phnum), 2, 1, fp); }
static inline void read_64_e_shentsize (FILE *fp, struct Elf64_Ehdr *elf64_hdr) 
{	fread (&(elf64_hdr->e_shentsize), 2, 1, fp); }
static inline void read_64_e_shnum (FILE *fp, struct Elf64_Ehdr *elf64_hdr) 
{	fread (&(elf64_hdr->e_shnum), 2, 1, fp); }
static inline void read_64_e_shstrndx (FILE *fp, struct Elf64_Ehdr *elf64_hdr) 
{	fread (&(elf64_hdr->e_shstrndx), 2, 1, fp); }

static inline void print_e_ident 	(uint8_t *);
static inline void print_e_type 	(uint16_t);
static inline void print_e_machine 	(uint16_t);
static inline void print_e_version 	(uint32_t);
static inline void print_e_entry 	(uint64_t);
static inline void print_e_phoff 	(uint64_t);
static inline void print_e_shoff 	(uint64_t);
static inline void print_e_flags	(uint32_t);
static inline void print_e_ehsize	(uint16_t);
static inline void print_e_phentsize	(uint16_t);
static inline void print_e_phnum	(uint16_t);
static inline void print_e_shentsize	(uint16_t);
static inline void print_e_shnum	(uint16_t);
static inline void print_e_shstrndx	(uint16_t);


void print_elf_hdr (const struct Elf_hdr *elf_hdr) 
{
	printf ("ELF Header:\n");
	if (elf_hdr->elf_hdr_t == ELFCLASS32) {
		print_e_ident		(elf_hdr->elf_hdr.elf32_hdr->e_ident);
		print_e_type 		(elf_hdr->elf_hdr.elf32_hdr->e_type);
		print_e_machine 	(elf_hdr->elf_hdr.elf32_hdr->e_machine);
		print_e_version 	(elf_hdr->elf_hdr.elf32_hdr->e_version);
		print_e_entry		(elf_hdr->elf_hdr.elf32_hdr->e_entry);
		print_e_phoff		(elf_hdr->elf_hdr.elf32_hdr->e_phoff);
		print_e_shoff		(elf_hdr->elf_hdr.elf32_hdr->e_shoff);
		print_e_flags		(elf_hdr->elf_hdr.elf32_hdr->e_flags);
		print_e_ehsize		(elf_hdr->elf_hdr.elf32_hdr->e_ehsize);
		print_e_phentsize	(elf_hdr->elf_hdr.elf32_hdr->e_phentsize);
		print_e_phnum		(elf_hdr->elf_hdr.elf32_hdr->e_phnum);
		print_e_shentsize	(elf_hdr->elf_hdr.elf32_hdr->e_shentsize);
		print_e_shnum		(elf_hdr->elf_hdr.elf32_hdr->e_shnum);
		print_e_shstrndx	(elf_hdr->elf_hdr.elf32_hdr->e_shstrndx);
	} else if (elf_hdr->elf_hdr_t == ELFCLASS64) {
		print_e_ident		(elf_hdr->elf_hdr.elf64_hdr->e_ident);
		print_e_type 		(elf_hdr->elf_hdr.elf64_hdr->e_type);
		print_e_machine		(elf_hdr->elf_hdr.elf64_hdr->e_machine);
		print_e_version 	(elf_hdr->elf_hdr.elf64_hdr->e_version);
		print_e_entry		(elf_hdr->elf_hdr.elf64_hdr->e_entry);
		print_e_phoff		(elf_hdr->elf_hdr.elf64_hdr->e_phoff);
		print_e_shoff		(elf_hdr->elf_hdr.elf64_hdr->e_shoff);
		print_e_flags		(elf_hdr->elf_hdr.elf64_hdr->e_flags);
		print_e_ehsize		(elf_hdr->elf_hdr.elf64_hdr->e_ehsize);
		print_e_phentsize	(elf_hdr->elf_hdr.elf64_hdr->e_phentsize);
		print_e_phnum		(elf_hdr->elf_hdr.elf64_hdr->e_phnum);
		print_e_shentsize	(elf_hdr->elf_hdr.elf64_hdr->e_shentsize);
		print_e_shnum		(elf_hdr->elf_hdr.elf64_hdr->e_shnum);
		print_e_shstrndx	(elf_hdr->elf_hdr.elf64_hdr->e_shstrndx);
	}
}

static inline void print_e_ident (uint8_t e_ident[EI_NIDENT]) 
{
	uint16_t i;

	printf ("Identifier:\t\t\t");
	for (i = 0; i < EI_NIDENT; i++)
		printf ("%02x ", e_ident[i]);
	putchar ('\n');
	printf ("Class:");
	if (e_ident[4] == ELFCLASSNONE) 
		printf ("\t\t\t\tInvalid class\n");
	else if (e_ident[4] == ELFCLASS32) 
		printf ("\t\t\t\t32-bit objects\n");
	else if (e_ident[4] == ELFCLASS64) 
		printf ("\t\t\t\t64-bit objects\n");
	printf ("Enconding:");
	if (e_ident[5] == ELFDATANONE) 
		printf ("\t\t\tInvalid data encoding\n");
	else if (e_ident[5] == ELFDATA2LSB) 
		printf ("\t\t\t2's complement, Little endian\n");
	else if (e_ident[5] == ELFDATA2MSB) 
		printf ("\t\t\t2's complement, Big endian\n");
	printf ("ELF header version:");
	if (e_ident[6] == EV_NONE) 
		printf ("\t\tInvalid Version\n");
	if (e_ident[6] == EV_CURRENT) 
		printf ("\t\tCurrent Version\n");
}
static inline void print_e_type (uint16_t e_type) 
{
	printf ("Type:");
	if (e_type == ET_NONE) 
		printf ("\t\t\t\tNo file type\n");
	else if (e_type == ET_REL) 
		printf ("\t\t\t\tRelocatable file\n");
	else if (e_type == ET_EXEC) 
		printf ("\t\t\t\tExecutable file \n");
	else if (e_type == ET_DYN) 
		printf ("\t\t\t\tShared object file\n");
	else if (e_type == ET_CORE) 
		printf ("\t\t\t\tCore file\n");
	else if (e_type == ET_HIPROC || e_type == ET_LOPROC) 
		printf ("\t\t\t\tProcessor-specific\n");
}
static inline void print_e_machine (uint16_t e_machine) 
{
	printf ("Machine:");
	if (e_machine == EM_NONE)
		printf ("\t\t\tNo machine\n");
	else if (e_machine == EM_M32)
		printf ("\t\t\tAT&T WE 32100\n");
	else if (e_machine == EM_SPARC)
		printf ("\t\t\tSPARC\n");
	else if (e_machine == EM_386)
		printf ("\t\t\tIntel 80386\n");
	else if (e_machine == EM_68K)
		printf ("\t\t\tMotorola 68000\n");
	else if (e_machine == EM_88K)
		printf ("\t\t\tMotorola 88000\n");
	else if (e_machine == EM_860)
		printf ("\t\t\tIntel 80860\n");
	else if (e_machine == EM_MIPS)
		printf ("\t\t\tMIPS RS3000\n");
	else if (e_machine == EM_IA_64)
		printf ("\t\t\tIntel IA-64 processor architecture\n");
	else
		printf ("\t\t\tOutro nao identificados: %u\n", e_machine);
}
static inline void print_e_version (uint32_t e_version) 
{

	printf ("Object version:");
	if (e_version == EV_NONE)
		printf ("\t\t\tInvalid object file version\n");
	else if (e_version == EV_CURRENT)
		printf ("\t\t\tCurrent object file version\n");
}
static inline void print_e_entry (uint64_t e_entry) 
{	printf ("Entry point: \t\t\t0x%08lx\n", e_entry); }
static inline void print_e_phoff (uint64_t e_phoff) 
{	printf ("Program header table: \t\t0x%08lx(%li) bytes into the file\n", e_phoff, e_phoff); }
static inline void print_e_shoff (uint64_t e_shoff) 
{	printf ("Section header table: \t\t0x%08lx(%li) bytes into the file\n", e_shoff, e_shoff); }
static inline void print_e_flags (uint32_t e_flags) 
{	printf ("flags:\t\t\t\t0x%04x\n", e_flags); }
static inline void print_e_ehsize (uint16_t e_ehsize) 
{	printf ("ELF header size \t\t0x%02x(%i)bytes\n", e_ehsize, e_ehsize); }
static inline void print_e_phentsize (uint16_t e_phentsize) 
{	printf ("Program header size: \t\t0x%02x(%i)bytes\n", e_phentsize, e_phentsize); }
static inline void print_e_phnum (uint16_t e_phnum) 
{	printf ("Number of program headers: \t0x%02x(%i)\n", e_phnum, e_phnum); }
static inline void print_e_shentsize (uint16_t e_shentsize) 
{	printf ("Section header size: \t\t0x%02x(%i)bytes\n", e_shentsize, e_shentsize); }
static inline void print_e_shnum (uint16_t e_shnum) 
{	printf ("Number of Section headers: \t0x%02x(%i)\n", e_shnum, e_shnum); }
static inline void print_e_shstrndx (uint16_t e_shstrndx) 
{	printf ("String table index: \t\t0x%02x(%d)\n", e_shstrndx, e_shstrndx); }


static inline struct Elf32_Shdr *get_elf32_shdr (FILE *);
static inline struct Elf64_Shdr *get_elf64_shdr (FILE *);

static inline struct Elf_shdr_table *get_elf_shdr_table (FILE *fp, struct Elf_hdr *elf_hdr) 
{
	struct Elf_shdr_table *elf_shdr_table;
	uint16_t i;

	elf_shdr_table = malloc(sizeof(struct Elf_shdr_table));
	elf_shdr_table->elf_shdr_table_t = elf_hdr->elf_hdr_t;

	if (elf_shdr_table->elf_shdr_table_t == ELFCLASS32) {
		elf_shdr_table->e_shnum = elf_hdr->elf_hdr.elf32_hdr->e_shnum;
		elf_shdr_table->elf_shdrs.elf32_shdr = malloc (elf_shdr_table->e_shnum*sizeof(struct Elf32_Shdr *));
		fseek (fp, elf_hdr->elf_hdr.elf32_hdr->e_shoff, SEEK_SET);
		for (i = 0; i < elf_shdr_table->e_shnum; i++)
			elf_shdr_table->elf_shdrs.elf32_shdr[i] = get_elf32_shdr (fp);
	} else if (elf_shdr_table->elf_shdr_table_t == ELFCLASS64) {
		elf_shdr_table->e_shnum = elf_hdr->elf_hdr.elf64_hdr->e_shnum;
		elf_shdr_table->elf_shdrs.elf64_shdr = malloc (elf_shdr_table->e_shnum*sizeof(struct Elf64_Shdr *));
		fseek (fp, elf_hdr->elf_hdr.elf64_hdr->e_shoff, SEEK_SET);
		for (i = 0; i < elf_shdr_table->e_shnum; i++)
			elf_shdr_table->elf_shdrs.elf64_shdr[i] = get_elf64_shdr (fp);
	}

	return elf_shdr_table;
}

static inline void read_32_sh_name 		(FILE *, struct Elf32_Shdr *);
static inline void read_32_sh_type		(FILE *, struct Elf32_Shdr *);
static inline void read_32_sh_flags 		(FILE *, struct Elf32_Shdr *);
static inline void read_32_sh_addr 		(FILE *, struct Elf32_Shdr *);
static inline void read_32_sh_offset 		(FILE *, struct Elf32_Shdr *);
static inline void read_32_sh_size 		(FILE *, struct Elf32_Shdr *);
static inline void read_32_sh_link 		(FILE *, struct Elf32_Shdr *);
static inline void read_32_sh_info 		(FILE *, struct Elf32_Shdr *);
static inline void read_32_sh_addralign 	(FILE *, struct Elf32_Shdr *);
static inline void read_32_sh_entsize 		(FILE *, struct Elf32_Shdr *);

static inline struct Elf32_Shdr *get_elf32_shdr (FILE *fp) 
{
	struct Elf32_Shdr *elf32_shdr;
	elf32_shdr = malloc (sizeof (struct Elf32_Shdr));

	read_32_sh_name 	(fp, elf32_shdr);
	read_32_sh_type 	(fp, elf32_shdr);
	read_32_sh_flags 	(fp, elf32_shdr);
	read_32_sh_addr 	(fp, elf32_shdr);
	read_32_sh_offset 	(fp, elf32_shdr);
	read_32_sh_size 	(fp, elf32_shdr);
	read_32_sh_link 	(fp, elf32_shdr);
	read_32_sh_info 	(fp, elf32_shdr);
	read_32_sh_addralign 	(fp, elf32_shdr);
	read_32_sh_entsize 	(fp, elf32_shdr);

	return elf32_shdr;
}

static inline void read_32_sh_name (FILE *fp, struct Elf32_Shdr *elf32_shdr) 
{	fread (&(elf32_shdr->sh_name), 4, 1, fp); }
static inline void read_32_sh_type (FILE *fp, struct Elf32_Shdr *elf32_shdr) 
{	fread (&(elf32_shdr->sh_type), 4, 1, fp); }
static inline void read_32_sh_flags (FILE *fp, struct Elf32_Shdr *elf32_shdr) 
{	fread (&(elf32_shdr->sh_flags), 4, 1, fp); }
static inline void read_32_sh_addr (FILE *fp, struct Elf32_Shdr *elf32_shdr) 
{	fread (&(elf32_shdr->sh_addr), 4, 1, fp); }
static inline void read_32_sh_offset (FILE *fp, struct Elf32_Shdr *elf32_shdr) 
{	fread (&(elf32_shdr->sh_offset), 4, 1, fp); }
static inline void read_32_sh_size (FILE *fp, struct Elf32_Shdr *elf32_shdr) 
{	fread (&(elf32_shdr->sh_size), 4, 1, fp); }
static inline void read_32_sh_link (FILE *fp, struct Elf32_Shdr *elf32_shdr) 
{	fread (&(elf32_shdr->sh_link), 4, 1, fp); }
static inline void read_32_sh_info (FILE *fp, struct Elf32_Shdr *elf32_shdr) 
{	fread (&(elf32_shdr->sh_info), 4, 1, fp); }
static inline void read_32_sh_addralign (FILE *fp, struct Elf32_Shdr *elf32_shdr) 
{	fread (&(elf32_shdr->sh_addralign), 4, 1, fp); }
static inline void read_32_sh_entsize (FILE *fp, struct Elf32_Shdr *elf32_shdr) 
{	fread (&(elf32_shdr->sh_entsize), 4, 1, fp); }

static inline void read_64_sh_name 		(FILE *, struct Elf64_Shdr *);
static inline void read_64_sh_type		(FILE *, struct Elf64_Shdr *);
static inline void read_64_sh_flags 		(FILE *, struct Elf64_Shdr *);
static inline void read_64_sh_addr 		(FILE *, struct Elf64_Shdr *);
static inline void read_64_sh_offset 		(FILE *, struct Elf64_Shdr *);
static inline void read_64_sh_size 		(FILE *, struct Elf64_Shdr *);
static inline void read_64_sh_link 		(FILE *, struct Elf64_Shdr *);
static inline void read_64_sh_info 		(FILE *, struct Elf64_Shdr *);
static inline void read_64_sh_addralign 	(FILE *, struct Elf64_Shdr *);
static inline void read_64_sh_entsize 		(FILE *, struct Elf64_Shdr *);

static inline struct Elf64_Shdr *get_elf64_shdr (FILE *fp) 
{
	struct Elf64_Shdr *elf64_shdr;
	elf64_shdr = malloc (sizeof (struct Elf64_Shdr));

	read_64_sh_name 	(fp, elf64_shdr);
	read_64_sh_type 	(fp, elf64_shdr);
	read_64_sh_flags 	(fp, elf64_shdr);
	read_64_sh_addr 	(fp, elf64_shdr);
	read_64_sh_offset 	(fp, elf64_shdr);
	read_64_sh_size 	(fp, elf64_shdr);
	read_64_sh_link 	(fp, elf64_shdr);
	read_64_sh_info 	(fp, elf64_shdr);
	read_64_sh_addralign 	(fp, elf64_shdr);
	read_64_sh_entsize 	(fp, elf64_shdr);

	return elf64_shdr;
}

static inline void read_64_sh_name (FILE *fp, struct Elf64_Shdr *elf64_shdr) 
{	fread (&(elf64_shdr->sh_name), 4, 1, fp); }
static inline void read_64_sh_type (FILE *fp, struct Elf64_Shdr *elf64_shdr) 
{	fread (&(elf64_shdr->sh_type), 4, 1, fp); }
static inline void read_64_sh_flags (FILE *fp, struct Elf64_Shdr *elf64_shdr) 
{	fread (&(elf64_shdr->sh_flags), 8, 1, fp); }
static inline void read_64_sh_addr (FILE *fp, struct Elf64_Shdr *elf64_shdr) 
{	fread (&(elf64_shdr->sh_addr), 8, 1, fp); }
static inline void read_64_sh_offset (FILE *fp, struct Elf64_Shdr *elf64_shdr) 
{	fread (&(elf64_shdr->sh_offset), 8, 1, fp); }
static inline void read_64_sh_size (FILE *fp, struct Elf64_Shdr *elf64_shdr) 
{	fread (&(elf64_shdr->sh_size), 8, 1, fp); }
static inline void read_64_sh_link (FILE *fp, struct Elf64_Shdr *elf64_shdr) 
{	fread (&(elf64_shdr->sh_link), 4, 1, fp); }
static inline void read_64_sh_info (FILE *fp, struct Elf64_Shdr *elf64_shdr) 
{	fread (&(elf64_shdr->sh_info), 4, 1, fp); }
static inline void read_64_sh_addralign (FILE *fp, struct Elf64_Shdr *elf64_shdr) 
{	fread (&(elf64_shdr->sh_addralign), 8, 1, fp); }
static inline void read_64_sh_entsize (FILE *fp, struct Elf64_Shdr *elf64_shdr) 
{	fread (&(elf64_shdr->sh_entsize), 8, 1, fp); }

static inline void print_sh_name 	(uint32_t);
static inline void print_sh_type 	(uint32_t);
static inline void print_sh_flags	(uint64_t);
static inline void print_sh_addr	(uint64_t);
static inline void print_sh_offset	(uint64_t);
static inline void print_sh_size	(uint64_t);
static inline void print_sh_link	(uint32_t);
static inline void print_sh_info	(uint32_t);
static inline void print_sh_addralign	(uint64_t);
static inline void print_sh_entsize	(uint64_t);
static inline void print_section 	(uint8_t *, uint64_t);

void print_elf_shdr_table (const struct Elf_shdr_table *elf_shdr_table) 
{
	uint16_t i;

	if (elf_shdr_table->elf_shdr_table_t == ELFCLASS32) {
		for (i = 0; i < elf_shdr_table->e_shnum; i++) {
			printf 	("\nShdr[%u]: %s\n", i, elf_shdr_table->elf_shdrs.elf32_shdr[i]->name);
			print_sh_name 		(elf_shdr_table->elf_shdrs.elf32_shdr[i]->sh_name);
			print_sh_type 		(elf_shdr_table->elf_shdrs.elf32_shdr[i]->sh_type);
			print_sh_flags 		(elf_shdr_table->elf_shdrs.elf32_shdr[i]->sh_flags);
			print_sh_addr 		(elf_shdr_table->elf_shdrs.elf32_shdr[i]->sh_addr);
			print_sh_offset 	(elf_shdr_table->elf_shdrs.elf32_shdr[i]->sh_offset);
			print_sh_size 		(elf_shdr_table->elf_shdrs.elf32_shdr[i]->sh_size);
			print_sh_link 		(elf_shdr_table->elf_shdrs.elf32_shdr[i]->sh_link);
			print_sh_info 		(elf_shdr_table->elf_shdrs.elf32_shdr[i]->sh_info);
			print_sh_addralign	(elf_shdr_table->elf_shdrs.elf32_shdr[i]->sh_addralign);
			print_sh_entsize 	(elf_shdr_table->elf_shdrs.elf32_shdr[i]->sh_entsize);
			print_section 		(elf_shdr_table->elf_shdrs.elf32_shdr[i]->section,
				       		 elf_shdr_table->elf_shdrs.elf32_shdr[i]->sh_size);
		}
	} else if (elf_shdr_table->elf_shdr_table_t == ELFCLASS64) {
		for (i = 0; i < elf_shdr_table->e_shnum; i++) {
			printf ("\nShdr[%u]: %s\n", i, elf_shdr_table->elf_shdrs.elf64_shdr[i]->name);
			print_sh_name 		(elf_shdr_table->elf_shdrs.elf64_shdr[i]->sh_name);
			print_sh_type 		(elf_shdr_table->elf_shdrs.elf64_shdr[i]->sh_type);
			print_sh_flags 		(elf_shdr_table->elf_shdrs.elf64_shdr[i]->sh_flags);
			print_sh_addr 		(elf_shdr_table->elf_shdrs.elf64_shdr[i]->sh_addr);
			print_sh_offset 	(elf_shdr_table->elf_shdrs.elf64_shdr[i]->sh_offset);
			print_sh_size 		(elf_shdr_table->elf_shdrs.elf64_shdr[i]->sh_size);
			print_sh_link 		(elf_shdr_table->elf_shdrs.elf64_shdr[i]->sh_link);
			print_sh_info 		(elf_shdr_table->elf_shdrs.elf64_shdr[i]->sh_info);
			print_sh_addralign 	(elf_shdr_table->elf_shdrs.elf64_shdr[i]->sh_addralign);
			print_sh_entsize 	(elf_shdr_table->elf_shdrs.elf64_shdr[i]->sh_entsize);
			print_section 		(elf_shdr_table->elf_shdrs.elf64_shdr[i]->section,
				       		 elf_shdr_table->elf_shdrs.elf64_shdr[i]->sh_size);
		}
	}
}
static inline void print_sh_name (uint32_t sh_name) 
{	printf ("String table index: \t\t%04x(%u)\n", sh_name, sh_name); }
static inline void print_sh_type (uint32_t sh_type) 
{	printf ("Section type: \t\t\t%04x(%u)\n", sh_type, sh_type); }
static inline void print_sh_flags (uint64_t sh_flags) 
{	printf ("Flags: \t\t\t\t%08lx(%lu)\n", sh_flags, sh_flags); }
static inline void print_sh_addr (uint64_t sh_addr) 
{	printf ("Memory addr: \t\t\t%08lx(%lu)\n", sh_addr, sh_addr); }
static inline void print_sh_offset (uint64_t sh_offset) 
{	printf ("Section initial byte: \t\t%08lx(%lu)\n", sh_offset, sh_offset); }
static inline void print_sh_size (uint64_t sh_size) 
{	printf ("Section header size: \t\t%08lx(%lu)\n", sh_size, sh_size); }
static inline void print_sh_link (uint32_t sh_link) 
{	printf ("sh_link: \t\t\t%04x(%u)\n", sh_link, sh_link); }
static inline void print_sh_info (uint32_t sh_info) 
{	printf ("sh_info: \t\t\t%04x(%u)\n", sh_info, sh_info); }
static inline void print_sh_addralign (uint64_t sh_addralign) 
{	printf ("sh_addralign: \t\t\t%08lx(%lu)\n", sh_addralign, sh_addralign); }
static inline void print_sh_entsize (uint64_t sh_entsize) 
{	printf ("sh_entsize: \t\t\t%08lx(%lu)\n", sh_entsize, sh_entsize); }
static inline void print_section (uint8_t *section, uint64_t size) 
{
	uint64_t i;

	printf ("Section: string[");
	for (i = 0; i < size; i++)
		putchar(section[i]);
	puts ("]");
}

static inline void prints_sh_name	(uint16_t, uint8_t *);
static inline void prints_sh_type	(uint32_t);
static inline void prints_sh_flags	(uint64_t);
static inline void prints_sh_offset	(uint64_t);
static inline void prints_sh_size	(uint64_t);
static inline void prints_sh_link	(uint32_t);
static inline void prints_sh_info	(uint32_t);
static inline void prints_sh_entsize	(uint64_t);

void prints_elf_shdr_table (const struct Elf_shdr_table *elf_shdr_table) 
{
	uint16_t i;
	
	printf ("\tName\ttype\t\tflags\t\toffset\tsize\tlink\tinfo\tentsize\n");

	if (elf_shdr_table->elf_shdr_table_t == ELFCLASS32) {
		for (i = 0; i < elf_shdr_table->e_shnum; i++) {
			prints_sh_name		(i, elf_shdr_table->elf_shdrs.elf32_shdr[i]->name);
			prints_sh_type		(elf_shdr_table->elf_shdrs.elf32_shdr[i]->sh_type);
			prints_sh_flags		(elf_shdr_table->elf_shdrs.elf32_shdr[i]->sh_flags);
			prints_sh_offset	(elf_shdr_table->elf_shdrs.elf32_shdr[i]->sh_offset);
			prints_sh_size 		(elf_shdr_table->elf_shdrs.elf32_shdr[i]->sh_size);
			prints_sh_link 		(elf_shdr_table->elf_shdrs.elf32_shdr[i]->sh_link);
			prints_sh_info 		(elf_shdr_table->elf_shdrs.elf32_shdr[i]->sh_info);
			prints_sh_entsize 	(elf_shdr_table->elf_shdrs.elf32_shdr[i]->sh_entsize);
		}
	} else if (elf_shdr_table->elf_shdr_table_t == ELFCLASS64) {
		for (i = 0; i < elf_shdr_table->e_shnum; i++) {
			prints_sh_name 		(i, elf_shdr_table->elf_shdrs.elf64_shdr[i]->name);
			prints_sh_type 		(elf_shdr_table->elf_shdrs.elf64_shdr[i]->sh_type);
			prints_sh_flags 	(elf_shdr_table->elf_shdrs.elf64_shdr[i]->sh_flags);
			prints_sh_offset 	(elf_shdr_table->elf_shdrs.elf64_shdr[i]->sh_offset);
			prints_sh_size 		(elf_shdr_table->elf_shdrs.elf64_shdr[i]->sh_size);
			prints_sh_link 		(elf_shdr_table->elf_shdrs.elf64_shdr[i]->sh_link);
			prints_sh_info 		(elf_shdr_table->elf_shdrs.elf64_shdr[i]->sh_info);
			prints_sh_entsize 	(elf_shdr_table->elf_shdrs.elf64_shdr[i]->sh_entsize);
		}
	}
}
static inline void prints_sh_name (uint16_t ndx, uint8_t *sh_name) 
{	printf ("\t[%u]%s\n", ndx, sh_name); }
static inline void prints_sh_type (uint32_t sh_type) 
{
	if (sh_type == SHT_NULL)
		printf ("\t\tNULL\t");
	else if (sh_type == SHT_PROGBITS)
		printf ("\t\tPROGBITS");
	else if (sh_type == SHT_SYMTAB)
		printf ("\t\tSYMTAB\t");
	else if (sh_type == SHT_STRTAB)
		printf ("\t\tSTRTAB\t");
	else if (sh_type == SHT_RELA)
		printf ("\t\tRELA\t");
	else if (sh_type == SHT_HASH)
		printf ("\t\tHASH\t");
	else if (sh_type == SHT_DYNAMIC)
		printf ("\t\tDYNAMIC\t");
	else if (sh_type == SHT_NOTE)
		printf ("\t\tNOTE\t");
	else if (sh_type == SHT_NOBITS)
		printf ("\t\tNOBITS\t");
	else if (sh_type == SHT_REL)
		printf ("\t\tREL\t");
	else if (sh_type == SHT_SHLIB)
		printf ("\t\tSHLIB\t");
	else if (sh_type == SHT_DYNSYM)
		printf ("\t\tDYNSYM\t");
	else if (sh_type > SHT_LOPROC && sh_type < SHT_HIPROC)
		printf ("\t\t(LO||HI)PROC");
	else if (sh_type > SHT_LOUSER && sh_type < SHT_HIUSER)
		printf ("\t\t(LO||HI)USER");
	else if ( (sh_type > SHT_DYNSYM) && (sh_type < SHT_LOPROC) )
		printf ("\t\t(%012u)", sh_type);
}
static inline void prints_sh_flags (uint64_t sh_flags) 
{
	if (sh_flags == SHF_WRITE)
		printf("\tWRT\t");
	else if (sh_flags == SHF_ALLOC)
		printf("\tALC\t");
	else if (sh_flags == SHF_ALLOC+SHF_WRITE)
		printf("\tWRT+ALC\t");
	else if (sh_flags == SHF_EXECINSTR)
		printf("\tEXC\t");
	else if (sh_flags == SHF_EXECINSTR+SHF_WRITE) /*nao acho que essa combinacao seja possivel..*/
		printf("\tWRT+EXC\t");
	else if (sh_flags == SHF_EXECINSTR+SHF_ALLOC)
		printf("\tALC+EXC\t");
	else
		printf("\t?(%lu)\t", sh_flags);
}
static inline void prints_sh_offset (uint64_t sh_offset) 
{	printf ("\t%lu", sh_offset); }
static inline void prints_sh_size (uint64_t sh_size) 
{	printf ("\t%lu", sh_size); }
static inline void prints_sh_link (uint32_t sh_link) 
{	printf ("\t%u", sh_link); }
static inline void prints_sh_info (uint32_t sh_info) 
{	printf ("\t%u", sh_info); }
static inline void prints_sh_entsize (uint64_t sh_entsize) 
{	printf ("\t%lu\n", sh_entsize); }

static inline struct Elf32_Phdr *get_elf32_phdr (FILE *);
static inline struct Elf64_Phdr *get_elf64_phdr (FILE *);

static inline struct Elf_phdr_table *get_elf_phdr_table (FILE *fp, struct Elf_hdr *elf_hdr) 
{
	struct Elf_phdr_table *elf_phdr_table;
	uint16_t i;

	elf_phdr_table = malloc (sizeof(struct Elf_phdr_table));
	elf_phdr_table->elf_phdr_table_t = elf_hdr->elf_hdr_t;

	if (elf_phdr_table->elf_phdr_table_t == ELFCLASS32) {
		fseek (fp, elf_hdr->elf_hdr.elf32_hdr->e_phoff, SEEK_SET);
		elf_phdr_table->e_phnum = elf_hdr->elf_hdr.elf32_hdr->e_phnum;
		elf_phdr_table->elf_phdrs.elf32_phdr = malloc (elf_phdr_table->e_phnum*sizeof(struct Elf32_Phdr *));
		for (i = 0; i < elf_phdr_table->e_phnum; i++)
			elf_phdr_table->elf_phdrs.elf32_phdr[i] = get_elf32_phdr (fp);
		
	} else if (elf_phdr_table->elf_phdr_table_t == ELFCLASS64) {
		fseek (fp, elf_hdr->elf_hdr.elf64_hdr->e_phoff, SEEK_SET);
		elf_phdr_table->e_phnum = elf_hdr->elf_hdr.elf64_hdr->e_phnum;
		elf_phdr_table->elf_phdrs.elf64_phdr = malloc (elf_phdr_table->e_phnum*sizeof(struct Elf64_Phdr *));
		for (i = 0; i < elf_phdr_table->e_phnum; i++)
			elf_phdr_table->elf_phdrs.elf64_phdr[i] = get_elf64_phdr (fp);
	}

	return elf_phdr_table;
}

static inline void read_32_p_type		(FILE *, struct Elf32_Phdr *);
static inline void read_32_p_offset 		(FILE *, struct Elf32_Phdr *);
static inline void read_32_p_vaddr 		(FILE *, struct Elf32_Phdr *);
static inline void read_32_p_paddr 		(FILE *, struct Elf32_Phdr *);
static inline void read_32_p_filesz 		(FILE *, struct Elf32_Phdr *);
static inline void read_32_p_memsz 		(FILE *, struct Elf32_Phdr *);
static inline void read_32_p_flags 		(FILE *, struct Elf32_Phdr *);
static inline void read_32_p_align 		(FILE *, struct Elf32_Phdr *);

static inline struct Elf32_Phdr *get_elf32_phdr (FILE *fp) 
{
	struct Elf32_Phdr *elf32_phdr;
	elf32_phdr = malloc (sizeof (struct Elf32_Phdr));

	read_32_p_type		(fp, elf32_phdr);
	read_32_p_offset 	(fp, elf32_phdr);
	read_32_p_vaddr 	(fp, elf32_phdr);
	read_32_p_paddr 	(fp, elf32_phdr);
	read_32_p_filesz 	(fp, elf32_phdr);
	read_32_p_memsz 	(fp, elf32_phdr);
	read_32_p_flags 	(fp, elf32_phdr);
	read_32_p_align 	(fp, elf32_phdr);

	return elf32_phdr;
}
static inline void read_32_p_type (FILE *fp, struct Elf32_Phdr *elf32_phdr) 
{	fread (&(elf32_phdr->p_type), 4, 1, fp); }
static inline void read_32_p_offset (FILE *fp, struct Elf32_Phdr *elf32_phdr) 
{	fread (&(elf32_phdr->p_offset), 4, 1, fp); }
static inline void read_32_p_vaddr (FILE *fp, struct Elf32_Phdr *elf32_phdr) 
{	fread (&(elf32_phdr->p_vaddr), 4, 1, fp); }
static inline void read_32_p_paddr (FILE *fp, struct Elf32_Phdr *elf32_phdr) 
{	fread (&(elf32_phdr->p_paddr), 4, 1, fp); }
static inline void read_32_p_filesz (FILE *fp, struct Elf32_Phdr *elf32_phdr) 
{	fread (&(elf32_phdr->p_filesz), 4, 1, fp); }
static inline void read_32_p_memsz (FILE *fp, struct Elf32_Phdr *elf32_phdr) 
{	fread (&(elf32_phdr->p_memsz), 4, 1, fp); }
static inline void read_32_p_flags (FILE *fp, struct Elf32_Phdr *elf32_phdr) 
{	fread (&(elf32_phdr->p_flags), 4, 1, fp); }
static inline void read_32_p_align (FILE *fp, struct Elf32_Phdr *elf32_phdr) 
{	fread (&(elf32_phdr->p_align), 4, 1, fp); }

static inline void read_64_p_type		(FILE *, struct Elf64_Phdr *);
static inline void read_64_p_offset 		(FILE *, struct Elf64_Phdr *);
static inline void read_64_p_vaddr 		(FILE *, struct Elf64_Phdr *);
static inline void read_64_p_paddr 		(FILE *, struct Elf64_Phdr *);
static inline void read_64_p_filesz 		(FILE *, struct Elf64_Phdr *);
static inline void read_64_p_memsz 		(FILE *, struct Elf64_Phdr *);
static inline void read_64_p_flags 		(FILE *, struct Elf64_Phdr *);
static inline void read_64_p_align 		(FILE *, struct Elf64_Phdr *);

static inline struct Elf64_Phdr *get_elf64_phdr (FILE *fp) 
{
	struct Elf64_Phdr *elf64_phdr;
	elf64_phdr = malloc (sizeof (struct Elf64_Phdr));

	read_64_p_type		(fp, elf64_phdr);
	read_64_p_flags 	(fp, elf64_phdr);
	read_64_p_offset 	(fp, elf64_phdr);
	read_64_p_vaddr 	(fp, elf64_phdr);
	read_64_p_paddr 	(fp, elf64_phdr);
	read_64_p_filesz 	(fp, elf64_phdr);
	read_64_p_memsz 	(fp, elf64_phdr);
	read_64_p_align 	(fp, elf64_phdr);

	return elf64_phdr;
}
static inline void read_64_p_type (FILE *fp, struct Elf64_Phdr *elf64_phdr) 
{	fread (&(elf64_phdr->p_type), 4, 1, fp); }
static inline void read_64_p_offset (FILE *fp, struct Elf64_Phdr *elf64_phdr) 
{	fread (&(elf64_phdr->p_offset), 8, 1, fp); }
static inline void read_64_p_vaddr (FILE *fp, struct Elf64_Phdr *elf64_phdr) 
{	fread (&(elf64_phdr->p_vaddr), 8, 1, fp); }
static inline void read_64_p_paddr (FILE *fp, struct Elf64_Phdr *elf64_phdr) 
{	fread (&(elf64_phdr->p_paddr), 8, 1, fp); }
static inline void read_64_p_filesz (FILE *fp, struct Elf64_Phdr *elf64_phdr) 
{	fread (&(elf64_phdr->p_filesz), 8, 1, fp); }
static inline void read_64_p_memsz (FILE *fp, struct Elf64_Phdr *elf64_phdr) 
{	fread (&(elf64_phdr->p_memsz), 8, 1, fp); }
static inline void read_64_p_flags (FILE *fp, struct Elf64_Phdr *elf64_phdr) 
{	fread (&(elf64_phdr->p_flags), 4, 1, fp); }
static inline void read_64_p_align (FILE *fp, struct Elf64_Phdr *elf64_phdr) 
{	fread (&(elf64_phdr->p_align), 8, 1, fp); }

static inline void print_p_type 	(uint32_t);
static inline void print_p_offset 	(uint64_t);
static inline void print_p_vaddr 	(uint64_t);
static inline void print_p_paddr 	(uint64_t);
static inline void print_p_filesz 	(uint64_t);
static inline void print_p_memsz 	(uint64_t);
static inline void print_p_flags 	(uint32_t);
static inline void print_p_align 	(uint64_t);
static inline void print_segment 	(uint8_t *, uint64_t);

void print_elf_phdr_table (const struct Elf_phdr_table *elf_phdr_table) 
{
	uint16_t i;

	printf ("\nPROGRAM HEADERS");
	if (elf_phdr_table->elf_phdr_table_t == ELFCLASS32) {
		for (i = 0; i < elf_phdr_table->e_phnum ; i++) {
			printf ("\nProgram Header:[%u]\n", i);
			print_p_type 	(elf_phdr_table->elf_phdrs.elf32_phdr[i]->p_type);
			print_p_offset 	(elf_phdr_table->elf_phdrs.elf32_phdr[i]->p_offset);
			print_p_vaddr 	(elf_phdr_table->elf_phdrs.elf32_phdr[i]->p_vaddr);
			print_p_paddr 	(elf_phdr_table->elf_phdrs.elf32_phdr[i]->p_paddr);
			print_p_filesz 	(elf_phdr_table->elf_phdrs.elf32_phdr[i]->p_filesz);
			print_p_memsz 	(elf_phdr_table->elf_phdrs.elf32_phdr[i]->p_memsz);
			print_p_flags 	(elf_phdr_table->elf_phdrs.elf32_phdr[i]->p_flags);
			print_p_align 	(elf_phdr_table->elf_phdrs.elf32_phdr[i]->p_align);
			print_segment 	(elf_phdr_table->elf_phdrs.elf32_phdr[i]->segment,
					 elf_phdr_table->elf_phdrs.elf32_phdr[i]->p_filesz);
		}
	} else if (elf_phdr_table->elf_phdr_table_t == ELFCLASS64) {
		for (i = 0; i < elf_phdr_table->e_phnum ; i++) {
			printf ("\nProgram Header:[%u]\n", i);
			print_p_type 	(elf_phdr_table->elf_phdrs.elf64_phdr[i]->p_type);
			print_p_offset 	(elf_phdr_table->elf_phdrs.elf64_phdr[i]->p_offset);
			print_p_vaddr 	(elf_phdr_table->elf_phdrs.elf64_phdr[i]->p_vaddr);
			print_p_paddr 	(elf_phdr_table->elf_phdrs.elf64_phdr[i]->p_paddr);
			print_p_filesz 	(elf_phdr_table->elf_phdrs.elf64_phdr[i]->p_filesz);
			print_p_memsz 	(elf_phdr_table->elf_phdrs.elf64_phdr[i]->p_memsz);
			print_p_flags 	(elf_phdr_table->elf_phdrs.elf64_phdr[i]->p_flags);
			print_p_align 	(elf_phdr_table->elf_phdrs.elf64_phdr[i]->p_align);
			print_segment 	(elf_phdr_table->elf_phdrs.elf64_phdr[i]->segment,
					 elf_phdr_table->elf_phdrs.elf64_phdr[i]->p_filesz);
		}
	}
}
static inline void print_p_type (uint32_t p_type) 
{
	if (p_type == PT_NULL)
		printf ("Program header type:\t\tNULL [0x%04x(%u)]\n", p_type, p_type);
	else if (p_type == PT_LOAD)
		printf ("Program header type:\t\tLOAD [0x%04x(%u)]\n", p_type, p_type);
	else if (p_type == PT_DYNAMIC)
		printf ("Program header type:\t\tDYNAMIC [0x%04x(%u)]\n", p_type, p_type);
	else if (p_type == PT_INTERP)
		printf ("Program header type:\t\tINTERP [0x%04x(%u)]\n", p_type, p_type);
	else if (p_type == PT_NOTE)
		printf ("Program header type:\t\tNOTE [0x%04x(%u)]\n", p_type, p_type);
	else if (p_type == PT_SHLIB)
		printf ("Program header type:\t\tSH_LIB [0x%04x(%u)]\n", p_type, p_type);
	else if (p_type == PT_PHDR)
		printf ("Program header type:\t\tPHDR [0x%04x(%u)]\n", p_type, p_type);
	else if (p_type > PT_LOPROC && p_type < PT_HIPROC)
		printf ("Program header type:\t\t[LOPROC||HIPROC] [0x%04x]\n", p_type);
}
static inline void print_p_offset (uint64_t p_offset) 
{	printf ("Segment initial byte:\t\t%04lx(%lu)\n", p_offset, p_offset); }
static inline void print_p_vaddr (uint64_t p_vaddr) 
{	printf ("vaddr:\t\t\t\t%04lx(%lu)\n", p_vaddr, p_vaddr); }
static inline void print_p_paddr (uint64_t p_paddr) 
{	printf ("paddr:\t\t\t\t%04lx(%lu)\n", p_paddr, p_paddr); }
static inline void print_p_filesz (uint64_t p_filesz) 
{	printf ("filesz:\t\t\t\t%04lx(%lu)\n", p_filesz, p_filesz); }
static inline void print_p_memsz (uint64_t p_memsz) 
{	printf ("memsz:\t\t\t\t%04lx(%lu)\n", p_memsz, p_memsz); }
static inline void print_p_flags (uint32_t p_flags) 
{
	if (p_flags == PF_X)
		printf ("flags:\t\t\t\tX %04x(%u)\n", p_flags, p_flags);
	else if (p_flags == PF_W)
		printf ("flags:\t\t\t\tW %04x(%u)\n", p_flags, p_flags);
	else if (p_flags == PF_R)
		printf ("flags:\t\t\t\tR %04x(%u)\n", p_flags, p_flags);
	else if (p_flags == PF_X+PF_W)
		printf ("flags:\t\t\t\tXW %04x(%u)\n", p_flags, p_flags);
	else if (p_flags == PF_X+PF_R)
		printf ("flags:\t\t\t\tXR %04x(%u)\n", p_flags, p_flags);
	else if (p_flags == PF_W+PF_R)
		printf ("flags:\t\t\t\tWR %04x(%u)\n", p_flags, p_flags);
	else if (p_flags == PF_X+PF_W+PF_R)
		printf ("flags:\t\t\t\tXWR %04x(%u)\n", p_flags, p_flags);
	else 
		printf ("UNDEFINED ACCESS FLAGS\n");
}
static inline void print_p_align (uint64_t p_align) 
{	printf ("align:\t\t\t\t%04lx(%lu)\n", p_align, p_align); }
static inline void print_segment (uint8_t *segment, uint64_t size) 
{
	uint64_t i;

	printf ("Section: string[");
	for (i = 0; i < size; i++)
		putchar(segment[i]);
	puts ("]");
}

static inline uint8_t *get_section_name (uint8_t *, uint32_t);

static inline void get_sections_name (struct Elf_shdr_table *elf_shdr_table, struct Elf_hdr *elf_hdr) 
{
	uint16_t i;

	if (elf_shdr_table->elf_shdr_table_t == ELFCLASS32) {
		for (i = 0; i < elf_shdr_table->e_shnum; i++){
			elf_shdr_table->elf_shdrs.elf32_shdr[i]->name = 
			get_section_name(elf_shdr_table->elf_shdrs.elf32_shdr[elf_hdr->elf_hdr.elf32_hdr->e_shstrndx]->section, 
			elf_shdr_table->elf_shdrs.elf32_shdr[i]->sh_name);
		}
	}
	else if (elf_shdr_table->elf_shdr_table_t == ELFCLASS64) {
		for (i = 0; i < elf_shdr_table->e_shnum; i++){
			elf_shdr_table->elf_shdrs.elf64_shdr[i]->name = 
			get_section_name(elf_shdr_table->elf_shdrs.elf64_shdr[elf_hdr->elf_hdr.elf64_hdr->e_shstrndx]->section, 
			elf_shdr_table->elf_shdrs.elf64_shdr[i]->sh_name);
		}
	}
}
static inline uint8_t *get_section_name (uint8_t *string_table, uint32_t pos) 
{
	uint8_t *name;
	uint32_t i;

	for (i = pos; string_table[i] != '\0'; i++);
	name = malloc (((i-pos)+1)*sizeof(uint8_t));
	for (i = pos; string_table[i] != '\0'; i++)
		name[i-pos] = string_table[i];
	name[i-pos] = '\0';

	return name;
}

static inline void get_elf32_section (FILE *fp, struct Elf32_Shdr *);
static inline void get_elf64_section (FILE *fp, struct Elf64_Shdr *);

static inline void get_elf_sections (FILE *fp, struct Elf_shdr_table *elf_shdr_table) 
{
	uint16_t i;

	if (elf_shdr_table->elf_shdr_table_t == ELFCLASS32)
		for (i = 0; i < elf_shdr_table->e_shnum; i++)
			get_elf32_section (fp, elf_shdr_table->elf_shdrs.elf32_shdr[i]);
	else if (elf_shdr_table->elf_shdr_table_t == ELFCLASS64)
		for (i = 0; i < elf_shdr_table->e_shnum; i++)
			get_elf64_section (fp, elf_shdr_table->elf_shdrs.elf64_shdr[i]);
}
static inline void get_elf32_section (FILE *fp, struct Elf32_Shdr *elf32_shdr) 
{
	elf32_shdr->section = malloc (elf32_shdr->sh_size*sizeof(uint8_t));
	fseek (fp, elf32_shdr->sh_offset, SEEK_SET);
	fread (elf32_shdr->section, elf32_shdr->sh_size, 1, fp);
}
static inline void get_elf64_section (FILE *fp, struct Elf64_Shdr *elf64_shdr) 
{
	elf64_shdr->section = malloc (elf64_shdr->sh_size*sizeof(uint8_t));
	fseek (fp, elf64_shdr->sh_offset, SEEK_SET);
	fread (elf64_shdr->section, elf64_shdr->sh_size, 1, fp);
}

static inline void get_elf32_segment (FILE *fp, struct Elf32_Phdr *);
static inline void get_elf64_segment (FILE *fp, struct Elf64_Phdr *);

static inline void get_elf_segments (FILE *fp, struct Elf_phdr_table *elf_phdr_table) 
{
	uint16_t i;

	if (elf_phdr_table->elf_phdr_table_t == ELFCLASS32)
		for (i = 0; i < elf_phdr_table->e_phnum; i++)
			get_elf32_segment (fp, elf_phdr_table->elf_phdrs.elf32_phdr[i]);
	else if (elf_phdr_table->elf_phdr_table_t == ELFCLASS64)
		for (i = 0; i < elf_phdr_table->e_phnum; i++)
			get_elf64_segment (fp, elf_phdr_table->elf_phdrs.elf64_phdr[i]);
}
static inline void get_elf32_segment (FILE *fp, struct Elf32_Phdr *elf32_phdr) 
{
	elf32_phdr->segment = malloc (elf32_phdr->p_filesz*sizeof(uint8_t));
	fseek (fp, elf32_phdr->p_offset, SEEK_SET);
	fread (elf32_phdr->segment, elf32_phdr->p_filesz, 1, fp);
}
static inline void get_elf64_segment (FILE *fp, struct Elf64_Phdr *elf64_phdr) 
{
	elf64_phdr->segment = malloc (elf64_phdr->p_filesz*sizeof(uint8_t));
	fseek (fp, elf64_phdr->p_offset, SEEK_SET);
	fread (elf64_phdr->segment, elf64_phdr->p_filesz, 1, fp);
}

static inline struct Elf32_Symbol *get_elf32_symbol (FILE *);
static inline struct Elf64_Symbol *get_elf64_symbol (FILE *);

static inline struct Elf_symtab *get_elf_symbol_table (FILE *fp, struct Elf_shdr_table *elf_shdr_table) 
{
	struct Elf_symtab *elf_symtab = NULL;
	uint16_t i;
	uint32_t j;

	if (elf_shdr_table->elf_shdr_table_t == ELFCLASS32) {
		for (i = 0; i < elf_shdr_table->e_shnum; i++) {
			if (elf_shdr_table->elf_shdrs.elf32_shdr[i]->sh_type == SHT_SYMTAB) {
				elf_symtab = malloc (sizeof (struct Elf_symtab));
				elf_symtab->elf_symtab_t = ELFCLASS32;
				elf_symtab->sh_info = elf_shdr_table->elf_shdrs.elf32_shdr[i]->sh_info;
				elf_symtab->elf_symbols.elf32_symbols = malloc (elf_symtab->sh_info*sizeof(struct Elf32_Symbol *));
				fseek (fp, elf_shdr_table->elf_shdrs.elf32_shdr[i]->sh_offset, SEEK_SET);
				for (j = 0; j < elf_symtab->sh_info; j++) 
					elf_symtab->elf_symbols.elf32_symbols[j] = get_elf32_symbol (fp);
				i = elf_shdr_table->e_shnum;
			}
		}
	}  else if (elf_shdr_table->elf_shdr_table_t == ELFCLASS64) {
		for (i = 0; i < elf_shdr_table->e_shnum; i++) {
			if (elf_shdr_table->elf_shdrs.elf64_shdr[i]->sh_type == SHT_SYMTAB) {
				elf_symtab = malloc (sizeof (struct Elf_symtab));
				elf_symtab->elf_symtab_t = ELFCLASS64;
				elf_symtab->sh_info = elf_shdr_table->elf_shdrs.elf64_shdr[i]->sh_info;
				elf_symtab->elf_symbols.elf64_symbols = malloc (elf_symtab->sh_info*sizeof(struct Elf64_Symbol *));
				fseek (fp, elf_shdr_table->elf_shdrs.elf64_shdr[i]->sh_offset, SEEK_SET);
				for (j = 0; j < elf_symtab->sh_info; j++) 
					elf_symtab->elf_symbols.elf64_symbols[j] = get_elf64_symbol (fp);
				i = elf_shdr_table->e_shnum;
			}
		}
	}
	
	return elf_symtab;
}


static inline void read_elf32_st_name	(FILE *, struct Elf32_Symbol *);
static inline void read_elf32_st_value	(FILE *, struct Elf32_Symbol *);
static inline void read_elf32_st_size	(FILE *, struct Elf32_Symbol *);
static inline void read_elf32_st_info	(FILE *, struct Elf32_Symbol *);
static inline void read_elf32_st_other	(FILE *, struct Elf32_Symbol *);
static inline void read_elf32_st_shndx	(FILE *, struct Elf32_Symbol *);

static inline struct Elf32_Symbol *get_elf32_symbol (FILE *fp) 
{
	struct Elf32_Symbol *elf32_symbol;
	elf32_symbol = malloc (sizeof(struct Elf32_Symbol));

	read_elf32_st_name	(fp, elf32_symbol);
	read_elf32_st_value	(fp, elf32_symbol);
	read_elf32_st_size	(fp, elf32_symbol);
	read_elf32_st_info	(fp, elf32_symbol);
	read_elf32_st_other	(fp, elf32_symbol);
	read_elf32_st_shndx	(fp, elf32_symbol);

	return elf32_symbol;
}
static inline void read_elf32_st_name (FILE *fp, struct Elf32_Symbol *elf32_symbol) 
{	fread (&(elf32_symbol->st_name), 4, 1, fp); }
static inline void read_elf32_st_value (FILE *fp, struct Elf32_Symbol *elf32_symbol) 
{	fread (&(elf32_symbol->st_value), 8, 1, fp); }
static inline void read_elf32_st_size (FILE *fp, struct Elf32_Symbol *elf32_symbol) 
{	fread (&(elf32_symbol->st_size), 4, 1, fp); }
static inline void read_elf32_st_info (FILE *fp, struct Elf32_Symbol *elf32_symbol) 
{	fread (&(elf32_symbol->st_info), 1, 1, fp); }
static inline void read_elf32_st_other (FILE *fp, struct Elf32_Symbol *elf32_symbol) 
{	fread (&(elf32_symbol->st_other), 1, 1, fp); }
static inline void read_elf32_st_shndx (FILE *fp, struct Elf32_Symbol *elf32_symbol) 
{	fread (&(elf32_symbol->st_shndx), 2, 1, fp); }

static inline void read_elf64_st_name	(FILE *, struct Elf64_Symbol *);
static inline void read_elf64_st_value	(FILE *, struct Elf64_Symbol *);
static inline void read_elf64_st_size	(FILE *, struct Elf64_Symbol *);
static inline void read_elf64_st_info	(FILE *, struct Elf64_Symbol *);
static inline void read_elf64_st_other	(FILE *, struct Elf64_Symbol *);
static inline void read_elf64_st_shndx	(FILE *, struct Elf64_Symbol *);

static inline struct Elf64_Symbol *get_elf64_symbol (FILE *fp) 
{
	struct Elf64_Symbol *elf64_symbol;
	elf64_symbol = malloc (sizeof(struct Elf64_Symbol));

	read_elf64_st_name	(fp, elf64_symbol);
	read_elf64_st_value	(fp, elf64_symbol);
	read_elf64_st_size	(fp, elf64_symbol);
	read_elf64_st_info	(fp, elf64_symbol);
	read_elf64_st_other	(fp, elf64_symbol);
	read_elf64_st_shndx	(fp, elf64_symbol);

	return elf64_symbol;
}
static inline void read_elf64_st_name (FILE *fp, struct Elf64_Symbol *elf64_symbol) 
{	fread (&(elf64_symbol->st_name), 4, 1, fp); }
static inline void read_elf64_st_value (FILE *fp, struct Elf64_Symbol *elf64_symbol) 
{
	fread (&(elf64_symbol->st_value), 4, 1, fp); /*ARRUMAR VER EXATAMENTE COMO DEVE SER!!!!!!!!!!!!!!!!*/
	fread (&(elf64_symbol->st_value), 8, 1, fp);	
}
static inline void read_elf64_st_size (FILE *fp, struct Elf64_Symbol *elf64_symbol) 
{	fread (&(elf64_symbol->st_size), 4, 1, fp); }
static inline void read_elf64_st_info (FILE *fp, struct Elf64_Symbol *elf64_symbol) 
{	fread (&(elf64_symbol->st_info), 1, 1, fp); }
static inline void read_elf64_st_other (FILE *fp, struct Elf64_Symbol *elf64_symbol) 
{	fread (&(elf64_symbol->st_other), 1, 1, fp); }
static inline void read_elf64_st_shndx (FILE *fp, struct Elf64_Symbol *elf64_symbol) 
{	fread (&(elf64_symbol->st_shndx), 2, 1, fp); }

static inline void print_elf_st_name	(uint32_t);
static inline void print_elf_st_value	(uint64_t);
static inline void print_elf_st_size	(uint32_t);
static inline void print_elf_st_info	(uint8_t);
static inline void print_elf_st_other	(uint8_t);
static inline void print_elf_st_shndx	(uint16_t);

void print_elf_symbol_table (const struct Elf_symtab *elf_symtab) 
{
	uint32_t i;

	printf ("\tname\t\tvalue\tsize\tinfo\tother\tshndx\n");
	if (elf_symtab->elf_symtab_t == ELFCLASS32) {
		for (i = 0; i < elf_symtab->sh_info; i++) {
			printf ("[%u]", i);
			print_elf_st_name	(elf_symtab->elf_symbols.elf32_symbols[i]->st_name);
			print_elf_st_value	(elf_symtab->elf_symbols.elf32_symbols[i]->st_value);
			print_elf_st_size	(elf_symtab->elf_symbols.elf32_symbols[i]->st_size);
			print_elf_st_info	(elf_symtab->elf_symbols.elf32_symbols[i]->st_info);
			print_elf_st_other	(elf_symtab->elf_symbols.elf32_symbols[i]->st_other);
			print_elf_st_shndx	(elf_symtab->elf_symbols.elf32_symbols[i]->st_shndx);
		}
	} else if (elf_symtab->elf_symtab_t == ELFCLASS64) {
		for (i = 0; i < elf_symtab->sh_info; i++) {
			printf ("[%u]", i);
			print_elf_st_name	(elf_symtab->elf_symbols.elf64_symbols[i]->st_name);
			print_elf_st_value	(elf_symtab->elf_symbols.elf64_symbols[i]->st_value);
			print_elf_st_size	(elf_symtab->elf_symbols.elf64_symbols[i]->st_size);
			print_elf_st_info	(elf_symtab->elf_symbols.elf64_symbols[i]->st_info);
			print_elf_st_other	(elf_symtab->elf_symbols.elf64_symbols[i]->st_other);
			print_elf_st_shndx	(elf_symtab->elf_symbols.elf64_symbols[i]->st_shndx);
		}
	}
}
static inline void print_elf_st_name (uint32_t st_name) 
{	printf ("\t%u\n", st_name); }
static inline void print_elf_st_value (uint64_t st_value) 
{	printf ("\t\t\t%lx", st_value); }
static inline void print_elf_st_size (uint32_t st_size) 
{	printf ("\t%u", st_size); }
static inline void print_elf_st_info (uint8_t st_info) 
{	printf ("\t%u", st_info); }
static inline void print_elf_st_other (uint8_t st_other) 
{	printf ("\t%u", st_other); }
static inline void print_elf_st_shndx (uint16_t st_shndx) 
{	printf ("\t%u\n", st_shndx); }

static inline void free_elf_hdr		(struct Elf_hdr *);
static inline void free_elf_shdr_table	(struct Elf_shdr_table *);
static inline void free_elf_phdr_table	(struct Elf_phdr_table *);
static inline void free_elf_symtab 	(struct Elf_symtab *);

void close_elf_obj (FILE *fp, struct Elf_obj *elf_obj) 
{
	free_elf_hdr		(elf_obj->elf_hdr);
	free_elf_shdr_table	(elf_obj->elf_shdr_table);
	free_elf_phdr_table	(elf_obj->elf_phdr_table);
	free_elf_symtab		(elf_obj->elf_symtab);
	free			(elf_obj);
	fclose			(fp);
}
static inline void free_elf_hdr (struct Elf_hdr *elf_hdr) 
{
	if (elf_hdr->elf_hdr_t == ELFCLASS32)
		free (elf_hdr->elf_hdr.elf32_hdr);
	else if (elf_hdr->elf_hdr_t == ELFCLASS64)
		free (elf_hdr->elf_hdr.elf64_hdr);
	free (elf_hdr);
}
static inline void free_elf_shdr_table (struct Elf_shdr_table *elf_shdr_table) 
{
	uint16_t i;

	if (elf_shdr_table->elf_shdr_table_t == ELFCLASS32) {
		for (i = 0; i < elf_shdr_table->e_shnum; i++) {
			free (elf_shdr_table->elf_shdrs.elf32_shdr[i]->section);
			free (elf_shdr_table->elf_shdrs.elf32_shdr[i]->name);
			free (elf_shdr_table->elf_shdrs.elf32_shdr[i]);
		}
		free (elf_shdr_table->elf_shdrs.elf32_shdr);
	} else if (elf_shdr_table->elf_shdr_table_t == ELFCLASS64) {
		for (i = 0; i < elf_shdr_table->e_shnum; i++) {
			free (elf_shdr_table->elf_shdrs.elf64_shdr[i]->section);
			free (elf_shdr_table->elf_shdrs.elf64_shdr[i]->name);
			free (elf_shdr_table->elf_shdrs.elf64_shdr[i]);
		}
		free (elf_shdr_table->elf_shdrs.elf64_shdr);
	}
	free (elf_shdr_table);
}
static inline void free_elf_phdr_table (struct Elf_phdr_table *elf_phdr_table) 
{
	uint16_t i;

	if (elf_phdr_table->elf_phdr_table_t == ELFCLASS32) {
		for (i = 0; i < elf_phdr_table->e_phnum; i++) {
			free (elf_phdr_table->elf_phdrs.elf32_phdr[i]->segment);
			free (elf_phdr_table->elf_phdrs.elf32_phdr[i]);
		}
		free (elf_phdr_table->elf_phdrs.elf32_phdr);
	} else if (elf_phdr_table->elf_phdr_table_t == ELFCLASS64) {
		for (i = 0; i < elf_phdr_table->e_phnum; i++) {
			free (elf_phdr_table->elf_phdrs.elf64_phdr[i]->segment);
			free (elf_phdr_table->elf_phdrs.elf64_phdr[i]);
		}
		free (elf_phdr_table->elf_phdrs.elf64_phdr);
	}
	free (elf_phdr_table);
}
static inline void free_elf_symtab (struct Elf_symtab *elf_symtab) 
{
	uint16_t i;

	if (elf_symtab != NULL) { /*Pode ser que um arquivo objeto não tenha uma tabela de simbolos.*/
		if (elf_symtab->elf_symtab_t == ELFCLASS32) {
			for (i = 0; i < elf_symtab->sh_info; i++)
				free (elf_symtab->elf_symbols.elf32_symbols[i]);
			free (elf_symtab->elf_symbols.elf32_symbols);
		} else if (elf_symtab->elf_symtab_t == ELFCLASS64) {
			for (i = 0; i < elf_symtab->sh_info; i++)
				free (elf_symtab->elf_symbols.elf64_symbols[i]);
			free (elf_symtab->elf_symbols.elf64_symbols);
		}
		free (elf_symtab);
	}
}

/*writes!!*/
static inline void fwrite_elf_hdr 		(FILE *, struct Elf_hdr *);
static inline void fwrite_elf_shdr_table	(FILE *, struct Elf_hdr *, struct Elf_shdr_table *);
static inline void fwrite_elf_phdr_table	(FILE *, struct Elf_hdr *, struct Elf_phdr_table *);
static inline void fwrite_elf_sections 		(FILE *, struct Elf_shdr_table *);

void write_modified_new_elf_object_file (FILE *pf, struct Elf_obj *elf_obj) 
{
	fwrite_elf_hdr 		(pf, elf_obj->elf_hdr);
	fwrite_elf_shdr_table 	(pf, elf_obj->elf_hdr, elf_obj->elf_shdr_table);
	fwrite_elf_phdr_table 	(pf, elf_obj->elf_hdr, elf_obj->elf_phdr_table);
	fwrite_elf_sections 	(pf, elf_obj->elf_shdr_table);
}
static inline void fwrite_elf_hdr (FILE *fp, struct Elf_hdr *elf_hdr) 
{
	if (elf_hdr->elf_hdr_t == ELFCLASS32) {
		fwrite (&elf_hdr->elf_hdr.elf32_hdr->e_ident, 16, 1, fp);
		fwrite (&elf_hdr->elf_hdr.elf32_hdr->e_type, 2, 1, fp);
		fwrite (&elf_hdr->elf_hdr.elf32_hdr->e_machine, 2, 1, fp);
		fwrite (&elf_hdr->elf_hdr.elf32_hdr->e_version, 4, 1, fp);
		fwrite (&elf_hdr->elf_hdr.elf32_hdr->e_entry, 4, 1, fp);
		fwrite (&elf_hdr->elf_hdr.elf32_hdr->e_phoff, 4, 1, fp);
		fwrite (&elf_hdr->elf_hdr.elf32_hdr->e_shoff, 4, 1, fp);
		fwrite (&elf_hdr->elf_hdr.elf32_hdr->e_flags, 4, 1, fp);
		fwrite (&elf_hdr->elf_hdr.elf32_hdr->e_ehsize, 2, 1, fp);
		fwrite (&elf_hdr->elf_hdr.elf32_hdr->e_phentsize, 2, 1, fp);
		fwrite (&elf_hdr->elf_hdr.elf32_hdr->e_phnum, 2, 1, fp);
		fwrite (&elf_hdr->elf_hdr.elf32_hdr->e_shentsize, 2, 1, fp);
		fwrite (&elf_hdr->elf_hdr.elf32_hdr->e_shnum, 2, 1, fp);
		fwrite (&elf_hdr->elf_hdr.elf32_hdr->e_shstrndx, 2, 1, fp);

	} else if (elf_hdr->elf_hdr_t == ELFCLASS64) {
		fwrite (&elf_hdr->elf_hdr.elf64_hdr->e_ident, 16, 1, fp);
		fwrite (&elf_hdr->elf_hdr.elf64_hdr->e_type, 2, 1, fp);
		fwrite (&elf_hdr->elf_hdr.elf64_hdr->e_machine, 2, 1, fp);
		fwrite (&elf_hdr->elf_hdr.elf64_hdr->e_version, 4, 1, fp);
		fwrite (&elf_hdr->elf_hdr.elf64_hdr->e_entry, 8, 1, fp);
		fwrite (&elf_hdr->elf_hdr.elf64_hdr->e_phoff, 8, 1, fp);
		fwrite (&elf_hdr->elf_hdr.elf64_hdr->e_shoff, 8, 1, fp);
		fwrite (&elf_hdr->elf_hdr.elf64_hdr->e_flags, 4, 1, fp);
		fwrite (&elf_hdr->elf_hdr.elf64_hdr->e_ehsize, 2, 1, fp);
		fwrite (&elf_hdr->elf_hdr.elf64_hdr->e_phentsize, 2, 1, fp);
		fwrite (&elf_hdr->elf_hdr.elf64_hdr->e_phnum, 2, 1, fp);
		fwrite (&elf_hdr->elf_hdr.elf64_hdr->e_shentsize, 2, 1, fp);
		fwrite (&elf_hdr->elf_hdr.elf64_hdr->e_shnum, 2, 1, fp);
		fwrite (&elf_hdr->elf_hdr.elf64_hdr->e_shstrndx, 2, 1, fp);
	}
}
static inline void fwrite_elf_shdr_table (FILE *fp, struct Elf_hdr *elf_hdr, struct Elf_shdr_table *elf_shdr_table) 
{
	uint16_t i;

	if (elf_shdr_table->elf_shdr_table_t == ELFCLASS32) {
		fseek (fp, elf_hdr->elf_hdr.elf32_hdr->e_shoff, SEEK_SET);
		for (i = 0; i < elf_shdr_table->e_shnum; i++) {
			fwrite (&elf_shdr_table->elf_shdrs.elf32_shdr[i]->sh_name, 4, 1, fp);
			fwrite (&elf_shdr_table->elf_shdrs.elf32_shdr[i]->sh_type, 4, 1, fp);
			fwrite (&elf_shdr_table->elf_shdrs.elf32_shdr[i]->sh_flags, 4, 1, fp);
			fwrite (&elf_shdr_table->elf_shdrs.elf32_shdr[i]->sh_addr, 4, 1, fp);
			fwrite (&elf_shdr_table->elf_shdrs.elf32_shdr[i]->sh_offset, 4, 1, fp);
			fwrite (&elf_shdr_table->elf_shdrs.elf32_shdr[i]->sh_size, 4, 1, fp);
			fwrite (&elf_shdr_table->elf_shdrs.elf32_shdr[i]->sh_link, 4, 1, fp);
			fwrite (&elf_shdr_table->elf_shdrs.elf32_shdr[i]->sh_info, 4, 1, fp);
			fwrite (&elf_shdr_table->elf_shdrs.elf32_shdr[i]->sh_addralign, 4, 1, fp);
			fwrite (&elf_shdr_table->elf_shdrs.elf32_shdr[i]->sh_entsize, 4, 1, fp);
		}
	} else if (elf_shdr_table->elf_shdr_table_t == ELFCLASS64) {
		fseek (fp, elf_hdr->elf_hdr.elf64_hdr->e_shoff, SEEK_SET);
		for (i = 0; i < elf_shdr_table->e_shnum; i++) {
			fwrite (&elf_shdr_table->elf_shdrs.elf64_shdr[i]->sh_name, 4, 1, fp);
			fwrite (&elf_shdr_table->elf_shdrs.elf64_shdr[i]->sh_type, 4, 1, fp);
			fwrite (&elf_shdr_table->elf_shdrs.elf64_shdr[i]->sh_flags, 8, 1, fp);
			fwrite (&elf_shdr_table->elf_shdrs.elf64_shdr[i]->sh_addr, 8, 1, fp);
			fwrite (&elf_shdr_table->elf_shdrs.elf64_shdr[i]->sh_offset, 8, 1, fp);
			fwrite (&elf_shdr_table->elf_shdrs.elf64_shdr[i]->sh_size, 8, 1, fp);
			fwrite (&elf_shdr_table->elf_shdrs.elf64_shdr[i]->sh_link, 4, 1, fp);
			fwrite (&elf_shdr_table->elf_shdrs.elf64_shdr[i]->sh_info, 4, 1, fp);
			fwrite (&elf_shdr_table->elf_shdrs.elf64_shdr[i]->sh_addralign, 8, 1, fp);
			fwrite (&elf_shdr_table->elf_shdrs.elf64_shdr[i]->sh_entsize, 8, 1, fp);
		}
	}
}
static inline void fwrite_elf_phdr_table (FILE *fp, struct Elf_hdr *elf_hdr, struct Elf_phdr_table *elf_phdr_table) 
{
	uint16_t i;

	if (elf_phdr_table->elf_phdr_table_t == ELFCLASS32) {
		fseek (fp, elf_hdr->elf_hdr.elf32_hdr->e_phoff, SEEK_SET);
		for (i = 0; i < elf_phdr_table->e_phnum; i++) {
			fwrite (&elf_phdr_table->elf_phdrs.elf32_phdr[i]->p_type, 4, 1, fp);
			fwrite (&elf_phdr_table->elf_phdrs.elf32_phdr[i]->p_offset, 4, 1, fp);
			fwrite (&elf_phdr_table->elf_phdrs.elf32_phdr[i]->p_vaddr, 4, 1, fp);
			fwrite (&elf_phdr_table->elf_phdrs.elf32_phdr[i]->p_paddr, 4, 1, fp);
			fwrite (&elf_phdr_table->elf_phdrs.elf32_phdr[i]->p_filesz, 4, 1, fp);
			fwrite (&elf_phdr_table->elf_phdrs.elf32_phdr[i]->p_memsz, 4, 1, fp);
			fwrite (&elf_phdr_table->elf_phdrs.elf32_phdr[i]->p_flags, 4, 1, fp); /*posicao diferente do de 64bit*/
			fwrite (&elf_phdr_table->elf_phdrs.elf32_phdr[i]->p_align, 4, 1, fp);
		}
	} else if (elf_phdr_table->elf_phdr_table_t == ELFCLASS64) {
		fseek (fp, elf_hdr->elf_hdr.elf64_hdr->e_phoff, SEEK_SET);
		for (i = 0; i < elf_phdr_table->e_phnum; i++) {
			fwrite (&elf_phdr_table->elf_phdrs.elf64_phdr[i]->p_type, 4, 1, fp);
			fwrite (&elf_phdr_table->elf_phdrs.elf64_phdr[i]->p_flags, 4, 1, fp);
			fwrite (&elf_phdr_table->elf_phdrs.elf64_phdr[i]->p_offset, 8, 1, fp);
			fwrite (&elf_phdr_table->elf_phdrs.elf64_phdr[i]->p_vaddr, 8, 1, fp);
			fwrite (&elf_phdr_table->elf_phdrs.elf64_phdr[i]->p_paddr, 8, 1, fp);
			fwrite (&elf_phdr_table->elf_phdrs.elf64_phdr[i]->p_filesz, 8, 1, fp);
			fwrite (&elf_phdr_table->elf_phdrs.elf64_phdr[i]->p_memsz, 8, 1, fp);
			fwrite (&elf_phdr_table->elf_phdrs.elf64_phdr[i]->p_align, 8, 1, fp);
		}
	}
}
static inline void fwrite_elf_sections (FILE *fp, struct Elf_shdr_table *elf_shdr_table) 
{
	uint16_t i;

	if (elf_shdr_table->elf_shdr_table_t == ELFCLASS32) {
		for (i = 0; i < elf_shdr_table->e_shnum; i++) {
			fseek (fp, elf_shdr_table->elf_shdrs.elf32_shdr[i]->sh_offset, SEEK_SET);
			fwrite (elf_shdr_table->elf_shdrs.elf32_shdr[i]->section, elf_shdr_table->elf_shdrs.elf32_shdr[i]->sh_size, 1, fp);
		}
	} else if (elf_shdr_table->elf_shdr_table_t == ELFCLASS64) {
		for (i = 0; i < elf_shdr_table->e_shnum; i++) {
			fseek (fp, elf_shdr_table->elf_shdrs.elf64_shdr[i]->sh_offset, SEEK_SET);
			fwrite (elf_shdr_table->elf_shdrs.elf64_shdr[i]->section, elf_shdr_table->elf_shdrs.elf64_shdr[i]->sh_size, 1, fp);
		}
	}
}

uint8_t *get_elf_shdr_section_by_name (uint8_t *shdr_name, const struct Elf_shdr_table *elf_shdr_table) 
{
	uint16_t i;
	uint8_t *section;

	if (elf_shdr_table->elf_shdr_table_t == ELFCLASS32) {
		for (i = 0; i < elf_shdr_table->e_shnum; i++) {
			if ( !strcmp ((char *)elf_shdr_table->elf_shdrs.elf32_shdr[i]->name, (char *)shdr_name ) ) {
				section = elf_shdr_table->elf_shdrs.elf64_shdr[i]->section;
				i = elf_shdr_table->e_shnum;
			}
		}
	} else if (elf_shdr_table->elf_shdr_table_t == ELFCLASS64) {
		for (i = 0; i < elf_shdr_table->e_shnum; i++) {
			if ( !strcmp ((char *)elf_shdr_table->elf_shdrs.elf64_shdr[i]->name, (char *)shdr_name ) ) {
				section = elf_shdr_table->elf_shdrs.elf64_shdr[i]->section;
				i = elf_shdr_table->e_shnum;
			}
		}
	}

	return section;
}
union Elf_shdrs *get_elf_shdr_by_name (uint8_t *shdr_name, const struct Elf_shdr_table *elf_shdr_table) 
{
	union Elf_shdrs *to_return_shdr = NULL;
	uint16_t i;

	if (elf_shdr_table->elf_shdr_table_t == ELFCLASS32) {
		for (i = 0; i < elf_shdr_table->e_shnum; i++) {
			if ( !strcmp ((char *)elf_shdr_table->elf_shdrs.elf32_shdr[i]->name, (char *)shdr_name ) ) {
				to_return_shdr = malloc (sizeof (union Elf_shdrs));
				to_return_shdr->elf32_shdr = malloc (sizeof (struct Elf32_Shdr *));
				to_return_shdr->elf32_shdr[0] = elf_shdr_table->elf_shdrs.elf32_shdr[i];
				i = elf_shdr_table->e_shnum;
			}
		}
	} else if (elf_shdr_table->elf_shdr_table_t == ELFCLASS64) {
		for (i = 0; i < elf_shdr_table->e_shnum; i++) {
			if ( !strcmp ((char *)elf_shdr_table->elf_shdrs.elf64_shdr[i]->name, (char *)shdr_name ) ) {
				to_return_shdr = malloc ( sizeof (union Elf_shdrs) );
				to_return_shdr->elf64_shdr = malloc (sizeof (struct Elf64_Shdr *));
				to_return_shdr->elf64_shdr[0] = elf_shdr_table->elf_shdrs.elf64_shdr[i];
				i = elf_shdr_table->e_shnum;
			}
		}
	}
	return to_return_shdr;
}
uint16_t get_elf_shdr_ndx_by_name (uint8_t *shdr_name, const struct Elf_shdr_table *elf_shdr_table) 
{
	uint16_t ndx;
	uint16_t i;

	if (elf_shdr_table->elf_shdr_table_t == ELFCLASS32) {
		for (i = 0; i < elf_shdr_table->e_shnum; i++) {
			if ( !strcmp ((char *)elf_shdr_table->elf_shdrs.elf32_shdr[i]->name, (char *)shdr_name ) ) {
				ndx = i;
				i = elf_shdr_table->e_shnum;
			}	
		}
	} else if (elf_shdr_table->elf_shdr_table_t == ELFCLASS64) {
		for (i = 0; i < elf_shdr_table->e_shnum; i++) {
			if ( !strcmp ((char *)elf_shdr_table->elf_shdrs.elf64_shdr[i]->name, (char *)shdr_name ) ) {
				ndx = i;
				i = elf_shdr_table->e_shnum;
			}
		}
	}

	return ndx;
}

void update_elf_hdr 		(struct Elf_obj *, uint64_t, uint64_t, uint16_t, uint8_t);
void update_elf_shdr_table 	(struct Elf_shdr_table *, uint64_t, uint64_t, uint16_t, union Elf_shdrs *, uint8_t);
void update_elf_phdr_table 	(struct Elf_phdr_table *, uint64_t, uint64_t, uint64_t, uint64_t, uint8_t);

void remove_elf_shdr_by_name (uint8_t *shdr_name, struct Elf_obj *elf_obj) 
{
	uint16_t ndx;
	ndx = get_elf_shdr_ndx_by_name (shdr_name, elf_obj->elf_shdr_table);

	if (elf_obj->elf_obj_t == ELFCLASS32) {
		uint32_t sh_size = elf_obj->elf_shdr_table->elf_shdrs.elf32_shdr[ndx]->sh_size;
		uint32_t sh_offset = elf_obj->elf_shdr_table->elf_shdrs.elf32_shdr[ndx]->sh_offset;
		uint16_t e_shentsize = elf_obj->elf_hdr->elf_hdr.elf32_hdr->e_shentsize;
		uint32_t e_shoff = elf_obj->elf_hdr->elf_hdr.elf32_hdr->e_shoff;

		update_elf_hdr (elf_obj, sh_size, sh_offset, ndx, REMOVE_TYPE);
		update_elf_shdr_table (elf_obj->elf_shdr_table, sh_size, sh_offset, ndx, NULL, REMOVE_TYPE);
		update_elf_phdr_table (elf_obj->elf_phdr_table, sh_size, e_shentsize, e_shoff, sh_offset, REMOVE_TYPE);

	} else if (elf_obj->elf_obj_t == ELFCLASS64) {
		uint64_t sh_size = elf_obj->elf_shdr_table->elf_shdrs.elf64_shdr[ndx]->sh_size;
		uint64_t sh_offset = elf_obj->elf_shdr_table->elf_shdrs.elf64_shdr[ndx]->sh_offset;
		uint16_t e_shentsize = elf_obj->elf_hdr->elf_hdr.elf64_hdr->e_shentsize;
		uint64_t e_shoff = elf_obj->elf_hdr->elf_hdr.elf64_hdr->e_shoff;

		update_elf_hdr (elf_obj, sh_size, sh_offset, ndx, REMOVE_TYPE);
		update_elf_shdr_table (elf_obj->elf_shdr_table, sh_size, sh_offset, ndx, NULL, REMOVE_TYPE);
		update_elf_phdr_table (elf_obj->elf_phdr_table, sh_size, e_shentsize, e_shoff, sh_offset, REMOVE_TYPE);
	}
}
void insert_elf_shdr_by_ndx (uint16_t ndx, struct Elf_obj *elf_obj, union Elf_shdrs *elf_shdr) 
{
	if (elf_obj->elf_obj_t == ELFCLASS32) {
		uint32_t sh_size = elf_shdr->elf32_shdr[0]->sh_size;
		uint32_t sh_offset = elf_shdr->elf32_shdr[0]->sh_offset;
		uint16_t e_shentsize = elf_obj->elf_hdr->elf_hdr.elf32_hdr->e_shentsize;
		uint32_t e_shoff = elf_obj->elf_hdr->elf_hdr.elf32_hdr->e_shoff;

		update_elf_hdr 		(elf_obj, sh_size, sh_offset, ndx, INSERT_TYPE);
		update_elf_shdr_table 	(elf_obj->elf_shdr_table, sh_size, sh_offset, ndx, elf_shdr, INSERT_TYPE);
		update_elf_phdr_table 	(elf_obj->elf_phdr_table, sh_size, e_shentsize, e_shoff, sh_offset, INSERT_TYPE);

	} else if (elf_obj->elf_obj_t == ELFCLASS64) {
		uint32_t sh_size = elf_shdr->elf64_shdr[0]->sh_size;
		uint32_t sh_offset = elf_shdr->elf64_shdr[0]->sh_offset;
		uint16_t e_shentsize = elf_obj->elf_hdr->elf_hdr.elf64_hdr->e_shentsize;
		uint32_t e_shoff = elf_obj->elf_hdr->elf_hdr.elf64_hdr->e_shoff;

		update_elf_hdr 		(elf_obj, sh_size, sh_offset, ndx, INSERT_TYPE);
		update_elf_shdr_table 	(elf_obj->elf_shdr_table, sh_size, sh_offset, ndx, elf_shdr, INSERT_TYPE);
		update_elf_phdr_table 	(elf_obj->elf_phdr_table, sh_size, e_shentsize, e_shoff, sh_offset, INSERT_TYPE);
	}
}
void update_elf_hdr (struct Elf_obj *elf_obj, uint64_t sh_size, uint64_t sh_offset, uint16_t ndx, uint8_t updt_t) 
{
	if (elf_obj->elf_obj_t == ELFCLASS32) {
		if (elf_obj->elf_hdr->elf_hdr.elf32_hdr->e_phoff > elf_obj->elf_hdr->elf_hdr.elf32_hdr->e_shoff) {
			if (updt_t == REMOVE_TYPE) 
				elf_obj->elf_hdr->elf_hdr.elf32_hdr->e_phoff -= elf_obj->elf_hdr->elf_hdr.elf32_hdr->e_shentsize;
			else if (updt_t == INSERT_TYPE) 
				elf_obj->elf_hdr->elf_hdr.elf32_hdr->e_phoff += elf_obj->elf_hdr->elf_hdr.elf32_hdr->e_shentsize;
		}
		if (elf_obj->elf_hdr->elf_hdr.elf32_hdr->e_phoff > sh_offset) {
			if (updt_t == REMOVE_TYPE)
				elf_obj->elf_hdr->elf_hdr.elf32_hdr->e_phoff -= sh_size;
			else if (updt_t == INSERT_TYPE) 
				elf_obj->elf_hdr->elf_hdr.elf32_hdr->e_phoff += sh_size;
		}
		if (elf_obj->elf_hdr->elf_hdr.elf32_hdr->e_shoff > sh_offset) {
			if (updt_t == REMOVE_TYPE)
				elf_obj->elf_hdr->elf_hdr.elf32_hdr->e_shoff -= sh_size;
			else if (updt_t == INSERT_TYPE) 
				elf_obj->elf_hdr->elf_hdr.elf32_hdr->e_shoff += sh_size;
		}
		if (elf_obj->elf_hdr->elf_hdr.elf32_hdr->e_shstrndx > ndx) {
			if (updt_t == REMOVE_TYPE)
				elf_obj->elf_hdr->elf_hdr.elf32_hdr->e_shstrndx--;
			else if (updt_t == INSERT_TYPE) 
				elf_obj->elf_hdr->elf_hdr.elf32_hdr->e_shstrndx++;
		} 
		else if (elf_obj->elf_hdr->elf_hdr.elf32_hdr->e_shstrndx == ndx) {
			elf_obj->elf_hdr->elf_hdr.elf32_hdr->e_shstrndx = 0;
		}
		if (updt_t == REMOVE_TYPE) 
			elf_obj->elf_hdr->elf_hdr.elf32_hdr->e_shnum--;
		else if (updt_t == INSERT_TYPE)
			elf_obj->elf_hdr->elf_hdr.elf32_hdr->e_shnum++;
	} 
	else if(elf_obj->elf_obj_t == ELFCLASS64) {
		/*Faz o update do offset do phtable baseado no tamanho do cabeçalho de uma seção*/
		if (elf_obj->elf_hdr->elf_hdr.elf64_hdr->e_phoff > elf_obj->elf_hdr->elf_hdr.elf64_hdr->e_shoff) {
			if (updt_t == REMOVE_TYPE) 
				elf_obj->elf_hdr->elf_hdr.elf64_hdr->e_phoff -= elf_obj->elf_hdr->elf_hdr.elf64_hdr->e_shentsize;
			else if (updt_t == INSERT_TYPE) 
				elf_obj->elf_hdr->elf_hdr.elf64_hdr->e_phoff += elf_obj->elf_hdr->elf_hdr.elf64_hdr->e_shentsize;
		}
		/*Faz o update do offset do phtable baseado no tamanho da seção*/
		if (elf_obj->elf_hdr->elf_hdr.elf64_hdr->e_phoff > sh_offset) {
			if (updt_t == REMOVE_TYPE) 
				elf_obj->elf_hdr->elf_hdr.elf64_hdr->e_phoff -= sh_size;
			else if (updt_t == INSERT_TYPE) 
				elf_obj->elf_hdr->elf_hdr.elf64_hdr->e_phoff += sh_size;
		}
		/*Faz o update do offset do shtable baseado no tamanho da seção*/
		if (elf_obj->elf_hdr->elf_hdr.elf64_hdr->e_shoff > sh_offset) {
			if (updt_t == REMOVE_TYPE) 
				elf_obj->elf_hdr->elf_hdr.elf64_hdr->e_shoff -= sh_size;
			else if (updt_t == INSERT_TYPE) 
				elf_obj->elf_hdr->elf_hdr.elf64_hdr->e_shoff += sh_size;
		}
		/*Faz o update do indice da string table*/
		if (elf_obj->elf_hdr->elf_hdr.elf64_hdr->e_shstrndx > ndx) {
			if (updt_t == REMOVE_TYPE) 
				elf_obj->elf_hdr->elf_hdr.elf64_hdr->e_shstrndx--;
			else if (updt_t == INSERT_TYPE) 
				elf_obj->elf_hdr->elf_hdr.elf64_hdr->e_shstrndx++;
		} 
		else if (elf_obj->elf_hdr->elf_hdr.elf64_hdr->e_shstrndx == ndx) {
			elf_obj->elf_hdr->elf_hdr.elf64_hdr->e_shstrndx = 0;
		}
		/*Diminui o numero de seções*/ /*preciso diminuir na struct de shtable*/
		if (updt_t == REMOVE_TYPE)
			elf_obj->elf_hdr->elf_hdr.elf64_hdr->e_shnum--;
		else if (updt_t == INSERT_TYPE)
			elf_obj->elf_hdr->elf_hdr.elf64_hdr->e_shnum++;
	}
}
void rm_elf_shdr_from_table (struct Elf_shdr_table *, uint16_t);
void insert_elf_shdr_in_table (struct Elf_shdr_table *, uint16_t, union Elf_shdrs *);
void update_elf_shdr_table (struct Elf_shdr_table *elf_shdr_table, uint64_t sh_size, uint64_t sh_offset, uint16_t ndx, union Elf_shdrs *elf_shdr, uint8_t updt_t) 
{
	uint16_t i;

	if (elf_shdr_table->elf_shdr_table_t == ELFCLASS32) {
		for (i = 0; i < elf_shdr_table->e_shnum; i++) {
			if (elf_shdr_table->elf_shdrs.elf32_shdr[i]->sh_offset > sh_offset) {
				if (updt_t == REMOVE_TYPE) {
					elf_shdr_table->elf_shdrs.elf32_shdr[i]->sh_offset -= sh_size;
					if ( elf_shdr_table->elf_shdrs.elf32_shdr[i]->sh_addr != 0 )
						elf_shdr_table->elf_shdrs.elf32_shdr[i]->sh_addr -= sh_size;
				}
				else if (updt_t == INSERT_TYPE) {
					elf_shdr_table->elf_shdrs.elf32_shdr[i]->sh_offset += sh_size;
					if ( elf_shdr_table->elf_shdrs.elf32_shdr[i]->sh_addr != 0 )
						elf_shdr_table->elf_shdrs.elf32_shdr[i]->sh_addr += sh_size;
				}
			}
		}
	} 
	/*Faz o update do offset de cada seção descrito no cabeçalho de cada seção baseado no tamanho da seção*/
	else if (elf_shdr_table->elf_shdr_table_t == ELFCLASS64) {
		for (i = 0; i < elf_shdr_table->e_shnum; i++) {
			if (elf_shdr_table->elf_shdrs.elf64_shdr[i]->sh_offset > sh_offset) {
				if (updt_t == REMOVE_TYPE) {
					elf_shdr_table->elf_shdrs.elf64_shdr[i]->sh_offset -= sh_size;
					if (elf_shdr_table->elf_shdrs.elf64_shdr[i]->sh_addr != 0)
						elf_shdr_table->elf_shdrs.elf64_shdr[i]->sh_addr -= sh_size;
				}
				else if (updt_t == INSERT_TYPE) {
					elf_shdr_table->elf_shdrs.elf64_shdr[i]->sh_offset += sh_size;
					if (elf_shdr_table->elf_shdrs.elf64_shdr[i]->sh_addr != 0)
						elf_shdr_table->elf_shdrs.elf64_shdr[i]->sh_addr += sh_size;
				}
			}
		}
	}
	if (updt_t == REMOVE_TYPE) 
		rm_elf_shdr_from_table (elf_shdr_table, ndx);
	else if (updt_t == INSERT_TYPE)
		insert_elf_shdr_in_table (elf_shdr_table, ndx, elf_shdr);
}
void rm_elf_shdr_from_table (struct Elf_shdr_table *elf_shdr_table, uint16_t ndx) 
{
	uint16_t i;

	if (elf_shdr_table->elf_shdr_table_t == ELFCLASS32) {
		struct Elf32_Shdr *elf_shdr_to_free = elf_shdr_table->elf_shdrs.elf32_shdr[ndx];
		for (i = ndx; i < elf_shdr_table->e_shnum-1; i++) {
			elf_shdr_table->elf_shdrs.elf32_shdr[i] = elf_shdr_table->elf_shdrs.elf32_shdr[i+1];
		}
		free (elf_shdr_to_free->name);
		free (elf_shdr_to_free->section);
		free (elf_shdr_to_free);
	} 
	else if (elf_shdr_table->elf_shdr_table_t == ELFCLASS64) {
		struct Elf64_Shdr *elf_shdr_to_free = elf_shdr_table->elf_shdrs.elf64_shdr[ndx];
		for (i = ndx; i < elf_shdr_table->e_shnum-1; i++) {
			elf_shdr_table->elf_shdrs.elf64_shdr[i] = elf_shdr_table->elf_shdrs.elf64_shdr[i+1];
		}
		free (elf_shdr_to_free->name);
		free (elf_shdr_to_free->section);
		free (elf_shdr_to_free);
	}
	elf_shdr_table->e_shnum--;
}
void insert_elf_shdr_in_table (struct Elf_shdr_table *elf_shdr_table, uint16_t ndx, union Elf_shdrs *elf_shdr)
{
	uint16_t i;

	if (elf_shdr_table->elf_shdr_table_t == ELFCLASS32) {
		elf_shdr_table->elf_shdrs.elf32_shdr = realloc (elf_shdr_table->elf_shdrs.elf32_shdr, (elf_shdr_table->e_shnum+1)*sizeof(struct Elf32_Shdr *));
		for (i = elf_shdr_table->e_shnum; i > ndx; i--) {
			elf_shdr_table->elf_shdrs.elf32_shdr[i] = elf_shdr_table->elf_shdrs.elf32_shdr[i-1];
		}
		elf_shdr_table->elf_shdrs.elf32_shdr[ndx] = elf_shdr->elf32_shdr[0];
	} 
	else if (elf_shdr_table->elf_shdr_table_t == ELFCLASS64) {
		elf_shdr_table->elf_shdrs.elf64_shdr = realloc (elf_shdr_table->elf_shdrs.elf64_shdr, (elf_shdr_table->e_shnum+1)*sizeof(struct Elf64_Shdr *));
		for (i = elf_shdr_table->e_shnum; i > ndx; i--) {
			elf_shdr_table->elf_shdrs.elf64_shdr[i] = elf_shdr_table->elf_shdrs.elf64_shdr[i-1];
		}
		elf_shdr_table->elf_shdrs.elf64_shdr[ndx] = elf_shdr->elf64_shdr[0];
	}
	elf_shdr_table->e_shnum++;
}
void update_elf_phdr_table (struct Elf_phdr_table *elf_phdr_table, uint64_t sh_size, uint64_t sh_entsize, uint64_t e_shoff, uint64_t sh_offset, uint8_t updt_t) 
{
	uint16_t i;

	if (elf_phdr_table->elf_phdr_table_t == ELFCLASS32) {
		for (i = 0; i < elf_phdr_table->e_phnum; i++) {
			if (elf_phdr_table->elf_phdrs.elf32_phdr[i]->p_offset > sh_offset) {
				if (updt_t == REMOVE_TYPE) 
					elf_phdr_table->elf_phdrs.elf32_phdr[i]->p_offset -= sh_size;
				else if (updt_t == INSERT_TYPE) 
					elf_phdr_table->elf_phdrs.elf32_phdr[i]->p_offset += sh_size;
			}
			if (elf_phdr_table->elf_phdrs.elf32_phdr[i]->p_offset > e_shoff) {
				if (updt_t == REMOVE_TYPE)
					elf_phdr_table->elf_phdrs.elf32_phdr[i]->p_offset -= sh_entsize;
				if (updt_t == INSERT_TYPE)
					elf_phdr_table->elf_phdrs.elf32_phdr[i]->p_offset += sh_entsize;
			}
		}
	} else if (elf_phdr_table->elf_phdr_table_t == ELFCLASS64) {
		for (i = 0; i < elf_phdr_table->e_phnum; i++) {
			if (elf_phdr_table->elf_phdrs.elf64_phdr[i]->p_offset > sh_offset) {
				if (updt_t == REMOVE_TYPE) 
					elf_phdr_table->elf_phdrs.elf64_phdr[i]->p_offset -= sh_size;
				else if (updt_t == INSERT_TYPE) 
					elf_phdr_table->elf_phdrs.elf64_phdr[i]->p_offset += sh_size;
			}
			if (elf_phdr_table->elf_phdrs.elf64_phdr[i]->p_offset > e_shoff) {
				if (updt_t == REMOVE_TYPE)
					elf_phdr_table->elf_phdrs.elf64_phdr[i]->p_offset -= sh_entsize;
				if (updt_t == INSERT_TYPE)
					elf_phdr_table->elf_phdrs.elf64_phdr[i]->p_offset += sh_entsize;
			}
		}
	}
}
