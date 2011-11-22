#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define MAX_INPUT 50
#define FBUFFER_SIZE 10000
#define MEM_SIZE 1<<16
#define TABLE_SIZE 500

#define USER_CODE 0x0000
#define USER_DATA 0x2000
#define OS_CODE 0x8000
#define OS_DATA 0xA000
#define PRIV (((PSR) >> 15) & 0x1)

#define DEC(x) (((x.B.h)*256) + (x.B.l))
#define FLIP(x) (((x) << 8) | ((x) >> 8))

#define OP(x) ((x) >> 12)
#define SUBOP(x) (((x) >> 3) & 0x7)
#define D_REG(x) (((x) >> 9) & 0x7)
#define S_REG(x) (((x) >> 6) & 0x7)
#define T_REG(x) ((x) & 0x7)

unsigned short MEM[MEM_SIZE];
unsigned char BRK[MEM_SIZE];
unsigned short PC = 0x8200;
unsigned short PSR = 0x8002;
unsigned short CC = 'Z';
signed short R0, R1, R2, R3, R4, R5, R6, R7;
signed short* REGS[] = {&R0, &R1, &R2, &R3, &R4, &R5, &R6, &R7};

typedef union {
	unsigned short W;
	struct { unsigned char l, h; } B;
} Word;

typedef struct {
		unsigned char s[50];
		unsigned short val;
} Symbol;
	
Symbol table[TABLE_SIZE];
int num_symbols=0;

struct { unsigned short x:4; } SEXT_4U;
struct { signed short x:5; } SEXT_5;
struct { signed short x:6; } SEXT_6;
struct { signed short x:7; } SEXT_7;
struct { unsigned short x:7; } SEXT_7U;
struct { unsigned short x:8; } SEXT_8U;
struct { signed short x:9; } SEXT_9;
struct { signed short x:11; } SEXT_11;

typedef void (*CPUInstructionHandler)(void);

int parse_command();
void print();
void reset();
void load(char *c);
void set(char *c);
void break_sc(char *c);
void step();
void contin();
void script(char *c);


void load_code(char* file);
void execute();

void nop();
void add();
void mul();
void sub();
void divi();
void add_im();

void brn();
void brnz();
void brnp();
void brz();
void brzp();
void brp();
void brnzp();

void cmp();
void cmpu();
void cmpi();
void cmpiu();

void jsr();
void jsrr();

void and();
void not();
void or();
void xor();
void and_im();

void ldr();
void str();

void rti();

void cons();

void sll();
void sra();
void srl();
void mod();

void jmpr();
void jmp();

void hiconst();

void trap();

CPUInstructionHandler jumpTable[0xFF] = {NULL};
void initialize() {

		/* NOP */
		jumpTable[0x00] = &nop;

		/* Arithmetic */
		jumpTable[0x10] = &add;
		jumpTable[0x12] = &mul;
		jumpTable[0x14] = &sub;
		jumpTable[0x16] = &divi;
		jumpTable[0x18] = &add_im;

		/* Compares */
		jumpTable[0x20] = &cmp;
		jumpTable[0x24] = &cmpu;
		jumpTable[0x28] = &cmpi;
		jumpTable[0x2C] = &cmpiu;

		/* Logic */
		jumpTable[0x50] = &and;
		jumpTable[0x52] = &not;
		jumpTable[0x54] = &or;
		jumpTable[0x56] = &xor;
		jumpTable[0x58] = &and_im;

		/* Shifts */
		jumpTable[0xA0] = &sll;
		jumpTable[0xA4] = &sra;
		jumpTable[0xA8] = &srl;
		jumpTable[0xAC] = &mod;

		/* Data */
		jumpTable[0x60] = &ldr;
		jumpTable[0x70] = &str;

		/* Constants */
		jumpTable[0x90] = &cons;
		jumpTable[0xD0] = &hiconst;

		/* Conditionals */
		jumpTable[0x08] = &brn;
		jumpTable[0x0C] = &brnz;
		jumpTable[0x0A] = &brnp;
		jumpTable[0x04] = &brz;
		jumpTable[0x06] = &brzp;
		jumpTable[0x02] = &brp;
		jumpTable[0x0E] = &brnzp;

		/* Jumps */
		jumpTable[0x48] = &jsr;
		jumpTable[0x40] = &jsrr;
		jumpTable[0xC0] = &jmpr;
		jumpTable[0xC8] = &jmp;

		jumpTable[0x80] = &rti;
		jumpTable[0xF0] = &trap;

}



int main(int argc, char** argv) {
	char *input = (char *)malloc(MAX_INPUT * sizeof(char));
	int i, command;

	initialize();
	for(;;) {

		fputs("Enter a command: ", stdout);
		fflush(stdout);
		fgets(input, MAX_INPUT, stdin);
		//printf("You entered: %s", input);

		// strip trailing newline
		if(input[strlen(input)-1] == '\n')
			input[strlen(input)-1] = '\0';

		command = parse_command(input);
		switch(command) {
			case 1: reset(); break;
			case 2: load(input); break;
			case 3: set(input); break;
			case 4: break_sc(input); break;
			case 5: step(); break;
			case 6: contin(); break;
			case 7: print(); break;
			case 8: script(input); break;
			case 9: return 1;
			default:
				printf("Unknown command: %s\n", input);
				break;
		}
	
	}
}

signed int lookup(char* symbol) {
	int i;
	for(i=0;i<num_symbols;i++)
		if(!strcmp(symbol, table[i].s))
			return table[i].val;
	return -1;
}

int parse_command(char* input) {
		if(!strcmp("quit",input)) return 9;
		else if(!strcmp("print", input)) return 7;
		else if(!strcmp("reset", input)) return 1;
		else if(!strncmp("load ", input, 5)) return 2;
		else if(!strncmp("set ", input, 4)) return 3;
		else if(!strncmp("break ", input, 6)) return 4;
		else if(!strncmp("script ", input, 7)) return 8;
		else if(!strcmp("step", input)) return 5;
		else if(!strcmp("continue", input)) return 6;
		else return 0;
}

void reset() {
	int i;
	PC = 0x8200;
	PSR = 0x8002;
	CC = 'Z';
	R0 = R1 = R2 = R3 = R4 = R5 = R6 = R7 = 0;
	for(i=0;i<MEM_SIZE;i++) {
		MEM[i] = 0;
		BRK[i] = 0;
	}
	num_symbols = 0;

	printf("System reset.\n");
}

void load(char *input) {
	char *p = strtok(input, " ");
	p = strtok(NULL, " ");
	strcat(p, ".obj");
	printf("Loading %s into memory...", p);
	load_code(p);
}

void set(char *input) {
	char *tmp = input;
	char com[50], reg[10], val[20];
	int i, addr;
	signed short v;

	sscanf(tmp, "%s%n", com, &i);
	tmp += i;
	sscanf(tmp, "%s%n", reg, &i);
	tmp += i;
	sscanf(tmp, "%s%n", val, &i);
	tmp += i;
	if(sscanf(tmp, "%s%n", com, &i) == 1 | strlen(reg) != 2) {
		printf("Unknown command: %s\n", input);
		return;
	}

	if(!strcmp("PC", reg)) {
		addr = lookup(val);
		if(addr != -1) {
				PC = addr;
				printf("Register PC updated to value x%04X\n", addr);
				return;
		}
	}

	if(val[0] == 'x') {
		if(sscanf(val, "x%hx%n", &v, &i) != 1 || i != strlen(val)) {
			printf("Unknown command: %s\n", input);
			return;
		}
	}
	else
		v = (signed short)(strtol(val, NULL, 0));

	if(errno) {
		printf("Invalid value: %s\n", val);
		errno = 0;
		return;
	}

	if(!strcmp("PC", reg)) {
			PC = v;
			printf("Register PC updated to value x%04hX\n", v);
	}
	else {
		i = atoi(reg+1);
		if(errno) {
			printf("Invalid register: %s\n", reg);
			errno = 0;
			return;
		}
		if(reg[0] != 'R' || i < 0 || i > 7) {
			printf("Invalid register: %s\n", reg);
			return;
		}
		*REGS[i] = v;
		printf("Register R%d updated to value x%04hX\n", i, v);
	}
			//printf("%d %04X\n", i, v);
}

void break_sc(char *input) {
	int i;
	unsigned int addr;
	char tmp[30];
	unsigned char flag;

	strcpy(tmp, input);
	char *p = strtok(tmp," ");
	p = strtok(NULL, " ");
	//p = strtok(NULL, " ");
	if(!strcmp("set", p)) flag = 1;
	else if(!strcmp("clear", p)) flag = 0;
	else {
		printf("Unknown command: %s\n", input);
		return;
	}

	p = strtok(NULL, " ");
	if(p[0] == 'x') {
		if(sscanf(p, "x%x%n", &addr, &i) != 1 || i != strlen(p)) {
			printf("Unknown command: %s\n", input);
			return;
		}
	}
	else {
		addr = lookup(p);
		if(addr == -1) {
			printf("Invalid address: %s\n", p);
			return;
		}
	}

	if(addr > 0xFFFF) {
		printf("Invalid address: %s\n", p);
		return;
	}

	BRK[addr] = flag;
	printf("Breakpoint %s at x%04X\n", flag?"set":"cleared", addr);
}

void step() {
	if((USER_DATA <= PC&&PC < OS_CODE) || (PC >= OS_DATA) || (OS_CODE <= PC&&PC < OS_DATA && !PRIV))
		printf("IllegalInstructionException: Attempting to execute an instruction outside code segment!\n");
	else {
		execute();
		if(BRK[PC])
			printf("Hit breakpoint at x%04X\n", PC);
	}
	/*if(PC <= 0x1FFF) {
		execute();
		if(BRK[PC])
			printf("Hit breakpoint at x%04X\n", PC);
	}
	else
		printf("IllegalInstructionException: Attempting to execute an instruction outside code segment!\n");
*/
}

void contin() {
	while(1) {
		if((USER_DATA <= PC&&PC < OS_CODE) || (PC >= OS_DATA) || (OS_CODE <= PC&&PC < OS_DATA && !PRIV)) {
			printf("IllegalInstructionException: Attempting to execute an instruction outside code segment!\n");
			return;
		}
		else {
			execute();
			if(BRK[PC]) {
				printf("Hit breakpoint at x%04X\n", PC);
				return;
			}
		}
	}
}

void print() {
	printf("[R0: x%04hX,R1: x%04hX,R2: x%04hX,R3: x%04hX,R4: x%04hX,R5: x%04hX,R6: x%04hX,R7: x%04hX]\n", 
						R0, R1, R2, R3, R4, R5, R6, R7); 
	printf("PC = x%04hX\n", PC);
	printf("PSR = x%04hX\n", PSR);
	printf("CC = %c\n", CC);
}

void script(char *input) {
	char buf[MAX_INPUT];
	int command;

	FILE *fin = fopen(input+7, "r");
	if(fin == NULL) {
		printf("Invalid script file: %s\n", input+7);
		return;
	}
	while(fgets(buf, 50, fin) != NULL) {
		if(buf[strlen(buf)-1] == '\n')
			buf[strlen(buf)-1] = '\0';
		command = parse_command(buf);
		switch(command) {
			case 1: reset(); break;
			case 2: load(buf); break;
			case 3: set(buf); break;
			case 4: break_sc(buf); break;
			case 5: step(); break;
			case 6: contin(); break;
			case 7: print(); break;
			case 9: return;
			default:
				printf("Invalid command: %s\n", buf);
				break;
		}
	}
	fclose(fin);
}

void execute() {
	unsigned short op = MEM[PC];
	unsigned short opcode = OP(op);

	// generate unique opcodes
	switch(opcode) {
		case 0x1: // arithmetic
			if((op >> 5) & 0x1)
					opcode = (opcode << 4) | (1 << 3);
			else
					opcode = (opcode << 4) | SUBOP(op) << 1;
			break;
		case 0x5: // logic
			if((op >> 5) & 0x1)
					opcode = (opcode << 4) | (1 << 3);
			else
					opcode = (opcode << 4) | SUBOP(op) << 1;
			break;
		case 0xA: // shifts
			opcode = (opcode << 4) | (((op >> 4) & 0x3) << 2);
			break;
		case 0x2: // compares
			opcode = (opcode << 4) | (((op >> 7) & 0x3) << 2);
			break;
		case 0x0: // conditionals
			opcode = ((op >> 9) & 0x7F) << 1;
			break;
		case 0x4: // jump subroutine
			opcode = ((op >> 11) & 0x1F) << 3;
			break;
		case 0xC: // jump and jumpr
			opcode = ((op >> 11) & 0x1F) << 3;
			break;
		default: opcode = opcode << 4; break; // everything else
	}

	//printf("OP: %04X, OPCODE: %04X\n", op, opcode);

	jumpTable[opcode]();
}

void nop() { PC++; }

void set_nzp(signed short v) {
		unsigned char N, Z, P;
		N = (v < 0);
		Z = (v == 0);
		P = (v > 0);
		PSR ^= ((PSR ^ ((N << 2) | (Z << 1) | P)) & 0x7);
		CC = N ? ('N') : (Z ? ('Z') : ('P'));
}
void set_nzpu(unsigned short v) {
		unsigned char N, Z, P;
		N = 0;
		Z = (v == 0);
		P = (v > 0);
		PSR ^= ((PSR ^ ((N << 2) | (Z << 1) | P)) & 0x7);
		CC = N ? ('N') : (Z ? ('Z') : ('P'));
}

void add() {
		unsigned short op = MEM[PC];
		unsigned short Rd = D_REG(op);
		unsigned short Rs = S_REG(op);
		unsigned short Rt = T_REG(op);
		//printf("Rd = %04X, Rs = %04X, Rt = %04X\n", Rd, Rs, Rt);

		*REGS[Rd] = (*REGS[Rs]) + (*REGS[Rt]);
		set_nzp(*REGS[Rd]);
		PC++;
}
void mul() {
		unsigned short op = MEM[PC];
		unsigned short Rd = D_REG(op);
		unsigned short Rs = S_REG(op);
		unsigned short Rt = T_REG(op);
		//printf("Rd = %04X, Rs = %04X, Rt = %04X\n", Rd, Rs, Rt);

		*REGS[Rd] = (*REGS[Rs]) * (*REGS[Rt]);
		set_nzp(*REGS[Rd]);
		PC++;
}
void sub() {
		unsigned short op = MEM[PC];
		unsigned short Rd = D_REG(op);
		unsigned short Rs = S_REG(op);
		unsigned short Rt = T_REG(op);
		//printf("Rd = %04X, Rs = %04X, Rt = %04X\n", Rd, Rs, Rt);

		*REGS[Rd] = (*REGS[Rs]) - (*REGS[Rt]);
		set_nzp(*REGS[Rd]);
		PC++;
}
void divi() {
		unsigned short op = MEM[PC];
		unsigned short Rd = D_REG(op);
		unsigned short Rs = S_REG(op);
		unsigned short Rt = T_REG(op);
		//printf("Rd = %04X, Rs = %04X, Rt = %04X\n", Rd, Rs, Rt);

		*REGS[Rd] = ((unsigned short)((*REGS[Rs]))) / ((unsigned short)((*REGS[Rt])));
		set_nzp(*REGS[Rd]);
		PC++;
}
void add_im() {
		unsigned short op = MEM[PC];
		unsigned short Rd = D_REG(op);
		unsigned short Rs = S_REG(op);
		signed short IMM5 = SEXT_5.x = (op & 0x1F);
		//printf("Rd = %04X, Rs = %04X, IMM5 = %04X\n", Rd, Rs, IMM5);

		*REGS[Rd] = (*REGS[Rs]) + IMM5;
		set_nzp(*REGS[Rd]);
		PC++;
}

void cons() {
		unsigned short op = MEM[PC];
		unsigned short Rd = D_REG(op);
		signed short IMM9 = SEXT_9.x = (op & 0x1FF);
		//printf("Rd = %04X, IMM9 = %04X\n", Rd, IMM9);

		*REGS[Rd] = IMM9;
		set_nzp(*REGS[Rd]);
		PC++;
}

void sll() {
		unsigned short op = MEM[PC];
		unsigned short Rd = D_REG(op);
		unsigned short Rs = S_REG(op);
		unsigned short UIMM4 = SEXT_4U.x = (op & 0xF);
		//printf("Rd = %04X, Rs = %04X, UIMM4 = %04X\n", Rd, Rs, UIMM4);

		*REGS[Rd] = (*REGS[Rs]) << UIMM4;
		set_nzp(*REGS[Rd]);
		PC++;
}
void sra() {
		unsigned short op = MEM[PC];
		unsigned short Rd = D_REG(op);
		unsigned short Rs = S_REG(op);
		unsigned short UIMM4 = SEXT_4U.x = (op & 0xF);
		//printf("Rd = %04X, Rs = %04X, UIMM4 = %04X\n", Rd, Rs, UIMM4);

		*REGS[Rd] = ((signed short)(*REGS[Rs])) >> UIMM4;
		set_nzp(*REGS[Rd]);
		PC++;
}
void srl() {
		unsigned short op = MEM[PC];
		unsigned short Rd = D_REG(op);
		unsigned short Rs = S_REG(op);
		unsigned short UIMM4 = SEXT_4U.x = (op & 0xF);
		//printf("Rd = %04X, Rs = %04X, UIMM4 = %04X\n", Rd, Rs, UIMM4);

		*REGS[Rd] = ((unsigned short)(*REGS[Rs])) >> UIMM4;
		set_nzp(*REGS[Rd]);
		PC++;
}
void mod() {
		unsigned short op = MEM[PC];
		unsigned short Rd = D_REG(op);
		unsigned short Rs = S_REG(op);
		unsigned short Rt = T_REG(op);
		//printf("Rd = %04X, Rs = %04X, Rt = %04X\n", Rd, Rs, Rt);

		*REGS[Rd] = ((signed short)(*REGS[Rs])) % ((signed short)(*REGS[Rt]));
		set_nzp(*REGS[Rd]);
		PC++;
}

void brn() {
		unsigned short op = MEM[PC];
		signed short IMM9 = SEXT_9.x = (op & 0x1FF);
		//printf("IMM9 = %04X\n", IMM9);

		if(CC == 'N') PC = PC + 1 + IMM9;
		else PC++;
}
void brnz() {
		unsigned short op = MEM[PC];
		signed short IMM9 = SEXT_9.x = (op & 0x1FF);
		//printf("IMM9 = %04X\n", IMM9);

		if(CC == 'N' | CC == 'Z') PC = PC + 1 + IMM9;
		else PC++;
}
void brnp() {
		unsigned short op = MEM[PC];
		signed short IMM9 = SEXT_9.x = (op & 0x1FF);
		//printf("IMM9 = %04X\n", IMM9);

		if(CC == 'N' | CC == 'P') PC = PC + 1 + IMM9;
		else PC++;
}
void brz() {
		unsigned short op = MEM[PC];
		signed short IMM9 = SEXT_9.x = (op & 0x1FF);
		//printf("IMM9 = %04X\n", IMM9);

		if(CC == 'Z') PC = PC + 1 + IMM9;
		else PC++;
}
void brzp() {
		unsigned short op = MEM[PC];
		signed short IMM9 = SEXT_9.x = (op & 0x1FF);
		//printf("IMM9 = %04X\n", IMM9);

		if(CC == 'Z' | CC == 'P') PC = PC + 1 + IMM9;
		else PC++;
}
void brp() {
		unsigned short op = MEM[PC];
		signed short IMM9 = SEXT_9.x = (op & 0x1FF);
		//printf("IMM9 = %04X\n", IMM9);

		if(CC == 'P') PC = PC + 1 + IMM9;
		else PC++;
}
void brnzp() {
		unsigned short op = MEM[PC];
		signed short IMM9 = SEXT_9.x = (op & 0x1FF);
		//printf("IMM9 = %04X\n", IMM9);

		PC = PC + 1 + IMM9;
}

void cmp() {
		unsigned short op = MEM[PC];
		unsigned short Rs = D_REG(op);
		unsigned short Rt = T_REG(op);
		//printf("Rs = %04X, Rt = %04X\n", Rs, Rt);

		set_nzp((signed short)((*REGS[Rs])-(*REGS[Rt])));
		PC++;
}
void cmpu() {
		unsigned short op = MEM[PC];
		unsigned short Rs = D_REG(op);
		unsigned short Rt = T_REG(op);
		//printf("Rs = %04X, Rt = %04X\n", Rs, Rt);

		set_nzpu((unsigned short)((*REGS[Rs])-(*REGS[Rt])));
		PC++;
}
void cmpi() {
		unsigned short op = MEM[PC];
		unsigned short Rs = D_REG(op);
		signed short IMM7 = SEXT_7.x = (op & 0x7F);
		//printf("IMM7 = %04X\n", IMM7);

		set_nzp((signed short)(*REGS[Rs]-IMM7));
		PC++;
}
void cmpiu() {
		unsigned short op = MEM[PC];
		unsigned short Rs = D_REG(op);
		unsigned short UIMM7 = SEXT_7U.x = (op & 0x7F);
		//printf("UIMM7 = %04X\n", UIMM7);

		set_nzpu((unsigned short)((*REGS[Rs])-UIMM7));
		PC++;
}

void jsr() {
		unsigned short op = MEM[PC];
		signed short IMM11 = SEXT_11.x = (op & 0x7FF);
		//printf("IMM11 = %04X\n", IMM11);

		R7 = PC + 1;
		set_nzpu((unsigned short)(R7));
		PC = (PC & 0x8000) | (IMM11 << 4);
}
void jsrr() {
		unsigned short op = MEM[PC];
		unsigned short Rs = S_REG(op);
		//printf("Rs = %04X\n", Rs);

		unsigned short tmp = (unsigned short)(*REGS[Rs]);
		R7 = PC + 1;
		set_nzpu((unsigned short)(R7));
		PC = tmp;
}

void and() {
		unsigned short op = MEM[PC];
		unsigned short Rd = D_REG(op);
		unsigned short Rs = S_REG(op);
		unsigned short Rt = T_REG(op);
		//printf("Rd = %04X, Rs = %04X, Rt = %04X\n", Rd, Rs, Rt);

		*REGS[Rd] = (*REGS[Rs]) & (*REGS[Rt]);
		set_nzp(*REGS[Rd]);
		PC++;
}
void not() {
		unsigned short op = MEM[PC];
		unsigned short Rd = D_REG(op);
		unsigned short Rs = S_REG(op);
		//printf("Rd = %04X, Rs = %04X\n", Rd, Rs);

		*REGS[Rd] = ~(*REGS[Rs]);
		set_nzp(*REGS[Rd]);
		PC++;
}
void or() {
		unsigned short op = MEM[PC];
		unsigned short Rd = D_REG(op);
		unsigned short Rs = S_REG(op);
		unsigned short Rt = T_REG(op);
		//printf("Rd = %04X, Rs = %04X, Rt = %04X\n", Rd, Rs, Rt);

		*REGS[Rd] = (*REGS[Rs]) | (*REGS[Rt]);
		set_nzp(*REGS[Rd]);
		PC++;
}
void xor() {
		unsigned short op = MEM[PC];
		unsigned short Rd = D_REG(op);
		unsigned short Rs = S_REG(op);
		unsigned short Rt = T_REG(op);
		//printf("Rd = %04X, Rs = %04X, Rt = %04X\n", Rd, Rs, Rt);

		*REGS[Rd] = (*REGS[Rs]) ^ (*REGS[Rt]);
		set_nzp(*REGS[Rd]);
		PC++;
}
void and_im() {
		unsigned short op = MEM[PC];
		unsigned short Rd = D_REG(op);
		unsigned short Rs = S_REG(op);
		signed short IMM5 = SEXT_5.x = (op & 0x1F);
		//printf("Rd = %04X, Rs = %04X, IMM5 = %04X\n", Rd, Rs, IMM5);

		*REGS[Rd] = (*REGS[Rs]) & IMM5;
		set_nzp(*REGS[Rd]);
		PC++;
}

void ldr() {
		unsigned short op = MEM[PC];
		unsigned short Rd = D_REG(op);
		unsigned short Rs = S_REG(op);
		signed short IMM6 = SEXT_6.x = (op & 0x3F);
		//printf("Rd = %04X, Rs = %04X, IMM6 = %04X\n", Rd, Rs, IMM6);

		*REGS[Rd] = MEM[(*REGS[Rs]) + IMM6];
		set_nzp(*REGS[Rd]);
		PC++;
}
void str() {
		unsigned short op = MEM[PC];
		unsigned short Rd = D_REG(op);
		unsigned short Rs = S_REG(op);
		signed short IMM6 = SEXT_6.x = (op & 0x3F);
		//printf("Rd = %04X, Rs = %04X, IMM6 = %04X\n", Rd, Rs, IMM6);

		MEM[(*REGS[Rs]) + IMM6] = *REGS[Rd];
		set_nzp(*REGS[Rd]);
		PC++;
}

void rti() {
		PC = (unsigned short)(R7);
		PSR &= ~(1 << 15);
}

void jmpr() {
		unsigned short op = MEM[PC];
		unsigned short Rs = S_REG(op);
		//printf("Rs = %04X\n", Rs);

		PC = (unsigned short)((*REGS[Rs]));
}
void jmp() {
		unsigned short op = MEM[PC];
		signed short IMM11 = SEXT_11.x = (op & 0x7FF);
		//printf("IMM11 = %04X\n", IMM11);

		PC = PC + 1 + IMM11;
}

void hiconst() {
		unsigned short op = MEM[PC];
		unsigned short Rd = D_REG(op);
		unsigned short UIMM8 = SEXT_8U.x = (op & 0xFF);
		//printf("Rd = %04X, UIMM8 = %04X\n", Rd, UIMM8);

		*REGS[Rd] = ((*REGS[Rd]) & 0xFF) | (UIMM8 << 8);
		set_nzp(*REGS[Rd]);
		PC++;
}

void trap() {
		unsigned short op = MEM[PC];
		unsigned short UIMM8 = SEXT_8U.x = (op & 0xFF);
		
		R7 = PC + 1;
		set_nzpu((unsigned short)(R7));
		PC = (0x8000 | UIMM8);
		PSR |= 1 << 15;
}

void load_code(char* file) {
	unsigned char buff[FBUFFER_SIZE];
	int i=0, j;
	//int size=0;
	unsigned short sec, addr, n, cur, line, index;

	FILE *fin = fopen(file, "rb");
	if(fin == NULL) {
		printf("failure. Invalid object file: %s\n", file);
		return;
	}
	while(!feof(fin)) {
		fread(&sec, 2, 1, fin);
		if(feof(fin)) break;
		sec = FLIP(sec);
	
		// SYMBOL HEADER
		if((unsigned int)sec == 0xC3B7) {
			fread(&addr, 2, 1, fin);
			fread(&n, 2, 1, fin);
			addr = FLIP(addr);
			n = FLIP(n);
			table[num_symbols].val = addr;
			for(j=0;j<n;j++) {
				fread(table[num_symbols].s+j, 1, 1, fin);
			}
			table[num_symbols].s[n] = '\0';
			num_symbols++;
		}
		// FILE NAME HEADER
		else if((unsigned int)sec == 0xF17E) {
			fread(&n, 2, 1, fin);
			n = FLIP(n);
			for(j=0;j<n;j++) {
				fread(&cur, 1, 1, fin);
			}
		}
		// LINE NUMBER HEADER
		else if((unsigned int)sec == 0x715E) {
			fread(&addr, 2, 1, fin);
			fread(&line, 2, 1, fin);
			fread(&index, 2, 1, fin);
			addr = FLIP(addr);
			line = FLIP(line);
			index = FLIP(index);
		}
		// DATA & CODE HEADER
		else if((unsigned int)sec == 0xCADE || (unsigned int)sec == 0xDADA){
			fread(&addr, 2, 1, fin);
			fread(&n, 2, 1, fin);
			addr = FLIP(addr);
			n = FLIP(n);
			for(j=0;j<n;j++) {
				fread(&cur, 2, 1, fin);
				MEM[addr+j] = FLIP(cur);
			}
		}
		else {
			printf("Unknown section\n");
			return;
		}
		//printf("%04X %04X %04X\n", sec, addr, n);
	}

	fclose(fin);
	printf("success!\n");

//	for(i=0x4000;i<0x4000+20;i++)
//		printf("MEM[%04X] = %04X\n", i, MEM[i]);
//	for(i=0;i<num_symbols;i++)
//		printf("table[%d] = %s %04X\n", i, table[i].s, table[i].val);
}
