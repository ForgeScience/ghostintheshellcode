#include <stdio.h>
#include <Windows.h>
#include <winternl.h>
#include <wchar.h>
#include <tlhelp32.h>

#define VAR_DWORD(name) __asm __emit 0x00 __asm __emit 0x00 __asm __emit 0x00 __asm __emit 0x00

#define STR_DEF_04(name,a1,a2,a3,a4)	__asm _emit a1 __asm _emit a2 \
										__asm _emit a3 __asm _emit a4

typedef signed char       int8_t;
typedef signed short      int16_t;
typedef signed int        int32_t;
typedef unsigned char     uint8_t;
typedef unsigned short    uint16_t;
typedef unsigned int      uint32_t;

int exec();

typedef int bool;
enum { false, true };

#define VM_STACK_SIZE	0x40000	

#define VM_OP_MASK		0x3F //111111

#define DISPLACE_BYTE	0x01
#define DISPLACE_FOUR_BYTE	0x04

#define OP_CODE_FIRST_MASK	0xFFFFFFFF
#define OP_CODE_SECOND_MASK	0x00FFFFFF
#define OP_CODE_THIRD_MASK	0x0000FFFF
#define OP_CODE_LAST_MASK	0x000000FF

#define GEN_REG_COUNT 0x07

#define CVM_SET_BIT(x) (1 << (x-1))
#define CVM_SET_BYTE(x, bits) (bits << (x-1))

#define SECTION_SPACE 0xFA00 //64kb

#define CODE_BEGIN 0x00 //0kb

#define MEMORY_BEGIN 0x7d0 //2kb

enum vm_opcodes {
	VM_NOP,
	VM_ADD,
	VM_SUB,
	VM_MUL,
	VM_DIV,

	VM_MOV,

	VM_OR,
	VM_AND,
	VM_XOR,
	VM_SHR,
	VM_SHL,

	VM_INC,
	VM_DEC,

	VM_CMP,

	VM_JMP,

	VM_PUSH,
	VM_POP,

	VM_RET,
	VM_EXIT,
	VM_OP_TOTAL
};

enum vm_registers {
	/* general purpose registers */
	VM_GR0,
	VM_GR1,
	VM_GR2,
	VM_GR3,
	VM_GR4,
	VM_GR5,
	VM_GR6,

	/* execution flow, vm state, etc */
	VM_STACK,
	VM_STACK_BASE,
	VM_IP,
	VM_DESTINATION,

	VM_REG_TOTAL
};

enum quarter_registers {
	VM_GR0_L,
	VM_GR1_L,
	VM_GR2_L,
	VM_GR3_L,
	VM_GR4_L,
	VM_GR5_L,
	VM_GR6_L,

	VM_GR0_H,
	VM_GR1_H,
	VM_GR2_H,
	VM_GR3_H,
	VM_GR4_H,
	VM_GR5_H,
	VM_GR6_H,

	VM_QUART_REG_TOTAL
};

enum vm_errors {
	VMERR_NO_ERROR,

	VMERR_NOT_ENOUGH_MEMORY,
	VMERR_BAD_INSTRUCTION,
	VMERR_FAILED_INSTRUCTION,
	VMERR_DIV_BY_0,
	VMERR_BAD_IP,
	VMERR_BAD_STATUS,
	VMERR_UNKNOWN,
	VMERR_TOTAL
};

enum vm_cond_flags {
	VMCF_UNUSED,

	VMCF_NEG,
	VMCF_POS,
	VMCF_ZERO,

	VMCF_TOTAL
};

#pragma pack(1)
typedef union {
	int32_t reg;
	int32_t *ptr;

	int8_t rl;
	int8_t rh;

	int16_t padding;
} vm_reg_t;
#pragma pack()

#pragma pack(1)
typedef struct {
	void *mem_space;
	int mem_space_size;
} vm_memory_t;
#pragma pack()

#pragma pack(1)
typedef struct {
	uint8_t opcode; //operation
	uint8_t len; //size in bytes of instruction

	int32_t *arg1; //either a pointer to a register or memory
	int32_t *arg2;

} opcode_t;
#pragma pack()

#pragma pack(1)
typedef struct {
	uint8_t *code;
	uint8_t min_ip;
	uint8_t max_ip;
	uint8_t padding;
	uint16_t processed_count; //how many bytes weve processed
	uint16_t instr_count; //amount of bytes in code

	vm_memory_t memory;
	vm_reg_t registers[VM_REG_TOTAL];
} vm_ctx_t;
#pragma pack()

#pragma pack(1)
typedef struct _ADDRESS_TABLE{
	vm_ctx_t vm;
} ADDRESS_TABLE;
#pragma pack()

void __declspec(naked) ShellCodeStart(void *block)
{
	__asm
	{
		push block
		call exec
		ret
	}
}

unsigned long AddressTable() {
	unsigned int tableAddress;

	__asm
	{
		call endOfData

		VAR_DWORD(vm); //code and ip
		VAR_DWORD(vm); //processed and instr count

		VAR_DWORD(memory); //memory
		VAR_DWORD(memory);

		VAR_DWORD(registers); //registers
		VAR_DWORD(registers);

		VAR_DWORD(registers);
		VAR_DWORD(registers);

		VAR_DWORD(registers);
		VAR_DWORD(registers);

		VAR_DWORD(registers);
		VAR_DWORD(registers);

		VAR_DWORD(registers);
		VAR_DWORD(registers);

		VAR_DWORD(registers);
		VAR_DWORD(registers);

		VAR_DWORD(registers);
		VAR_DWORD(registers);

		VAR_DWORD(registers);
		VAR_DWORD(registers);

		VAR_DWORD(registers);
		VAR_DWORD(registers);

		VAR_DWORD(registers);
		VAR_DWORD(registers);
		endOfData:
		pop eax
		mov tableAddress, eax
	}

	return (tableAddress);
}

opcode_t *parse_buffer(uint8_t *code_buffer, vm_ctx_t *vm) {
	uint8_t code = code_buffer[0];
	//access the same point in our memory each time
	opcode_t *opcode = (opcode_t *)vm->memory.mem_space;
	uint8_t len = 0;

	bool immediate_assign = false;
	bool reg_is_destination = false;
	bool quarter_reg = false; //8bit vs 32 16 currently not supported

	bool has_displacement = false;
	bool has_scale = false;
	bool second_register = true;
	bool byte_displacement = false;

	//opcode byte and source/dest set

	opcode->opcode = ((code)& CVM_SET_BYTE(3, 5)) >> 2;

	immediate_assign = ((code)& CVM_SET_BIT(7)) ? true : false;
	reg_is_destination = ((code)& CVM_SET_BIT(2)) ? true : false;
	quarter_reg = ((code)& CVM_SET_BIT(1)) ? false : true;

	uint8_t op_mnemonic = ((code) >> 2) - ((code)& CVM_SET_BIT(7));
	if (op_mnemonic > 0 && op_mnemonic < VM_OP_TOTAL) {
		opcode->opcode = op_mnemonic;
	}
	else { //act like its a NOP
		opcode->opcode = VM_NOP;
		opcode->len = 1; //in bytes

		return opcode;
	}

	code = code_buffer[1];

	//mod reg rm byte
	//since we want more registers this is mostly blank space
	//can be used to stick carry flags in later
	uint8_t mod_op = ((code)& CVM_SET_BYTE(7, 3)) >> 6;
	

	//lets throw in the scale at the last 2 bits of this byte
	uint8_t scale = (code & CVM_SET_BYTE(7, 3)) >> 5;
	if (scale == 6) { scale += 2; }
	
	code = code_buffer[2];
	uint8_t rm_op = ((code)& 0x0F);
	uint8_t reg_op = ((code)& CVM_SET_BYTE(5, 15)) >> 4;
	uint8_t quarter_reg_op;
	uint8_t quarter_rm_op;

	vm_reg_t regfirst;
	vm_reg_t regsec;
	void *arg1_ref = malloc(sizeof(uint32_t));
	void *arg2_ref = malloc(sizeof(uint32_t));

	if (mod_op < 0x03 && mod_op > 0x00) {
		byte_displacement = (mod_op == 0x02) ? false : true;
	}

	if (mod_op < 0x03 && rm_op == 0x04) {
		has_scale = true;
		if (mod_op > 0x00) {
			has_displacement = true;
		}
		second_register = false;
	}
	else if (mod_op < 0x03 && rm_op == 0x05) {
		has_displacement = true;
		has_scale = false;
		second_register = false;
	}
	else {
		if (reg_is_destination) {

			if (quarter_reg) { //flip these checks for !reg_is_dest
				if (reg_op >= VM_QUART_REG_TOTAL ||
					((mod_op == 0x03 && rm_op >= VM_QUART_REG_TOTAL) || (rm_op >= VM_REG_TOTAL))){
					opcode->opcode = VM_NOP;
					opcode->len = 2; //in bytes

					return opcode;
				}

				quarter_reg_op = reg_op;
				if (quarter_reg_op < GEN_REG_COUNT) {
					(int32_t *)arg1_ref = &vm->registers[reg_op].rl;
				}
				else {
					reg_op = (quarter_reg_op - GEN_REG_COUNT);
					(int32_t *)arg1_ref = &vm->registers[reg_op].rh;
				}

				if (mod_op == 0x03) {
					quarter_rm_op = rm_op;
					if (quarter_rm_op < GEN_REG_COUNT) {
						(int32_t *)arg2_ref = &vm->registers[rm_op].rl;
					}
					else {
						rm_op = (quarter_rm_op - GEN_REG_COUNT);
						(int32_t *)arg2_ref = &vm->registers[rm_op].rh;
					}
				}
				else {
					arg1_ref = ((int *)vm->memory.mem_space)[vm->registers[rm_op].reg];
				}
			}
			else {
				if (reg_op >= VM_REG_TOTAL || rm_op >= VM_REG_TOTAL){
					opcode->opcode = VM_NOP;
					opcode->len = 2; //in bytes

					return opcode;
				}

				(int32_t *)arg1_ref = &vm->registers[reg_op].reg;

				if (mod_op == 0x03) {
					(int32_t *)arg2_ref = &vm->registers[rm_op].reg;
				}
				else {
					arg2_ref = ((int *)vm->memory.mem_space)[vm->registers[rm_op].reg];
				}
			}
		}
		else {
			if (quarter_reg) {
				if (rm_op >= VM_QUART_REG_TOTAL ||
					((mod_op == 0x03 && reg_op >= VM_QUART_REG_TOTAL) || (reg_op >= VM_REG_TOTAL))){
					opcode->opcode = VM_NOP;
					opcode->len = 2; //in bytes

					return opcode;
				}

				quarter_rm_op = rm_op;
				if (quarter_rm_op < GEN_REG_COUNT) {
					(int32_t *)arg1_ref = &vm->registers[rm_op].rl;
				}
				else {
					reg_op = (quarter_rm_op - GEN_REG_COUNT);
					(int32_t *)arg1_ref = &vm->registers[rm_op].rh;
				}

				if (mod_op == 0x03) {
					quarter_reg_op = reg_op;
					if (quarter_reg_op < GEN_REG_COUNT) {
						(int32_t *)arg2_ref = &vm->registers[reg_op].rl;
					}
					else {
						reg_op = (quarter_reg_op - GEN_REG_COUNT);
						(int32_t *)arg2_ref = &vm->registers[reg_op].rh;
					}
				}
				else {
					arg2_ref = ((int *)vm->memory.mem_space)[vm->registers[reg_op].reg];
				}
			}
			else {
				if (reg_op >= VM_REG_TOTAL || rm_op >= VM_REG_TOTAL){
					opcode->opcode = VM_NOP;
					opcode->len = 2; //in bytes

					return opcode;
				}

				(int32_t *)arg1_ref = &vm->registers[rm_op].reg;

				if (mod_op == 0x03) {
					(int32_t *)arg2_ref = &vm->registers[reg_op].reg;
				}
				else {
					arg2_ref = ((int *)vm->memory.mem_space)[vm->registers[reg_op].reg];
				}
			}
		}
	}
	len += 3;
	uint32_t offset = 0;

	if (has_scale) {
		code = code_buffer[len];
		uint8_t reg_op = ((code)& CVM_SET_BYTE(4, 15)) >> 4;

		uint8_t index_reg = (code & CVM_SET_BYTE(5, 15)) >> 4;
		uint8_t base_reg = (code & 0x0F);

		if (index_reg >= VM_OP_TOTAL || base_reg >= VM_OP_TOTAL) {
			opcode->opcode = VM_NOP;
			opcode->len = 3; //in bytes

			return opcode;
		}
		vm_reg_t index = vm->registers[index_reg];

		offset = (scale * index.reg);
		offset += vm->registers[base_reg].reg;

		if (mod_op != 00 || base_reg != 0x05) { //otherwise displacement mode
			(int32_t *)arg2_ref = ((int *)vm->memory.mem_space)[offset];
		}
		else {
			has_displacement = true;
		}
		len++;
	}

	if (has_displacement) {
		int32_t displacement = 0;

		if (byte_displacement) {
			displacement = code_buffer[len];
			len++;
		}
		else {
			displacement = (code_buffer[len] << 24) |
				(code_buffer[len + 1] << 16) | (code_buffer[len + 2] << 8) | (code_buffer[len + 3]);
			len += 4;
		}


		if (!second_register && !has_scale) {
			//ayy prolly add a check here first
			(int32_t *)arg2_ref = &((int *)vm->memory.mem_space)[displacement];
		}
		else if (!has_scale) {
		//	(int32_t *)arg2_ref = &((int *)vm->memory->mem_space)[((int32_t *)arg2_ref) + displacement];
		}
		else {
			(int32_t *)arg2_ref = &((int *)vm->memory.mem_space)[offset + displacement];
		}
	}

	if (immediate_assign && !second_register) {
		int32_t imm = 0;
		
		if (quarter_reg) {
			imm = code_buffer[len];
			len++;
		}
		else {
			imm = (code_buffer[len] << 24) |
				(code_buffer[len + 1] << 16) | (code_buffer[len + 2] << 8) | (code_buffer[len + 3]);
			len += 4;
		}

		(int32_t *)arg2_ref = &imm;
	}

	opcode->arg1 = arg1_ref;
	opcode->arg2 = arg2_ref;
	opcode->len = len;


	return opcode;
}

int vm_run(vm_ctx_t *vm) {
	bool end_process = false;

	while (vm->processed_count < vm->instr_count) {
		//grab 12 bytes or up to the end of code
		//process into opcode structure
		unsigned int count = 12;
		void* process_buffer;
		if (vm->processed_count + 12 > vm->instr_count) {
			process_buffer = malloc(sizeof(uint8_t) * 12);
		}
		else {
			count = ((vm->instr_count + 1) - vm->processed_count);
			process_buffer = malloc(sizeof(uint8_t) * count);
		}

		memcpy(process_buffer, vm->code[vm->processed_count], count);

		opcode_t *opcode = parse_buffer(process_buffer, vm);
		if (opcode->opcode != VM_NOP) {
			switch (opcode->opcode) {
			case VM_MOV:
				*(opcode->arg1) = *(opcode->arg2);
				break;
			case VM_ADD:
				*(opcode->arg1) += *(opcode->arg2);
				break;
			case VM_SUB:
				*(opcode->arg1) -= *(opcode->arg2);
				break;
			case VM_MUL:
				*(opcode->arg1) *= *(opcode->arg2);
				break;
			case VM_DIV:
				*(opcode->arg1) /= *(opcode->arg2);
				break;
			case VM_INC:
				++(*opcode->arg1);
				break;
			case VM_DEC:
				--(*opcode->arg1);
				break;
			case VM_SHL:
				(*opcode->arg1) <<= (*opcode->arg2);
				break;
			case VM_SHR:
				(*opcode->arg1) >>= (*opcode->arg2);
				break;
			case VM_XOR:
				(*opcode->arg1) ^= (*opcode->arg2);
				break;
			case VM_OR:
				(*opcode->arg1) |= (*opcode->arg2);
				break;
			case VM_AND:
				(*opcode->arg1) &= (*opcode->arg2);
				break;
			case VM_EXIT:
				end_process = true;
				break;
			default:
				break;
			}
		}

		if (end_process) {
			break;
		}
	}

	return 0;
}

void stack_create(vm_ctx_t *vm, uint32_t size) {
	vm->registers[GEN_REG_COUNT].ptr = ((int32_t *)vm->memory.mem_space) + (size / sizeof(uint32_t));
}

void stack_push(vm_ctx_t *vm, int32_t *item) {
	vm->registers[GEN_REG_COUNT].ptr -= 1;
	*(vm->registers[GEN_REG_COUNT].ptr) = *item;
}

void stack_pop(vm_ctx_t *vm, int32_t *item) {
	vm->registers[GEN_REG_COUNT].ptr += 1;
	*(vm->registers[GEN_REG_COUNT].ptr) = *item;
}

int vm_init(vm_ctx_t *vm) {

	//reset registers
	for (unsigned int ii = 0; ii < VM_REG_TOTAL; ii++) {
		vm->registers[ii].reg = 0;
		vm->registers[ii].rh = 0;
		vm->registers[ii].rl = 0;
	}

	stack_create(vm, VM_STACK_SIZE);

	return 1;
}

int exec(void *block) {
	/*
	uint32_t code_address = program_start - SECTION_SPACE; //where we are - 64kb
	uint32_t mem_address = code_address + MEMORY_BEGIN;
	ADDRESS_TABLE *table = (ADDRESS_TABLE *)AddressTable();
	*/
	uint32_t code_address = block; //where we are - 64kb
	uint32_t mem_address = code_address + 0x3e8;
	ADDRESS_TABLE *table = (ADDRESS_TABLE *)AddressTable();

	printf("%d \n", code_address);
	printf("%d \n", table);
	printf("%d \n", (*table).vm);	
	printf("%d \n", (*table).vm.code);

	(*table).vm.code = (void *)code_address;
	(*table).vm.memory.mem_space = (void *)mem_address;
	
	vm_init(&(*table).vm);

	vm_run(&(*table).vm);
}

int main(int argc, char *argv[])
{
	int sizecode = (int)main - (int)ShellCodeStart;
	printf("Shellcode starts at %p and is %d long", ShellCodeStart, sizecode);

	void *mem_block = malloc((size_t)2000);
	ShellCodeStart(mem_block);
	/*
	FILE *output_file = fopen("shellcode.bin", "w");
	fwrite(shell_code, sizecode, 1, output_file);
	fclose(output_file);
	*/
	return 0;
}