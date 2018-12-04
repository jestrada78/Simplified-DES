/*
 * des.c
 *
 *  Created on: 29 nov. 2018
 *      Author: Jesús Estrada Salinas
 * 
 *  License: This software is under the terms and conditions of the
 * 	MIT License as described in the LICENSE file.
 * 
 *
 *  Descripcion del algoritmo en https://www.cs.uri.edu/cryptography/dessimplified.htm
 *
 */


#define ENCRYPT 1
#define DECRYPT 0

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>



int Divide_Data_6(int, int *);
int Divide_Data_4(int, int *);
int Expanse_Function(int);
int dec_to_binary_array(int, int *, int);
int sbox_num_select(int, int);
int feistel_encrypt(int, int, int, int);
int feistel_decrypt(int, int, int);
int Encrypt_Decrypt(int, int, int, int);

const int SBox1[2][8] = {
{0b101, 0b010, 0b001, 0b110, 0b011, 0b100, 0b111, 0b000},
{0b001, 0b100, 0b110, 0b010, 0b000, 0b111, 0b101, 0b011}
};

const int SBox2[2][8] = {
{0b100, 0b000, 0b110, 0b101, 0b111, 0b001, 0b011, 0b010},
{0b101, 0b011, 0b000, 0b111, 0b110, 0b010, 0b001, 0b100}
};



int main (int argc, char *argv[]) {

	int resultado=0;
	int key = 0;
	//int data = 3100;
	int data = 0;
	int operation_mode = 0;

	if (argc != 4){
		printf("Number of arguments wrong!!\n");
		exit(0);
	}
	
	if (!strcmp(argv[1], "--encrypt")) {  
		operation_mode = ENCRYPT; 
	}
	
	if (!strcmp(argv[1], "--decrypt")) {
		operation_mode = DECRYPT;
	}
	
	if ((data = atoi(argv[2])) > 4096){
		printf("Data argument out of range 0 to 4096 (12 bits)\n");
		exit(0);
	}
	
	if ((key = atoi(argv[3])) > 512){
		printf("Key argument out of range 0 to 512 (9 bits)\n");
		exit(0);
	}
	
	resultado = Encrypt_Decrypt(4, operation_mode, key, data);

	printf("Resultado: %d\n", resultado);
	
	return 1;
}

int Encrypt_Decrypt(int number_of_rounds, int crypt_decrypt, int key, int data)
{
	int data_temp = data;
	int resultado = 0;

	if (crypt_decrypt == ENCRYPT){
		for(int i = 0; i < number_of_rounds; i++){
			resultado = feistel_encrypt(i+1, key, data_temp, number_of_rounds);
			data_temp = resultado;
		}
	}
	else{
		for(int i = number_of_rounds; i > 0; i--){
			resultado = feistel_decrypt(i, key, data_temp);
			data_temp = resultado;
		}
	}

	return resultado;
}

/**
 * Separa los 12 bits de entrada en 6 bits derechos y 6 bits izquierdos.
 *
 */
int Divide_Data_6(int Data, int *LR)
{
	LR[0] = Data & 0b000000111111; //6 bits derechos
	LR[1] = (Data & 0b111111000000) >> 6; //6 bits izquierdos

	return 1;
}

/**
 * Separa los 8 bits de entrada en 4 bits izquierdos y 4 bits derechos.
 */
int Divide_Data_4(int Data, int *LR4)
{
	LR4[0] = Data & 0b00001111; //4 bits derechos
	LR4[1] = (Data & 0b11110000) >> 4; //4 bits izquierdos
	
	return 1;
}

/**
 Función que transforma registro de 6 bit, mediante función de expansión
 definida en la doc (Simplified DES).
*/
int Expanse_Function(int data)
{
	int sbd_str[6];
	int ebd_str[8];
	int six_bit_data = data;
	int eight_bit_data = 0;
	
	dec_to_binary_array(six_bit_data, sbd_str,6);
	
	ebd_str[0] = sbd_str[0];
	ebd_str[1] = sbd_str[1];
	ebd_str[2] = sbd_str[3];
	ebd_str[3] = sbd_str[2];
	ebd_str[4] = sbd_str[3];
	ebd_str[5] = sbd_str[2];
	ebd_str[6] = sbd_str[4];
	ebd_str[7] = sbd_str[5];

	
	for(int i=0; i < 8; i++){
		eight_bit_data += ebd_str[i] * (int)pow(2,i);
	}

	return eight_bit_data;
}

/*
 * Convierte un entero en base decimal en un array de bits enteros.
 */
int dec_to_binary_array(int dec_data, int *data, int length)
{
	int bit=0;
	int six_bit_data = dec_data;
		
	for(int i=0; i < length; i++){
		bit = six_bit_data % 2;
		six_bit_data = six_bit_data / 2;
		data[i] =  bit;
	}
	return 1;
}

/*
 * Operaciones sobre SBox1 y SBox2 según algoritmo "Simplified DES".
 */

int sbox_num_select(int l_bits, int r_bits)
{
	int nibble_l[4] = {0,0,0,0};
	int nibble_r[4] = {0,0,0,0};
	int final_bits = 0, col_bits = 0, op_bits_r = 0, op_bits_l = 0;
		
	dec_to_binary_array(l_bits, nibble_l, 4);
	dec_to_binary_array(r_bits, nibble_r, 4);
	
	//nibble_l op SB1
	for(int i=0; i < 3; i++)
		col_bits += nibble_l[i] * (int)pow(2,i);
	
	op_bits_l = SBox1[nibble_l[3]][col_bits];
	printf("Coordenadas SBox1: %d %d\n", nibble_l[3], col_bits);
	printf("valor sb1: %d\n", op_bits_l);
	
	//nibble_r op SB2
	col_bits = 0;
	for(int i=0; i < 3; i++)
		col_bits += nibble_r[i] * (int)pow(2,i);
	

	op_bits_r = SBox2[nibble_r[3]][col_bits];
	printf("Coordenadas SBox2: %d %d\n", nibble_r[3], col_bits);
	printf("valor sb2: %d\n", op_bits_r);
	
	//concat both parts
	final_bits = op_bits_l << 3;
	final_bits = final_bits | op_bits_r;
	
	return final_bits;
	
}

int feistel_encrypt(int round_number, int key, int data, int number_of_rounds)
{
	int *LR, *LR_next, *LR_4;
	int *E_LR;
	int function_R_K = 0;
	int round_key = 0;
	int Data = 0;
	int * key_array, *key_array_aux;
	int Resultado = 0;

	LR = (int *)malloc(2*sizeof(int));
	LR_next = (int *)malloc(2*sizeof(int));
	LR_4 = (int *)malloc(2*sizeof(int));
	E_LR = (int *)malloc(2*sizeof(int));
	key_array = (int *)malloc(9*sizeof(int));
	key_array_aux = (int *)malloc(8*sizeof(int));
	key = key & 0b111111111;
	Data = data & 0b111111111111;
	
	//We get array of bits from the key
	dec_to_binary_array(key, key_array, 9);

	//We copy bit by bit, depending on the round we are, the key bits will be in
	//different places place.
	int j = 8 - (round_number - 1);
	for(int i = 7; i >= 0; i--){
		if (j == -1) j=8;
		key_array_aux[i] = key_array[j];
		j--;
	}


	//Convert array of bits in integer
	//round_key is the key now
	for(int i = 0; i < 8; i++){
		round_key += key_array_aux[i] * (int)pow(2,i);
	}
	
	round_key = round_key & 0b11111111;
	printf("Valor K: %d\n", round_key);
		
	Divide_Data_6(Data, LR);
	
	E_LR[0] = Expanse_Function(LR[0]); //Ri expandido
	printf("E(R0): %d\n", E_LR[0]);
	E_LR[0] = E_LR[0] ^ round_key;
	printf("E(R0) XOR Ki: %d\n", E_LR[0]);
	Divide_Data_4(E_LR[0], LR_4);
	function_R_K = sbox_num_select(LR_4[1], LR_4[0]);
	printf("Valor a la salida de SBox: %d\n", function_R_K);

	LR_next[0] = LR[1] ^ function_R_K;
	printf("Ri: %d\n", LR_next[0]);
	LR_next[1] = LR[0];	
	printf("Li: %d\n", LR_next[1]);
	

		if (round_number == number_of_rounds){
			Resultado = LR_next[0] << 6;
			Resultado = Resultado | LR_next[1];
			Resultado = Resultado & 0b111111111111;
		}
		else {
			Resultado = LR_next[1] << 6;
			Resultado = LR_next[0] | Resultado;
			Resultado = Resultado & 0b111111111111;
		}


	return Resultado;
}

int feistel_decrypt(int round_number, int key, int data)
{
	int *LR, *LR_next, *LR_4;
	int *E_LR;
	int function_R_K = 0;
	int round_key = 0;
	int Data = 0;
	int * key_array, *key_array_aux;
	int Resultado = 0;

	LR = (int *)malloc(2*sizeof(int));
	LR_next = (int *)malloc(2*sizeof(int));
	LR_4 = (int *)malloc(2*sizeof(int));
	E_LR = (int *)malloc(2*sizeof(int));
	key_array = (int *)malloc(9*sizeof(int));
	key_array_aux = (int *)malloc(8*sizeof(int));
	key = key & 0b111111111;
	Data = data & 0b111111111111;

	//We get array of bits from the key
	dec_to_binary_array(key, key_array, 9);

	//We copy bit to bit depending on the round the key bits in the
	//right place.
	int j = 8 - (round_number - 1);
	for(int i = 7; i >= 0; i--){
		if (j == -1) j=8;
		key_array_aux[i] = key_array[j];
		j--;
	}


	//Convert array of bits in integer
	//round_key is the key now
	for(int i = 0; i < 8; i++){
		round_key += key_array_aux[i] * (int)pow(2,i);
	}

	round_key = round_key & 0b11111111;
	printf("Valor K: %d\n", round_key);

	Divide_Data_6(Data, LR);

	E_LR[0] = Expanse_Function(LR[0]); //Ri expandido
	printf("E(R0): %d\n", E_LR[0]);
	E_LR[0] = E_LR[0] ^ round_key;
	printf("E(R0) XOR K1: %d\n", E_LR[0]);
	Divide_Data_4(E_LR[0], LR_4);
	function_R_K = sbox_num_select(LR_4[1], LR_4[0]);
	printf("Valor a la salida de SBox: %d\n", function_R_K);

	LR_next[0] = LR[1] ^ function_R_K;
	printf("Ri: %d\n", LR_next[0]);
	LR_next[1] = LR[0];
	printf("Li: %d\n", LR_next[1]);


		if (round_number == 1){
			Resultado = LR_next[0] << 6;
			Resultado = Resultado | LR_next[1];
			Resultado = Resultado & 0b111111111111;
		}
		else {
			Resultado = LR_next[1] << 6;
			Resultado = LR_next[0] | Resultado;
			Resultado = Resultado & 0b111111111111;
		}


	return Resultado;
}
