#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <time.h>
#include <cstdlib>
#include "des.h"
#include <string.h>
#include <vector>
#include<string>
#include <fstream>
#include <cassert>
#include <io.h>
#include <fcntl.h>
using namespace std;

static FILE* key_file, * input_file, * output_file;

#define ACTION_GENERATE_KEY "-g"
#define ACTION_ENCRYPT "-e"
#define ACTION_DECRYPT "-d"

#define DES_KEY_SIZE 8
int HEX_TO_DEC(char st[10])
{
	int i, s, k, p;
	s = 0;
	p = strlen(st) - 1;
	for (i = 0; st[i] != '\0'; i++) {
		switch (toupper(st[i])) {
		case 'A':
			k = 10;
			break;
		case 'B':
			k = 11;
			break;
		case 'C':
			k = 12;
			break;
		case 'D':
			k = 13;
			break;
		case 'E':
			k = 14;
			break;
		case 'F':
			k = 15;
			break;
		case '1':
			k = 1;
			break;
		case '2':
			k = 2;
			break;
		case '3':
			k = 3;
			break;
		case '4':
			k = 4;
			break;
		case '5':
			k = 5;
			break;
		case '6':
			k = 6;
			break;
		case '7':
			k = 7;
			break;
		case '8':
			k = 8;
			break;
		case '9':
			k = 9;
			break;
		case '0':
			k = 0;
			break;
		}
		s = s + k * pow(16, p);
		p--;
	}
	return s;
}
using namespace std;
int main(int argc, char* argv[]) {
	clock_t start, finish;
	double time_taken;
	unsigned long file_size;
	unsigned short int padding;

	if (argc < 2) {
		std::printf("You must provide at least 1 parameter, where you specify the action.");
		return 1;
	}

	if (strcmp(argv[1], ACTION_GENERATE_KEY) == 0) {
		if (argc != 3) {
			std::printf("Invalid # of parameter specified. Usage: run_des -g keyfile.key");
			return 1;
		}

		key_file = fopen(argv[2], "wb");
		if (!key_file) {
			std::printf("Could not open file to write key.");
			return 1;
		}

		unsigned int iseed = (unsigned int)time(NULL);
		srand(iseed);

		short int bytes_written;
		unsigned char* des_key = (unsigned char*)malloc(8 * sizeof(char));
		generate_key(des_key);  
		

		bytes_written = 8 * 8;
		for (int i = 0; i < 8; i++)
		{
			fprintf(key_file, "%02X ", des_key[i]);

		}
		

		std::free(des_key);
		std::fclose(key_file);
	}
	else if ((strcmp(argv[1], ACTION_ENCRYPT) == 0) || (strcmp(argv[1], ACTION_DECRYPT) == 0)) { 
		if (argc != 5) {
			std::printf("Invalid # of parameters (%d) specified. Usage: run_des [-e|-d] keyfile.key input.file output.file", argc);
			return 1;
		}

		
		key_file = fopen(argv[2], "rb");
		if (!key_file) {
			std::printf("Could not open key file to read key.");
			return 1;
		}

		short int bytes_read;
		unsigned char* des_key = (unsigned char*)malloc(8 * sizeof(char));
		char* tmp_y = (char*)malloc(sizeof(char) * 3);
		bytes_read = 8;
		for (int i = 0; i < 8; i++)
		{

			fscanf(key_file, "%s", tmp_y);
			int tmp1 = HEX_TO_DEC(*&tmp_y);
			*(des_key + i) = (char)tmp1;
		}

		int* tmp = 0;
		if (bytes_read != DES_KEY_SIZE) {
			std::printf("Key read from key file does nto have valid key size.");
			std::fclose(key_file);
			return 1;
		}
		std::fclose(key_file);

		input_file = fopen(argv[3], "rb");
		if (!input_file) {
			std::printf("Could not open input file to read data.");
			return 1;
		}


		output_file = fopen(argv[4], "wb");
		if (!output_file) {
			std::printf("Could not open output file to write data.");
			return 1;
		}

		short int bytes_written, process_mode;
		unsigned long block_count = 0, number_of_blocks;
		unsigned char* data_block = (unsigned char*)malloc(8 * sizeof(char));
		unsigned char* processed_block = (unsigned char*)malloc(8 * sizeof(char));
		key_set* key_sets = (key_set*)malloc(17 * sizeof(key_set));

		start = clock();
		generate_sub_keys(des_key, key_sets);
		finish = clock();
		time_taken = (double)(finish - start) / (double)CLOCKS_PER_SEC;

		if (strcmp(argv[1], ACTION_ENCRYPT) == 0) {
			process_mode = ENCRYPTION_MODE;
			std::printf("Encrypting..\n");
		}
		else {
			process_mode = DECRYPTION_MODE;
			std::printf("Decrypting..\n");
		}

		fseek(input_file, 0L, SEEK_END);
		file_size = ftell(input_file);

		fseek(input_file, 0L, SEEK_SET);
		number_of_blocks = file_size / 8 + ((file_size % 8) ? 1 : 0);

		start = clock();


		if (strcmp(argv[1], ACTION_ENCRYPT) == 0)
		{
			while (fread(data_block, 1, 8, input_file)) {
				block_count++;
				if (block_count == number_of_blocks) {
					if (process_mode == ENCRYPTION_MODE) {
						padding = 8 - file_size % 8;
						if (padding < 8) { // Fill empty data block bytes with padding
							memset((data_block + 8 - padding), (unsigned char)padding, padding);
						}

						process_message(data_block, processed_block, key_sets, process_mode);
						bytes_written = fwrite(processed_block, 1, 8, output_file);

						if (padding == 8) { // Write an extra block for padding
							memset(data_block, (unsigned char)padding, 8);
							process_message(data_block, processed_block, key_sets, process_mode);
							bytes_written = fwrite(processed_block, 1, 8, output_file);
						}
					}
					else {
						process_message(data_block, processed_block, key_sets, process_mode);
						padding = processed_block[7];

						if (padding < 8) {
							bytes_written = fwrite(processed_block, 1, 8 - padding, output_file);
						}
					}
				}
				else {
					process_message(data_block, processed_block, key_sets, process_mode);
					bytes_written = fwrite(processed_block, 1, 8, output_file);
				}
				memset(data_block, 0, 8);
			}
			fclose(output_file);
			output_file = fopen(argv[4], "rb");
			FILE* file;
			file = fopen("16enc.enc", "wb");
			char* tmp = (char*)malloc(sizeof(char) * 1000);
			ifstream read(output_file);
			std::string dna;
			std::string text_read;
			int count = 0;
			while (getline(read, text_read))
			{
				if (count > 0)
				{
					dna = dna + "\n";
				}
				dna += text_read;
				count++;

			}
			for (int i = 0; i < dna.length(); i++)
			{
				fprintf(file, "%02X", (unsigned char)dna[i]);
			}
		}
		if (strcmp(argv[1], ACTION_DECRYPT) == 0)
		{
			FILE* file;
			file = fopen("16enc.enc", "rb");
			char* tmp = (char*)malloc(sizeof(char) * 1000);
			int count = 0;
			FILE* my_input_file;
			my_input_file = fopen("tmp.enc", "wb");
			fscanf(file, "%s", tmp);
			char tmp1[3];
			char* ha = (char*)calloc(1000, sizeof(char));
			for (int i = 0, j = 0; i < strlen(tmp); i = i + 2, j++)
			{
				tmp1[0] = *(tmp + i);
				tmp1[1] = *(tmp + i + 1);
				tmp1[2] = '\0';
				int res_hex = HEX_TO_DEC(tmp1);
				*(ha + j) = (unsigned char)res_hex;
			}
			fputs(ha, my_input_file);
			std::fclose(my_input_file);
			my_input_file = fopen("tmp.enc", "rb");
			while (fread(data_block, 1, 8, my_input_file)) {
				block_count++;
				if (block_count == number_of_blocks) {
					if (process_mode == ENCRYPTION_MODE) {
						padding = 8 - file_size % 8;
						if (padding < 8) { // Fill empty data block bytes with padding
							memset((data_block + 8 - padding), (unsigned char)padding, padding);
						}

						process_message(data_block, processed_block, key_sets, process_mode);
						bytes_written = fwrite(processed_block, 1, 8, output_file);

						if (padding == 8) { // Write an extra block for padding
							memset(data_block, (unsigned char)padding, 8);
							process_message(data_block, processed_block, key_sets, process_mode);
							bytes_written = fwrite(processed_block, 1, 8, output_file);
						}
					}
					else {
						process_message(data_block, processed_block, key_sets, process_mode);
						padding = processed_block[7];

						if (padding < 8) {
							bytes_written = fwrite(processed_block, 1, 8 - padding, output_file);
						}
					}
				}
				else {
					process_message(data_block, processed_block, key_sets, process_mode);
					bytes_written = fwrite(processed_block, 1, 8, output_file);
				}
				memset(data_block, 0, 8);
			}

		}

		finish = clock();

		// Free up memory
		std::free(des_key);
		std::free(data_block);
		std::free(processed_block);
		std::fclose(input_file);
		std::fclose(output_file);

		// Provide feedback
		time_taken = (double)(finish - start) / (double)CLOCKS_PER_SEC;
		std::printf("Finished processing %s. Time taken: %lf seconds.\n", argv[3], time_taken);
		return 0;
	}
	else {
		std::printf("Invalid action: %s. First parameter must be [ -g | -e | -d ].", argv[1]);
		return 1;
	}

	return 0;
}
