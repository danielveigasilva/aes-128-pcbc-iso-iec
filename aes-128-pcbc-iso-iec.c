#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <math.h>
#include "aes.h"

#define SIZE_BLOCK 16
#define ENCRIPT "enc"
#define DECRIPT "dec"

#define true 1
#define false 0

#define uint8_t unsigned char

int file_exist(char * filename){
    FILE * file = fopen(filename, "rb");
    if (file){
        fclose(file);
        return true;
    }
    else
        return false;
}

void xor_block(uint8_t * block1, uint8_t * block2, uint8_t * output){
    for (int i = 0; i < SIZE_BLOCK; i++)
        output[i] = block1[i] ^ block2[i];
}

int padding(uint8_t * block, int size){
    if (size < SIZE_BLOCK){
        block[size] = 0x80;
        for (int i = size + 1; i < SIZE_BLOCK ; i++)
            block[i] = 0x00;
        return false;
    }
    return true;
}

void encript_file(uint8_t * key, char * file_name_in, char * file_name_out){
    
    FILE * file_in = fopen(file_name_in, "rb");
    FILE * file_out = fopen(file_name_out, "wb");

    fseek(file_in, 0L, SEEK_END);
    long sizeFileIn = ftell(file_in);

    int nBlocks = ceil((float) sizeFileIn / SIZE_BLOCK);
    int lastBlockSize = nBlocks == 1 ? sizeFileIn : SIZE_BLOCK - ((nBlocks * SIZE_BLOCK) - sizeFileIn);

    int addBlockPadding = false;

    fseek(file_in, 0L, SEEK_SET);

    uint8_t IV[SIZE_BLOCK] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

    while (nBlocks > 0 || addBlockPadding){

        uint8_t block_plaintext[SIZE_BLOCK] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

        if (!addBlockPadding){
            fread(block_plaintext, SIZE_BLOCK, 1, file_in);
            nBlocks --;

            if (nBlocks == 0)
                addBlockPadding = padding(block_plaintext, lastBlockSize);
        }
        else {
            block_plaintext[0] = 0x80;
            addBlockPadding = false;
        }

        uint8_t iv_xor_pt[SIZE_BLOCK] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        uint8_t block_ciphertext[SIZE_BLOCK] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

        xor_block(IV, block_plaintext, iv_xor_pt);
        AES128_Encrypt(iv_xor_pt, key, block_ciphertext);

        fwrite(block_ciphertext, SIZE_BLOCK, 1, file_out);
        xor_block(block_ciphertext, block_plaintext, IV);
    }
}

void decript_file(uint8_t * key, char * file_name_in, char * file_name_out){
    
    FILE * file_in = fopen(file_name_in, "rb");
    FILE * file_out = fopen(file_name_out, "wb");

    fseek(file_in, 0L, SEEK_END);
    long sizeFileIn = ftell(file_in);

    int nBlocks = ceil((float) sizeFileIn / SIZE_BLOCK);
    fseek(file_in, 0L, SEEK_SET);

    uint8_t IV[SIZE_BLOCK] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

    while (nBlocks > 0){

        uint8_t block_ciphertext[SIZE_BLOCK] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        
        fread(block_ciphertext, SIZE_BLOCK, 1, file_in);
        nBlocks --;

        uint8_t iv_xor_pt[SIZE_BLOCK] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        AES128_Decrypt(block_ciphertext, key, iv_xor_pt);
        
        uint8_t block_plaintext[SIZE_BLOCK] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        xor_block(iv_xor_pt, IV, block_plaintext);

        if (nBlocks == 0){
            for (int i = SIZE_BLOCK - 1; i >= 0; i --)
                if (block_plaintext[i] == 0x80 && i != 0)
                    fwrite(block_plaintext, i, 1, file_out);
        }
        else {
            fwrite(block_plaintext, SIZE_BLOCK, 1, file_out);
            xor_block(block_ciphertext, block_plaintext, IV);
        }
    }
}

int main (int argc, char *argv[]){

    char * action = argv[1];
    char * file_name_in = argv[2];
    char * file_name_out = argv[3];

    uint8_t key[SIZE_BLOCK] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };    // SIZE_BLOCK bytes = 128 bits

    if (!file_exist(file_name_in)){
        printf("ERRO: Arquivo %s não foi encontrado!\n", file_name_in);
        return 1;
    }

    printf("Insira sua chave: ");
    fgets((char *) key, SIZE_BLOCK, stdin );

    if (!strcmp(action, ENCRIPT))
        encript_file(key, file_name_in, file_name_out);
    else if (!strcmp(action, DECRIPT))
        decript_file(key, file_name_in, file_name_out);
    else {
        printf("Tipo de ação inválida\n");
        return 1;
    }

    return 0;
}