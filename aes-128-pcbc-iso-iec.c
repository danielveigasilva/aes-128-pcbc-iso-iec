#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <termios.h>
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

void padding(uint8_t * block, long size){
    if (size < SIZE_BLOCK){
        block[size] = 0x80;
        for (int i = size + 1; i < SIZE_BLOCK ; i++)
            block[i] = 0x00;
    }
}

void encript_file(uint8_t * key, char * file_name_in, char * file_name_out){
    
    FILE * file_in = fopen(file_name_in, "rb");
    FILE * file_out = fopen(file_name_out, "wb");

    fseek(file_in, 0L, SEEK_END);
    long nBytesToRead = ftell(file_in);
    fseek(file_in, 0L, SEEK_SET);

    int addBlockPadding = false;

    uint8_t IV[SIZE_BLOCK] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

    while (nBytesToRead > 0 || addBlockPadding){

        uint8_t block_plaintext[SIZE_BLOCK] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

        if (!addBlockPadding){
            long nBytesRead = fread(block_plaintext, 1, SIZE_BLOCK, file_in);
            nBytesToRead -= nBytesRead;
            if (nBytesRead < SIZE_BLOCK)
                padding(block_plaintext, nBytesRead);
            else if (nBytesToRead == 0)
                addBlockPadding = true;
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
    long nBytesToRead = ftell(file_in);
    fseek(file_in, 0L, SEEK_SET);

    uint8_t IV[SIZE_BLOCK] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

    while (nBytesToRead > 0){

        uint8_t block_ciphertext[SIZE_BLOCK] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        
        long nBytesRead = fread(block_ciphertext, 1, SIZE_BLOCK, file_in);
        nBytesToRead -= nBytesRead;

        uint8_t iv_xor_pt[SIZE_BLOCK] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        AES128_Decrypt(block_ciphertext, key, iv_xor_pt);
        
        uint8_t block_plaintext[SIZE_BLOCK] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        xor_block(iv_xor_pt, IV, block_plaintext);

        if (nBytesToRead == 0){
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

ssize_t my_getpass(char **lineptr, size_t *n, FILE *stream)
{
  struct termios old, new;
  int nread;

  /* Turn echoing off and fail if we can’t. */
  if (tcgetattr (fileno (stream), &old) != 0)
    return -1;
  new = old;
  new.c_lflag &= ~ECHO;
  if (tcsetattr (fileno (stream), TCSAFLUSH, &new) != 0)
    return -1;

  /* Read the passphrase */
  nread = getline(lineptr, n, stream);

  /* Restore terminal. */
  (void) tcsetattr(fileno (stream), TCSAFLUSH, &old);

  return nread;
}

int main (int argc, char *argv[]){

    char * action;
    char * file_name_in;
    char * file_name_out;
    size_t sizeKey = SIZE_BLOCK;

    uint8_t * key = (uint8_t * ) calloc(sizeKey, sizeof(uint8_t));

    if (argc < 3){
        printf("ERRO: Quantidade de argumentos insuficiente!\n");
        return 1;
    }
    else {
        action = argv[1];
        file_name_in = argv[2];
        
        if (argc > 3){
            if (!strcmp(argv[3], "-o") && argc == 5)
                file_name_out = argv[4];
            else {
                printf("ERRO: Comando inválido ou quantidade de argumentos insuficiente!\n");
                return 1;
            }
        }
        else{
            char file_out_gerate [sizeof(file_name_in) + sizeof(action) + 1];
            strcpy(file_out_gerate, file_name_in);
            strcat(file_out_gerate, ".");
            strcat(file_out_gerate, action);

            file_name_out = file_out_gerate;
        }
    }
    
    if (!file_exist(file_name_in)){
        printf("ERRO: Arquivo %s não foi encontrado!\n", file_name_in);
        return 1;
    }

    printf("Insira sua chave: ");
    my_getpass((char **) &key, &sizeKey, stdin);
    printf("\n");
    //fgets((char *) key, SIZE_BLOCK, stdin );

    if (!strcmp(action, ENCRIPT))
        encript_file(key, file_name_in, file_name_out);
    else if (!strcmp(action, DECRIPT))
        decript_file(key, file_name_in, file_name_out);
    else {
        printf("ERRO: Tipo de ação inválida\n");
        return 1;
    }

    return 0;
}