#include<stdio.h>
#include "aes.h"

#define SIZE_BLOCK 16
#define uint8_t unsigned char

int main (){

    uint8_t key[SIZE_BLOCK] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, };    // SIZE_BLOCK bytes = 128 bits
    uint8_t input[SIZE_BLOCK];
    uint8_t output[SIZE_BLOCK];
    uint8_t dec[SIZE_BLOCK]; 
    
    printf("Enter with message: ");
    fgets((char *) input, SIZE_BLOCK, stdin );
    
    
    printf("Enter passphrase for key: ");
    fgets((char *) key, SIZE_BLOCK, stdin );
    
    AES128_Encrypt(input, key, output);
    AES128_Decrypt(output, key, dec);
    
    
    printf("Encrypted message: \n");
    for( int i = 0; i < SIZE_BLOCK; i++ ) {
        printf("%.2X", output[i] );
    }
    printf("\n");
    printf("Decrypted message: \n");
    printf("%s\n", dec);

    return 0;
}