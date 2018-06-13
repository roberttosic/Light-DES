#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef uint16_t BITS;

//Feistel function used in each round
BITS f(BITS input, BITS key) {
    //S-box mappings:
    const BITS s1[16] = {
        0b101, 0b010, 0b001, 0b110, 0b011, 0b100, 0b111, 0b000,
        0b001, 0b100, 0b110, 0b010, 0b000, 0b111, 0b101, 0b011
    };
    
    const BITS s2[16] = {
        0b100, 0b000, 0b110, 0b101, 0b111, 0b001, 0b011, 0b010,
        0b101, 0b011, 0b000, 0b111, 0b110, 0b010, 0b001, 0b100
    };

    //Epansion function for 6b input and 8b output
    BITS expanded_input = (input & 0b000011) |
                          (input & 0b001000) >> 1 |
                          (input & 0b001100) << 1 |
                          (input & 0b000100) << 3 |
                          (input & 0b110000) << 2;
    
    //XOR with key to encrypt
    BITS encrypted_input = expanded_input ^ key;

    //Split result in half for each S-box
    BITS s1_input = encrypted_input / 0b10000;
    BITS s2_input = encrypted_input % 0b10000;
    BITS s1_result = s1[s1_input]; 
    BITS s2_result = s2[s2_input];

    return s1_result << 3 | s2_result;
}

//Takes array of 12-bit input and splits into larger array of 8-bit output
void text_12_8(BITS* split, unsigned char* text, int len_text) {
    for (int i=0,j=0;i<len_text;i+=3,j+=2) {
        text[i] = split[j] / 0b10000;
        text[i+1] = ((split[j] % 0b10000) << 4) | (split[j+1] / 0b100000000);
        text[i+2] = split[j+1] % 0b100000000;
    }
}

//Takes array of 8-bit input and splits into smaller array of 12-bit output
void text_8_12(unsigned char* text, BITS* split, int len_text) { 
    for (int i=0, j=0; i < len_text; i += 3, j += 2) {
        split[j] = (text[i] << 4) | (text[i+1] / 0b10000);
        split[j+1] = ((text[i+1] % 0b10000) << 8) | text[i+2];
    }
}

//Key schedule function that takes a 9-bit key and return an i-bit left shift
// and crops to the upper 8 bits
BITS sched(BITS key, int i) {
    i %= 10;
    const BITS mask = 0b1 << (10-i);
    const BITS masked = key & (mask-1);
    const int shift = i-2;
    const BITS shifted = shift < 0 ? masked >> -shift : masked << shift;
    return shifted | (key / (mask << 1));
}

//ECB mode encryption
void ecb_e(BITS key, int rounds, unsigned char* ptext, unsigned char* ctext, int plen) {
    //Calculate resultent length of 12-bit array
    const int len = ((plen * 2) / 3)+(plen%3==0?0:1);
    BITS input[len];

    //Transform 8-bit input to 12-bit array
    text_8_12(ptext, input, plen);

    for (int i=0;i<len;i++) { //For each block
        for (int j=1;j<=rounds;j++) { //Perform Perform requested rounds of the round function
            BITS l = input[i] / 0b1000000; 
            BITS r = input[i] % 0b1000000;
            input[i] = r << 6 | (f(r, sched(key,j)) ^ l);
        }
    }

    //Transform 12-bit encrypted array to an 8-bit readable format
    text_12_8(input, ctext, plen);
}

//ECB mode decryption
void ecb_d(BITS key, int rounds, unsigned char* ctext, unsigned char* ptext, int clen) {
    //Calculate resultent length of 12-bit array
    const int len = (clen * 2) / 3;
    BITS input[len];

    //Transform 8-bit input to 12-bit array
    text_8_12(ctext, input, clen);
    
    for (int i=0;i<len;i++) { //For each block
        for (int j=rounds;j>=1;j--) { //Perform Perform requested rounds of the round function
            BITS l = input[i] / 0b1000000;
            BITS r = input[i] % 0b1000000;
            input[i] = (f(l, sched(key,j)) ^ r) << 6 | l;
        }
    }

    //Transform 12-bit decrypted array to an 8-bit readable format
    text_12_8(input, ptext, clen);
}

//CBC mode encryption
void cbc_e(BITS key, int rounds, BITS IV, unsigned char* ptext, unsigned char* ctext, int plen) {
    //Calculate resultant length of 12-bit array
    const int len = ((plen * 2) / 3)+(plen%3==0?0:1);
    BITS input[len];

    //Transform 8-bit input to 12-bit output
    text_8_12(ptext, input, plen);

    //XOR with IV for first block
    input[0] = input[0] ^ IV;
    for (int j=1;j<=rounds;j++) { //Perform requested rounds of encryption
        BITS l = input[0] / 0b1000000;
        BITS r = input[0] % 0b1000000;
        input[0] = r << 6 | (f(r, sched(key,j)) ^ l);
    }
    for (int i=1;i<len;i++) {
        input[i] = input[i] ^ input[i-1]; //XOR with previous encrypted block
        for (int j=1;j<=rounds;j++) { //Perform requested rounds of encryption
            BITS l = input[i] / 0b1000000;
            BITS r = input[i] % 0b1000000;
            input[i] = r << 6 | (f(r, sched(key,j)) ^ l);
        }
    }

    //Transform 12-bit encrypted array to 8-bit readable format
    text_12_8(input, ctext, plen);
}

//CBC mode decryption
void cbc_d(BITS key, int rounds, BITS IV, unsigned char* ctext, unsigned char* ptext, int clen) {
    //Calculate resultant length of 12-bit array
    const int len = ((clen * 2) / 3) + (clen%3==0?0:1);
    BITS input[len];
    BITS cinput[len]; //An array to store an untouched version of the cipher-
                      // text during decryption

    //Transform 8-bit input to 12-bit array
    text_8_12(ctext, cinput, clen);

    //Retrieve cipher-text for first block
    input[0] = cinput[0];
    for (int j=rounds;j>=1;j--) { //Perform requested rounds of decryption
        BITS l = input[0] / 0b1000000;
        BITS r = input[0] % 0b1000000;
        input[0] = (f(l, sched(key,j)) ^ r) << 6 | l;
    }
    //XOR with IV for first round
    input[0] = input[0] ^ IV;

    for (int i=1;i<len;i++) { //For proceeding block
        input[i] = cinput[i]; //Retrieve cipher-text
        for (int j=rounds;j>=1;j--) { //Perform requested rounds of decryption
            BITS l = input[i] / 0b1000000;
            BITS r = input[i] % 0b1000000;
            input[i] = (f(l, sched(key,j)) ^ r) << 6 | l;
        }
        //XOR with ciphertext of previous block
        input[i] = input[i] ^ cinput[i-1];
    }

    //Transform decrypted 12-bit array to 8-bit readable format
    text_12_8(input, ptext, clen);
}

//CTR mode encryption
void ctr_e(BITS key, int rounds, BITS IV, unsigned char* ptext, unsigned char* ctext, int plen) {
    //Calculate resultant length of 12-bit array
    const int len = ((plen * 2) / 3)+(plen%3==0?0:1);
    BITS input[len];

    //Transform 8-bit input to 12-bit array
    text_8_12(ptext, input, plen);
    
    BITS ctr;
    for (int i=0;i<len;i++) {//For each block
        ctr = IV + i; //Generate input CTR as nonce + increment
        for (int j=1;j<=rounds;j++) { //Perform requested rounds of CTR encryption
            BITS l = ctr / 0b1000000;
            BITS r = ctr % 0b1000000;
            ctr = r << 6 | (f(r, sched(key,j)) ^ l);
        }
        //XOR plaintext with encrypted CTR
        input[i] = input[i] ^ ctr;
    }

    //Transform 12-bit encrypted array to 8-bit readable format
    text_12_8(input, ctext, plen);
}

//CTR mode decryption
void ctr_d(BITS key, int rounds, BITS IV, unsigned char* ctext, unsigned char* dtext, int clen) {
    //CTR decryption is identical to CTR encryption except now the ciphertext
    // is input and the plain (decrypted) text is the desired output
    ctr_e(key, rounds, IV, ctext, dtext, clen);
}

//Encryption entry point
//runs appropriate encryption function based on `int mode`
void encrypt(int mode, BITS key, int rounds, BITS IV, char* ptext, char* ctext, int len) {
    switch(mode) {
        case 0:
            ecb_e(key, rounds, ptext, ctext, len);
            break;
        case 1:
            cbc_e(key, rounds, IV, ptext, ctext, len);
            break;
        case 2:
            ctr_e(key, rounds, IV, ptext, ctext, len);
            break;
    }
}

//Decryption entry point
//runs appropriate decryption function based on `int mode`
void decrypt(int mode, BITS key, int rounds, BITS IV, char* ctext, char* dtext, int len) {
    switch(mode) {
        case 0:
            ecb_d(key, rounds, ctext, dtext, len);
            break;
        case 1:
            cbc_d(key, rounds, IV, ctext, dtext, len);
            break;
        case 2:
            ctr_d(key, rounds, IV, ctext, dtext, len);
            break;
    }
}

void print_fail() {
    printf("Invalid arguments. Must be in the form:\n"
            "./lab3 [--ecb/--cbc/--ctr] [--enc/--dec] [int rounds] [int key]\n\n"
            "Please fix arguments and try again.\n");
}

int main(int argc, unsigned char** argv) {
    //Check user input
    if (argc < 5) {
        print_fail();
        return -1;
    }

    //Generate key, IV, and set mode
    // BITS key = 0b010110101; //9-bit default key
    BITS IV = 0b111100001100; //12-bit default IV
    int mode;
    void (*func)(int, BITS, int, BITS, char*, char*, int);

    //Mode
    if      (strcmp(argv[1], "--ecb") == 0)
        mode = 0;
    else if (strcmp(argv[1], "--cbc") == 0)
        mode = 1;
    else if (strcmp(argv[1], "--ctr") == 0)
        mode = 2;

    //Encipher or decipher
    if      (strcmp(argv[2], "--enc") == 0)
        func = encrypt;
    else if (strcmp(argv[2], "--dec") == 0)
        func = decrypt;

    //Get number of rounds and the key from the user
    int rounds = atoi(argv[3]);
    BITS key = atoi(argv[4]);

    //Allow user to specify is input is char (default) or int, and if output is hex (default) or int
    int intout = 0;
    int intin = 0;

    //Restrict output to only the result (for piping)
    int xout = 0;
    if (argc > 5 && strcmp(argv[5], "--xout") == 0)
        xout = 1;

    int len;
    if (xout == 0) //User has not chosen to restrict output
        printf("Enter input length: ");
    scanf("%i", &len); //Get length as d
    getchar(); //Flush the buffer

    if (xout == 0) //User has not chosen to restrict output
        printf("Enter text (limit: %i chars):\n", len);
    
    //An input and output array of the set length
    char result[len];
    char input[len];

    fgets(input, len+1, stdin); //Must get 1 more than len to fit \0

    //Execute appropriate crypto function
    func(mode, key, rounds, IV, input, result, len);

    if (xout == 0) {
        //Present summary report
        printf("\nInput:\t");
        for (int i=0;i<len;i++)
            printf(intin==0?"%#02x ":"%i ",input[i]);
        printf("\nLength: %d", len);
        printf("\nResult:\t");
        for (int i=0;i<len;i++)
            printf(intout==0?"%#02x ":"%i ",result[i]);
        printf("\n");
    }
    else {
        //Print result
        printf("%d\n", len);
        fwrite(result, 1, len, stdout);
        printf("\n");
    }
}