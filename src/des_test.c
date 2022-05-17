#include "des_test.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int TestDES() {
    /* test DES
    input
        M = 0x0123456789ABCDEF
        K = 0x133457799BBCDFF1
    output
        out = 85E813540F0AB405
    */
    uint64 M = 0x0123456789ABCDEF;
    uint64 K = 0x133457799BBCDFF1;
    uint64 out = 0;
    des64(&out, M, K, 1);
    printf("DES  = %llx\n\n", out);
    return 0;
}

int TestDES_En_De1() {
    /* test DES encrypt and decrypt
    input
        M   = 0x8787878787878787
        K   = 0x0E329232EA6D0D73
    output
        out = 0x0000000000000000
    */
    uint64 MM = 0x8787878787878787;
    uint64 K = 0x0E329232EA6D0D73;
    uint64 lenm = 8;

    unsigned char *M = (unsigned char *)malloc(lenm * sizeof(unsigned char));
    memcpy(M, &MM, lenm);

    printf("Input  = ");
    for (int i = 0; i < lenm; ++i) {
        printf("%02x", M[i]);
    }
    putchar(10);

    unsigned char *enOutput =
        (unsigned char *)malloc((lenm + 8) * sizeof(unsigned char));
    uint64 lenEo = 0;

    DES_Encrypt(enOutput, &lenEo, M, lenm, K);

    printf("DES En = ");
    for (int i = 0; i < lenEo; ++i) {
        printf("%02x", enOutput[i]);
    }
    putchar(10);

    // 开始解密
    unsigned char *deOutput =
        (unsigned char *)malloc(lenEo * sizeof(unsigned char));
    uint64 lenDo = 0;
    DES_Decrypt(deOutput, &lenDo, enOutput, 16, K);

    printf("DES De = ");
    for (int i = 0; i < lenDo; ++i) {
        printf("%02x", deOutput[i]);
    }
    putchar(10);
    putchar(10);
    free(deOutput);
    free(enOutput);
    free(M);
    return 0;
}

int TestDES_En_De2() {
    /* test DES encrypt and decrypt
    input
        M   = 0x8787878787878787
        K   = 0x0E329232EA6D0D73
    output
        out = 0x0000000000000000
    */
    uint64 MM = 0x8787878787878787;
    uint64 K = 0x0E329232EA6D0D73;
    uint64 lenm = 10;

    unsigned char *M = (unsigned char *)malloc(lenm * sizeof(unsigned char));
    memcpy(M, &MM, lenm);
    M[8] = 0x2;
    M[9] = 0x1;

    printf("Input  = ");
    for (int i = 0; i < lenm; ++i) {
        printf("%02x", M[i]);
    }
    putchar(10);

    unsigned char *enOutput =
        (unsigned char *)malloc((lenm + 8) * sizeof(unsigned char));
    uint64 lenEo = 0;

    DES_Encrypt(enOutput, &lenEo, M, lenm, K);

    printf("DES En = ");
    for (int i = 0; i < lenEo; ++i) {
        printf("%02x", enOutput[i]);
    }
    putchar(10);

    // 开始解密
    unsigned char *deOutput =
        (unsigned char *)malloc(lenEo * sizeof(unsigned char));
    uint64 lenDo = 0;
    DES_Decrypt(deOutput, &lenDo, enOutput, 16, K);

    printf("DES De = ");
    for (int i = 0; i < lenDo; ++i) {
        printf("%02x", deOutput[i]);
    }
    putchar(10);
    putchar(10);
    free(deOutput);
    free(enOutput);
    free(M);
    return 0;
}

int TestDES_En2() {
    uint64 MM = 0x8787878787878787;
    uint64 K = 0x0E329232EA6D0D73;
    uint64 lenm = 8;

    unsigned char *M = (unsigned char *)malloc(lenm * sizeof(unsigned char));
    memcpy(M, &MM, lenm);

    uint64 *out = (uint64 *)malloc(lenm + 8);
    uint64 leno = 0;

    DES_Encrypt((unsigned char *)out, &leno, M, 8, K);

    printf("DES = ");
    for (uint64 i = 0; i < leno / 8; ++i) {
        printf("%016llx ", out[i]);
    }
    putchar(10);
    putchar(10);
    free(M);
    return 0;
}

int TestDES_En1() {
    uint64 MM = 0x0123456789ABCDEF;
    uint64 K = 0x133457799BBCDFF1;
    uint64 lenm = 8;

    unsigned char *M = (unsigned char *)malloc(lenm * sizeof(unsigned char));
    memcpy(M, &MM, lenm);

    uint64 *out = (uint64 *)malloc(lenm + 8);
    uint64 leno = 0;

    DES_Encrypt((unsigned char *)out, &leno, M, 8, K);

    printf("DES = ");
    for (uint64 i = 0; i < leno / 8; ++i) {
        printf("%llx ", out[i]);
    }
    putchar(10);
    putchar(10);
    free(out);
    free(M);
    return 0;
}

int TestDES_De() {
    uint64 MM = 0;
    uint64 K = 0x0E329232EA6D0D73;
    uint64 lenm = 8;

    unsigned char *M = (unsigned char *)malloc(lenm * sizeof(unsigned char));
    memcpy(M, &MM, lenm);

    uint64 *out = (uint64 *)malloc(lenm + 8);
    uint64 leno = 0;

    DES_Decrypt((unsigned char *)out, &leno, M, 8, K);

    printf("DES = ");
    for (uint64 i = 0; i < leno / 8; ++i) {
        printf("%016llx ", out[i]);
    }
    putchar(10);
    putchar(10);
    free(out);
    free(M);
    return 0;
}

int TestGeneKeys() {
    // key
    // = 00010011 00110100 01010111 01111001 10011011 10111100 11011111 11110001
    // = 0x133457799bbcdff1
    uint64 key = 0x133457799bbcdff1;

    uint48 keys[17];
    for (int i = 0; i <= 16; ++i) {
        keys[i] = 0;
    }
    geneKeys(keys, key);
    for (int i = 0; i <= 16; ++i) {
        printb(keys[i], 48);
    }
    return 0;
}

int TestFeistel() {
    // test feistel
    /* input
        R = 1111 0000 1010 1010 1111 0000 1010 1010
            f0aaf0aa
        K = 0001 1011 0000 0010 1110 1111 1111 1100 0111 0000 0111 0010
            1b02effc7072
       output
        f = 0010 0011 0100 1010 1010 1001 1011 1011
            234aa9bb

    */
    uint32 R = 0xf0aaf0aa;
    uint64 K = 0x1b02effc7072;
    uint32 f = feistel(R, K);
    printf("ffff %x\n", f);
    return 0;
}