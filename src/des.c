#include "des.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 用于显示 DES 过程，可选择单个函数
#define DEBUG_DES 0

#define DEBUG_F_D 0
#define DEBUG_F_DE 0
#define DEBUG_F_DD 0
#define DEBUG_F_P 0
#define DEBUG_F_F 0

// 置换表

// PC_1 用于生成密钥组
static const unsigned char PC_1[56] = {
    57, 49, 41, 33, 25, 17, 9,  1,  58, 50, 42, 34, 26, 18, 10, 2,  59, 51, 43,
    35, 27, 19, 11, 3,  60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7,  62, 54,
    46, 38, 30, 22, 14, 6,  61, 53, 45, 37, 29, 21, 13, 5,  28, 20, 12, 4};
// PC_2 用于生成密钥组
static const unsigned char PC_2[48] = {
    14, 17, 11, 24, 1,  5,  3,  28, 15, 6,  21, 10, 23, 19, 12, 4,
    26, 8,  16, 7,  27, 20, 13, 2,  41, 52, 31, 37, 47, 55, 30, 40,
    51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32};

static const unsigned char IP_table[64] = {
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9,  1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7};
static const unsigned char IP_1_table[64] = {
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9,  49, 17, 57, 25};
static const unsigned char E_expansion[48] = {
    32, 1,  2,  3,  4,  5,  4,  5,  6,  7,  8,  9,  8,  9,  10, 11,
    12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21,
    22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1};
static const unsigned char P_box[32] = {
    16, 7, 20, 21, 29, 12, 28, 17, 1,  15, 23, 26, 5,  18, 31, 10,
    2,  8, 24, 14, 32, 27, 3,  9,  19, 13, 30, 6,  22, 11, 4,  25};

static const unsigned char S_boxes[8][4 * 16] = {
    {14, 4,  13, 1, 2,  15, 11, 8,  3,  10, 6,  12, 5,  9,  0, 7,
     0,  15, 7,  4, 14, 2,  13, 1,  10, 6,  12, 11, 9,  5,  3, 8,
     4,  1,  14, 8, 13, 6,  2,  11, 15, 12, 9,  7,  3,  10, 5, 0,
     15, 12, 8,  2, 4,  9,  1,  7,  5,  11, 3,  14, 10, 0,  6, 13},

    {15, 1,  8,  14, 6,  11, 3,  4,  9,  7, 2,  13, 12, 0, 5,  10,
     3,  13, 4,  7,  15, 2,  8,  14, 12, 0, 1,  10, 6,  9, 11, 5,
     0,  14, 7,  11, 10, 4,  13, 1,  5,  8, 12, 6,  9,  3, 2,  15,
     13, 8,  10, 1,  3,  15, 4,  2,  11, 6, 7,  12, 0,  5, 14, 9},

    {10, 0,  9,  14, 6, 3,  15, 5,  1,  13, 12, 7,  11, 4,  2,  8,
     13, 7,  0,  9,  3, 4,  6,  10, 2,  8,  5,  14, 12, 11, 15, 1,
     13, 6,  4,  9,  8, 15, 3,  0,  11, 1,  2,  12, 5,  10, 14, 7,
     1,  10, 13, 0,  6, 9,  8,  7,  4,  15, 14, 3,  11, 5,  2,  12},

    {7,  13, 14, 3, 0,  6,  9,  10, 1,  2, 8, 5,  11, 12, 4,  15,
     13, 8,  11, 5, 6,  15, 0,  3,  4,  7, 2, 12, 1,  10, 14, 9,
     10, 6,  9,  0, 12, 11, 7,  13, 15, 1, 3, 14, 5,  2,  8,  4,
     3,  15, 0,  6, 10, 1,  13, 8,  9,  4, 5, 11, 12, 7,  2,  14},

    {2,  12, 4,  1,  7,  10, 11, 6,  8,  5,  3,  15, 13, 0, 14, 9,
     14, 11, 2,  12, 4,  7,  13, 1,  5,  0,  15, 10, 3,  9, 8,  6,
     4,  2,  1,  11, 10, 13, 7,  8,  15, 9,  12, 5,  6,  3, 0,  14,
     11, 8,  12, 7,  1,  14, 2,  13, 6,  15, 0,  9,  10, 4, 5,  3},

    {12, 1,  10, 15, 9, 2,  6,  8,  0,  13, 3,  4,  14, 7,  5,  11,
     10, 15, 4,  2,  7, 12, 9,  5,  6,  1,  13, 14, 0,  11, 3,  8,
     9,  14, 15, 5,  2, 8,  12, 3,  7,  0,  4,  10, 1,  13, 11, 6,
     4,  3,  2,  12, 9, 5,  15, 10, 11, 14, 1,  7,  6,  0,  8,  13},

    {4,  11, 2,  14, 15, 0, 8,  13, 3,  12, 9, 7,  5,  10, 6, 1,
     13, 0,  11, 7,  4,  9, 1,  10, 14, 3,  5, 12, 2,  15, 8, 6,
     1,  4,  11, 13, 12, 3, 7,  14, 10, 15, 6, 8,  0,  5,  9, 2,
     6,  11, 13, 8,  1,  4, 10, 7,  9,  5,  0, 15, 14, 2,  3, 12},

    {13, 2,  8,  4, 6,  15, 11, 1,  10, 9,  3,  14, 5,  0,  12, 7,
     1,  15, 13, 8, 10, 3,  7,  4,  12, 5,  6,  11, 0,  14, 9,  2,
     7,  11, 4,  1, 9,  12, 14, 2,  0,  6,  10, 13, 15, 3,  5,  8,
     2,  1,  14, 7, 4,  10, 8,  13, 15, 12, 9,  0,  3,  5,  6,  11}};
void DES_Encrypt(unsigned char *des, unsigned long long *lend,
                 const unsigned char *src, const unsigned long long lens,
                 const uint64 key) {
    if (init() != 1) {
        return;
    }
#if DEBUG_DES || DEBUG_F_DE
    printf("src = ");
    for (int i = 0; i < lens; ++i) {
        printf("%02x", src[i]);
    }
    putchar(10);
#endif
    uint8 lenp = (uint8)8 - (uint8)(lens % 8);
    *lend = lens + lenp;
    uint64 i = 0, M = 0, out = 0;

    for (; i < lens / 8; ++i) {
        memcpy(&M, src + i * 8, 8);
        des64(&out, M, key, 1);
        memcpy(des + i * 8, &out, 8);
    }
    M = 0;
    memcpy(&M, src + i * 8, lens - i * 8);

    for (uint64 j = 0; j < lenp; ++j) {
        memcpy((void *)&M + 8 - lenp + j, &lenp, 1);
    }
    des64(&out, M, key, 1);
    memcpy(des + i * 8, &out, 8);
    return;
}
void DES_Decrypt(unsigned char *des, unsigned long long *lend,
                 const unsigned char *src, const unsigned long long lens,
                 const uint64 key) {
    if (init() != 1) {
        return;
    }
    uint64 i = 0;
    uint64 M = 0;
    uint64 out = 0;
#if DEBUG_DES || DEBUG_F_DD
    printf("*** Begin DES Decrypt ***\n");
    printf("M = %llx\n", M);
    printf("K = %llx\n", key);
#endif
    for (; i < (lens / 8) - (uint64)1; ++i) {
        memcpy(&M, src + i * 8, 8);
        des64(&out, M, key, 0);
        memcpy(des + i * 8, &out, 8);
    }
    memcpy(&M, src + i * 8, 8);
    des64(&out, M, key, 0);
    memcpy(des + i * 8, &out, 8);
    *lend = lens;
#if DEBUG_DES || DEBUG_F_DD
    printf("OUT = ");
    for (uint64 i = 0; i < *lend; ++i) {
        printf("%02x", des[i]);
    }
    putchar(10);
    printf("*** END DES Decrypt ***\n");
#endif

    // 处理填充内容
    unsigned char lenp = 0;
    memcpy(&lenp, (void *)&out + 7, 1);

    *lend = lens - lenp;
#if DEBUG_DES || DEBUG_F_DD
    printf("OUT = ");
    for (uint64 i = 0; i < *lend; ++i) {
        printf("%02x", des[i]);
    }
    putchar(10);
    printf("*** END DES Decrypt ***\n");
#endif
}

// 主函数
void des64(uint64 *output, const uint64 M, const uint64 key, bool isEn) {
#if DEBUG_DES || DEBUG_F_D
    printf("*** Begin DES 64bits ***\n");
    printf("M = %llx\n", M);
    printf("K = %llx\n", key);
#endif
    uint48 keys[17];
    geneKeys(keys, key);

#if DEBUG_DES || DEBUG_F_D
    for (int i = 1; i <= 16; ++i) {
        printf("K [%2d] = ", i);
        printb(keys[i], 48);
    }
#endif

    uint64 IP = 0;
    permutation(&IP, 64, M, 64, IP_table);  // 初始化： IP 置换

    // printf("IP = %llx\n", IP);

    uint32 *L = (uint32 *)malloc(17 * sizeof(uint32));
    uint32 *R = (uint32 *)malloc(17 * sizeof(uint32));
    splitLR(&L[0], &R[0], IP, 64);  // 分组

    for (int i = 1; i <= 16; ++i) {  // 开始 16 轮「轮函数」
        L[i] = R[i - 1];
        if (isEn) {
            R[i] = L[i - 1] ^ feistel(R[i - 1], keys[i]);
        } else {
            R[i] = L[i - 1] ^ feistel(R[i - 1], keys[17 - i]);
        }
    }

    //#if DEBUG_DES
    // for (int i = 1; i <= 16; ++i) {
    //     printf("L [%2d] = ", i);
    //     printb(L[i], 32);
    //     printf("R [%2d] = ", i);
    //     printb(R[i], 32);
    // }
    //#endif

    jointLR(&IP, R[16], L[16], 64);               // 拼接 * 注意调换位置
    permutation(output, 64, IP, 64, IP_1_table);  // 逆置换

#if DEBUG_F || DEBUG_F_D
    printf("OUT = %llx\n", *output);
    printf("*** END DES 64bits ***\n");
#endif
    return;
}

unsigned char readBit(const uint64 n, const int len,
                      const unsigned char index) {
    uint64 mask = (uint64)1 << (len - 1 - index);
    if ((mask & n) == 0) {
        return 0;
    } else {
        return 1;
    }
}
void writeBit(uint64 *n, const int len, const unsigned char index,
              const unsigned char bit) {
    uint64 mask = (uint64)1 << (len - 1 - index);
    uint64 umask = ~mask;
    if (bit == 1) {
        *n = *n | mask;
    } else {
        *n = *n & umask;
    }
}

// splitLR 将 bit 位的 text 分成 (bit / 2) 位的 L 和 (bit / 2) 位的 R
void splitLR(uint32 *L, uint32 *R, const uint64 text, const int bit) {
    uint64 umask = 1;
    for (int i = 0; i < bit / 2; ++i) {
        umask |= 1 << i;
    }
    *R = text & umask;
    umask <<= (bit / 2);
    *L = (text & umask) >> (bit / 2);
}

// jointLR 将 (bit/2) 位的 L 和 (bit/2) 位的 R 拼接成 bit 位的 text
void jointLR(uint64 *text, const uint32 L, const uint32 R, const int bit) {
    *text = L;
    *text = (*text) << (bit / 2);
    *text = (*text) | (uint64)R;
}

// 辅助函数实现
void leftCircularShift(uint32 *des, const uint32 src, const int n,
                       const int bit) {
    for (int i = 0; i < bit; ++i) {
        *des |= ((src & (1 << i)) >> i) << ((n + i) % bit);
    }
}

// permulation 置换函数，根据置换表 table 将 src 置换为 des
void permutation(uint64 *des, const int lend, const uint64 src, const int lens,
                 const unsigned char *table) {
    for (int i = 0; i < lend; ++i) {
        writeBit(des, lend, i, readBit(src, lens, table[i] - 1));
#if DEBUG_DES || DEBUG_F_P
        printf("%d - %d : ", i, table[i]);
        printb(*des, lend);
#endif
    }
}

// geneKeys 根据密钥 key 生成密钥组 keys
void geneKeys(uint48 *keys, const uint64 key) {
#if DEBUG_DES
    printf("K = ");
    printb(key, 64);
#endif
    uint64 key56 = 0;
    permutation(&key56, 56, key, 64, PC_1);
#if DEBUG_DES
    printf("K+ = ");
    printb(key56, 56);
#endif

    uint28 *c = (uint28 *)malloc(17 * sizeof(uint28));
    uint28 *d = (uint28 *)malloc(17 * sizeof(uint28));
    splitLR(&c[0], &d[0], key56, 56);

    for (int i = 1; i <= 16; ++i) {
        if (i == 1 || i == 2 || i == 9 || i == 16) {
            leftCircularShift(&c[i], c[i - 1], 1, 28);
            leftCircularShift(&d[i], d[i - 1], 1, 28);
        } else {
            leftCircularShift(&c[i], c[i - 1], 2, 28);
            leftCircularShift(&d[i], d[i - 1], 2, 28);
        }
    }
#if DEBUG_DES
    for (int i = 0; i <= 16; ++i) {
        printf("C[%d] = ", i);
        printb(c[i], 28);
        printf("D[%d] = ", i);
        printb(d[i], 28);
    }
#endif
    for (int i = 0; i <= 16; ++i) {
        jointLR(&key56, c[i], d[i], 56);
        permutation(&keys[i], 48, key56, 56, PC_2);
    }
#if DEBUG_DES
    for (int i = 1; i <= 16; ++i) {
        printf("K%2d = ");
        printb(keys[i], 48);
    }
#endif
}

// feistel 轮函数
uint32 feistel(const uint32 R, const uint48 K) {
    uint48 E_R = 0;
    permutation(&E_R, 48, R, 32, E_expansion);
    uint48 K_E_R = K ^ E_R;

    uint32 S_B = 0;

    for (int i = 0; i < 8; ++i) {
        uint32 row = readBit(K_E_R, 48, 6 * i + 0);
        row = row * 2 + readBit(K_E_R, 48, 6 * i + 5);
        uint32 col = readBit(K_E_R, 48, 6 * i + 1);
        col = col * 2 + readBit(K_E_R, 48, 6 * i + 2);
        col = col * 2 + readBit(K_E_R, 48, 6 * i + 3);
        col = col * 2 + readBit(K_E_R, 48, 6 * i + 4);

        unsigned char tmp = S_boxes[i][row * 16 + col];
        for (int j = 0; j < 4; ++j) {
            if (tmp & ((char)1 << (3 - j))) {
                writeBit((uint64 *)&S_B, 32, i * 4 + j, 1);
            } else {
                writeBit((uint64 *)&S_B, 32, i * 4 + j, 0);
            }
        }
    }
    uint32 f = 0;
    permutation((uint64 *)&f, 32, S_B, 32, P_box);

    return f;
}

// init () 检测运行环境
bool init() {
    // 检测 long long 数据类型的大小
    if (sizeof(unsigned long long) != 8) {
        printf("期望 unsigned long long 的长度为 8 个字节，期望没有满足");
        return 0;
    }
    // 检测 int 数据类型的大小
    if (sizeof(unsigned int) != 4) {
        printf("期望 unsigned int 的长度为 4 个字节，期望没有满足");
        return 0;
    }
    // 检测是否满足小端序
    unsigned char tmp = 0;
    unsigned int mask = 0x12345678;
    memcpy(&tmp, &mask, 1);
    if (tmp == 0x12) {
        printf("期望环境为小端序，期望没有满足");
        return 0;
    } else if (tmp != 0x78) {
        printf("检测端序出错");
        return 0;
    }
    return 1;
}

// printb () 打印整型 n 末 len 位的二进制
void printb(const uint64 n, const int len) {
    for (int i = len - 1; i >= 0; --i) {
        if (n & ((uint64)1 << i)) {
            putchar('1');
        } else {
            putchar('0');
        }
        if (i % 8 == 0) {
            putchar(' ');
        }
    }
    putchar(10);
}