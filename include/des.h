#ifndef DES_H
#define DES_H

typedef unsigned long long uint64;
typedef unsigned long long uint48;
typedef unsigned int uint32;
typedef unsigned int uint28;
typedef unsigned char uint8;
typedef unsigned char uint6;
typedef unsigned char uint4;
typedef char bool;

// ****** 主要函数 ******

// 数据采用 unsigned char 存储，一个 unsigned char 为一个字节
// DES_Encrypt () DES 加密算法，
// 使用 8 字节的 key 将 lens 字节的 src 转化为 lend 字节的 des
void DES_Encrypt(unsigned char *des, unsigned long long *lend,
                 const unsigned char *src, const unsigned long long lens,
                 const unsigned long long key);

// DES_Decrypt () DES 解密算法，
// 使用 8 字节的 key 将 lens 字节的 src 转化为 lend 字节的 des
void DES_Decrypt(unsigned char *des, unsigned long long *lend,
                 const unsigned char *src, const unsigned long long lens,
                 const uint64 key);

// ****** 辅助函数（算法内部使用，不建议外部调用） ******
// init () 检测运行环境
bool init();

// des64 () DES 算法中心函数，输入 64 位，输出 64 位
void des64(uint64 *output, const uint64 M, const uint64 key, bool isEn);

// geneKeys () 根据密钥 key 生成密钥组 keys
void geneKeys(uint48 *keys, const uint64 key);

// permulation () 置换函数，根据置换表 table 将 src 置换为 des
void permutation(uint64 *des, const int lend, const uint64 src, const int lens,
                 const unsigned char *table);

// splitL () 将 bit 位的 text 分成 (bit/2) 位的 L 和 (bit/2) 位的 R
void splitLR(uint32 *L, uint32 *R, const uint64 text, const int bit);

// jointLR () 将 (bit/2) 位的 L 和 (bit/2) 位的 R 拼接成 bit 位的 text
void jointLR(uint64 *text, const uint32 L, const uint32 R, const int bit);

// feistel () DES 轮函数
uint32 feistel(const uint32 R, const uint48 K);

// leftCircularShift () 循环左移位，将 bit 位的 src 循环左移 n 位得到 des
void leftCircularShift(uint32 *des, const uint32 src, const int n,
                       const int bit);

// printb () 打印整型 n 末 len 位的二进制
void printb(const uint64 n, const int len);

#endif  // DES_H