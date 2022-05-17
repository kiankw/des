
#ifndef DES_TEST_H
#define DES_TEST_H

#include "des.h"

int TestDES();
int TestDES_En1();
int TestDES_En2();
int TestDES_De();
int TestDES_En_De1();
int TestDES_En_De2();
// 内部细节测试
int TestFeistel();
int TestGeneKeys();

#endif  // DES_TEST_H