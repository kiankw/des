# DES 算法

> C 语言实现 DES 算法，本仓库用于学习 DES
> 该仓库代码根据 [The DES Algorithm Illustrated. by J. Orlin Grabbe](https://page.math.tu-berlin.de/~kant/teaching/hess/krypto-ws2006/des.htm) 实现。 (这篇文章的翻译版很适合 DES 入门新手)

### 使用说明

将 `include/des.h` 和 `src/des.c` 放入你的项目中便可使用 DES 算法

以下过程可以测试 DES 算法过程

```shell
git clone https://gitee.com/kiankw/des
cd des
make run
```

修改 `src/main.c` 中的注释，可选择测试其他函数

修改 `src/des.c` 中的 DEBUG 宏，可显示 DES 运行过程

## 学习过程

技术要点

* 深入理解 DES 过程
* 熟练使用 C 语言位操作，如写入、写出、移位、异或
    * 写入写出采用 mask 和 umask，如 mask = 0010，umask = 1101
    * 判断 n & mask 可取出该位
    * `n = n | mask` 可在该位写入 1，`n = n & umask` 可在该位写入 0
* 熟悉 C 语言特征，如端序、数据类型

DES 算法

* 一种块加密算法，一个块为 64bits
* 密钥
    * 密钥为 64 位，但只有 56 位有效
* DES 过程
    * （填充数据）
    * 初始化密钥组
        * PC 1 置换 (64 -> 56)
        * 分左右，分别循环左移 16 次，得到 16 组左右
        * 每组合并左右后，进行 PC 2 置换（16 * 56->16 * 48)
    * IP 置换
    * 分为左右 L R
    * 16 次轮函数
        * L_i = R_i-1
        * R_i = L_i - 1 按位异或 F 函数（R_i-1, K_i or K_17-i)
            * Feistel（F 轮函数）
                * E 拓展 (32 -> 48)
                * 与 key 异或（48 -> 48)
                * S 盒处理 (48 -> 32)
                * P 置换 (32 -> 32)
    * 拼接 L_16, R_16
    * IP 逆置换
    * （去除填充）
* 主要运算
    * 置换
        * 根据置换表，将某一位的数据放到另一个位置，置换表是给定的
        * DES 标准提供的置换表中，索引从 1 开始而不是从 0 开始，索引从前向后数，如 64 位数据的 第1 位表示数值的第 63 位
    * 移位
        * DES 中如密钥生成等需要进行非 c 语言数据类型存在的循环移位，如对 28 位的数据进行循环移位，或对 56 位的数据进行循环移位，这里需要做一些范围判断。
    * 异或
        * 在算法内部用 unsigned long long 存放数据，可以直接用 ^ 按位异或
* 加密和解密的区别
    * 加密和解密的区别在于传入 F 轮函数的 key 参数不同
    * 加密时按 key1 到 key16 的顺序传入
    * 解密时按 key16 到 key 1 的顺序传入
* 陷阱
    * 将某信息写入某内存使用 memcpy，memcpy 的参数有运算时，需要先转成 void* 或 unsigned char * 再运算
        * 错误写法 `memcpy(&M + j, &lenp, 1);`  M 是 uint64 类型，&M + 1 偏移了 8 个地址
        * 正确写法 `memcpy((void *)&M + j, &lenp, 1);`
    * c 语言是小端序
        * unsigned long long 和 unsigned char 转换时，需要考虑小端序
* 填充
    * 采用 PKCS#5 (RFC 8018) 标准
        * 原始明文消息最后的分组不够 8 个字节 (64位) 时，在末尾以 字节填满，填入的字节取值相同，都是填充的字节数目；
        * 原始明文消息刚好分组完全时，在明文末尾额外填充8个字 节 (即增加一个完整分组)，每个字节取值都是08
    * 即填充的内容和个数均为 8 - len % 8 （len 表示原数据的字节数）
* 其他
    * 秘钥储存为 64 位，但每 8 位都没有被用上（也就是第8, 16, 24, 32, 40, 48, 56, 和64位都没有被用上）
* 参考文献
    * [The DES Algorithm Illustrated. by J. Orlin Grabbe](https://page.math.tu-berlin.de/~kant/teaching/hess/krypto-ws2006/des.htm)
