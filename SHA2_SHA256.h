#pragma once
//项目名(eg)：     SECURE HASH ALGORITHMS -- SHA-256
//项目名(zh-cn)：  安全哈希算法 -- SHA-256
//创建时间：       2022-11-06
//源代码参与者：   HongRen Fu
//参考规范文档：    FEDERAL INFORMATION PROCESSING STANDARDS
//                  PUBLICATION 180-4
//                  Secure Hash Standard (SHS)
//
//使用命名空间：   GKCODE::SHA

#include <inttypes.h>
#include <string>
#include <math.h>

#define MESSAGE_BLCK_MAXSIZE_32     static_cast<size_t>(16)

class SHA2_SHA256 {
private:    //DATA
    uint64_t    messageBlockNum;
    uint32_t**  messageBlock;

public:     //构造
    SHA2_SHA256();
    ~SHA2_SHA256();

public:     //PUBLIC FUNCTION
    /// <summary>
    /// 设置要计算的消息，并对齐分解
    /// </summary>
    /// <param name="MESSAGE_ARRY">要计算哈希值的消息</param>
    /// <param name="MESSAGE_LENGTH">消息的大小(最大可用下标 + 1)</param>
    /// <returns>设置是否成功</returns>
    bool set_messageParsing(const uint8_t* const MESSAGE_ARRY, const uint64_t& MESSAGE_LENGTH);
    /// <summary>
    /// 计算设置的消息的哈希值
    /// </summary>
    /// <param name="dec_shaVal">目标哈希值字符串</param>
    /// <returns>计算是否成功</returns>
    bool get_calculationShaVal(std::string& dec_shaVal)const;

private:    //PRIVATE FUNCTION
    inline void clear_message(void) {
        if (messageBlock) {
            for (uint64_t index_blockNum = static_cast<uint64_t>(0); index_blockNum < messageBlockNum; index_blockNum++)
                if(&messageBlock[index_blockNum])
                    delete[] messageBlock[index_blockNum];
            delete[] messageBlock;
        }
    }

    inline bool is_LittleEndian(void) {
        uint32_t u16 = 0x00FF;
        return *((uint8_t*)&u16) == 0xFF && *(((uint8_t*)&u16) + 1) == 0x00;
    }

    inline void conv_uint32_to_BigOrLittleEndian(uint32_t* UINT32) {
        *UINT32 =
            ((*UINT32 & 0xFF000000) >> 24) |
            ((*UINT32 & 0x00FF0000) >> 8) |
            ((*UINT32 & 0x0000FF00) << 8) |
            ((*UINT32 & 0x000000FF) << 24);
        return;
    }

    inline void conv_uint64_to_BigOrLittleEndian(uint64_t& UINT64) {
        UINT64 =
            ((UINT64 & 0xFF00000000000000) >> 56) |
            ((UINT64 & 0x00FF000000000000) >> 40) |
            ((UINT64 & 0x0000FF0000000000) >> 24) |
            ((UINT64 & 0x000000FF00000000) >> 8) |
            ((UINT64 & 0x00000000FF000000) << 8) |
            ((UINT64 & 0x0000000000FF0000) << 24) |
            ((UINT64 & 0x000000000000FF00) << 40) |
            ((UINT64 & 0x00000000000000FF) << 56);
        return;
    }

    inline void conv_uint64_to_uint8_t(const uint64_t& const ORIGINAL,uint8_t* dec) {
        for (size_t index = static_cast<size_t>(0); index < 8; index++, dec++)
            *dec = *((uint8_t*)&ORIGINAL + index);
        return;
    }

private:    //PRIVATE SHA FUNCTION
    //Ch Functions                      Sec FIPS PUB 180-4 - 4.1.2
    inline uint32_t shaFun_Ch(const uint32_t& x, const uint32_t& y, const uint32_t& z)const {
        return (x & y) ^ (~x & z);
    }
    //Maj Functions                     Sec FIPS PUB 180-4 - 4.1.2
    inline uint32_t shaFun_Maj(const uint32_t& x, const uint32_t& y, const uint32_t& z)const {
        return (x & y) ^ (x & z) ^ (y & z);
    }
    //Big Sigma{256}0 Functions         Sec FIPS PUB 180-4 - 4.1.2
    inline uint32_t shaFun_BigSigma0(const uint32_t& x)const {
        return ((x >> 2) | (x << 30)) ^ ((x >> 13) | (x << 19)) ^ ((x >> 22) | (x << 10));
    }
    //Big Sigma {256}1 Functions        Sec FIPS PUB 180-4 - 4.1.2
    inline uint32_t shaFun_BigSigma1(const uint32_t& x)const {
        return ((x >> 6) | (x << 26)) ^ ((x >> 11) | (x << 21)) ^ ((x >> 25) | (x << 7));
    }
    //Small Sigma {256}0 Functions      Sec FIPS PUB 180-4 - 4.1.2
    inline uint32_t shaFun_SmlSigma0(const uint32_t& x)const {
        return ((x >> 7) | (x << 25)) ^ ((x >> 18) | (x << 14)) ^ (x >> 3);
    }
    //Small Sigma {256}1 Functions      Sec FIPS PUB 180-4 - 4.1.2
    inline uint32_t shaFun_SmlSigma1(const uint32_t& x)const {
        return ((x >> 17) | (x << 15)) ^ ((x >> 19) | (x << 13)) ^ (x >> 10);
    }
 };

bool setMessage_StdStr(SHA2_SHA256& object, const std::string& const MESSAGE);