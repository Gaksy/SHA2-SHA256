#include "SHA2_SHA256.h"

#define MESSAGE_BLCK_MAXSIZE_BYTE   64
#define MESSAGE_CONT_HEXEND         0x80

static char NS_16_SYBSET[16]{ '0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F' };

bool setMessage_StdStr(SHA2_SHA256& object, const std::string& const MESSAGE) {
    if (MESSAGE.empty())
        return false;

    const uint64_t MESSAGE_LENGTH = MESSAGE.length();
    uint8_t* messageArry = new uint8_t[MESSAGE_LENGTH];

    for (uint64_t index = static_cast<uint64_t>(0); index < MESSAGE_LENGTH; index++)
        messageArry[index] = MESSAGE[index];
    bool suc = object.set_messageParsing(messageArry, MESSAGE_LENGTH);

    if (messageArry)
        delete[] messageArry;

    return suc;
}

//哈希初始值             Sec FIPS PUB 180-4 - 5.3.3
static uint32_t SHA2_SHA256_CONST_H[8]{
    0x6A09E667,0xBB67AE85,
    0x3C6EF372,0xA54FF53A,
    0x510E527F,0x9B05688C,
    0x1F83D9AB,0x5BE0CD19
};

//哈希常量              Sec FIPS PUB 180-4 - 4.2.2
static uint32_t SHA2_SHA256_CONST_K[64]{
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};


//构造
SHA2_SHA256::SHA2_SHA256() {
    //初始化数据
    messageBlockNum = static_cast<uint64_t>(0);
    messageBlock    = nullptr;
}

SHA2_SHA256::~SHA2_SHA256() {
    //删除消息
    clear_message();
}

//函数实现

bool SHA2_SHA256::set_messageParsing(const uint8_t* const MESSAGE_ARRY, const uint64_t& const MESSAGE_LENGTH) {
    //检查数据合法性
    if (!MESSAGE_ARRY || !MESSAGE_LENGTH || MESSAGE_LENGTH * 8 == UINT64_MAX)
        return false;

    //删除消息
    clear_message();

    //计算需要的消息块数量
    messageBlockNum = static_cast<uint64_t>(ceil(static_cast<double>(MESSAGE_LENGTH * 8 + 1) / static_cast<double>(512)));

    messageBlock = new uint32_t * [messageBlockNum];
    uint64_t indexMax = messageBlockNum - 1;

    for (uint64_t index_BlockNum = static_cast<uint64_t>(0); index_BlockNum < indexMax; index_BlockNum++) {
        messageBlock[index_BlockNum] = new uint32_t[MESSAGE_BLCK_MAXSIZE_32]{ 0 };

        uint8_t* blockPtr = (uint8_t*)messageBlock[index_BlockNum];
        uint8_t  times = 0;
        uint8_t* blockEndPtr = blockPtr + MESSAGE_BLCK_MAXSIZE_BYTE;

        while (blockPtr < blockEndPtr)
            *(blockPtr++) = MESSAGE_ARRY[index_BlockNum * MESSAGE_BLCK_MAXSIZE_BYTE + times++];
    }

    //处理最后一个数据块
    uint8_t index_lasetBlockMax = static_cast<uint8_t>((MESSAGE_LENGTH * 8 - indexMax * 512) / 8);
    messageBlock[indexMax] = new uint32_t[MESSAGE_BLCK_MAXSIZE_32]{ 0 };
    uint8_t* blockPtr = (uint8_t*)messageBlock[indexMax];
    uint8_t  times = 0;
    uint8_t* blockEndPtr = blockPtr + index_lasetBlockMax;

    while (blockPtr < blockEndPtr)
        *(blockPtr++) = MESSAGE_ARRY[indexMax * MESSAGE_BLCK_MAXSIZE_BYTE + times++];

    *(blockEndPtr++) = MESSAGE_CONT_HEXEND;

    uint64_t messageLengt_BigEndian = MESSAGE_LENGTH * 8;

    //端序转换
    if (is_LittleEndian()) {
        conv_uint64_to_BigOrLittleEndian(messageLengt_BigEndian);
    }

    //写入消息长度
    //messageBlock[indexMax][MESSAGE_BLCK_MAXSIZE_32 - 1] = messageLengt_BigEndian;
    conv_uint64_to_uint8_t(messageLengt_BigEndian, (uint8_t*)messageBlock[indexMax] + 56);

    if (is_LittleEndian()) {
        for (uint64_t index_blockNum = static_cast<uint64_t>(0); index_blockNum < messageBlockNum; index_blockNum++)
            for (uint64_t index_CountNum = static_cast<uint64_t>(0); index_CountNum < MESSAGE_BLCK_MAXSIZE_32; index_CountNum++)
                conv_uint32_to_BigOrLittleEndian(&messageBlock[index_blockNum][index_CountNum]);
    }

    return true;
}

bool SHA2_SHA256::get_calculationShaVal(std::string& shaVal)const {
    if (!messageBlock)
        return false;

    auto shaValToStr = [](const uint32_t& _10NUMSYSTEM)->std::string {
        std::string _16NumSystem;
        if (_10NUMSYSTEM == 0 || _10NUMSYSTEM == 1) {
            _16NumSystem.push_back(NS_16_SYBSET[_10NUMSYSTEM]);
        }
        else {
            uint32_t Quotients = _10NUMSYSTEM;
            for (uint32_t index = static_cast<uint32_t>(0); Quotients >= static_cast<uint32_t>(16); index++) {
                _16NumSystem += NS_16_SYBSET[Quotients % 16];
                Quotients = floor((long double)Quotients / (long double)16);
            }
            if (Quotients != static_cast<uint32_t>(0))
                _16NumSystem += NS_16_SYBSET[Quotients];
            std::reverse(_16NumSystem.begin(), _16NumSystem.end());
        }
        return _16NumSystem;
    };

    uint32_t workingVar[8], orWorkingVar[8], hashVal[8];

    //初始化哈希值
    for (size_t index = 0; index < 8; index++)
        hashVal[index] = SHA2_SHA256_CONST_H[index];

    for (uint64_t index_BlockNum = static_cast<uint64_t>(0); index_BlockNum < messageBlockNum; index_BlockNum++) {
        uint32_t W_Array[64]{ 0 };

        for (uint64_t wIndex = static_cast<uint64_t>(0); wIndex < MESSAGE_BLCK_MAXSIZE_32; wIndex++)
            W_Array[wIndex] = messageBlock[index_BlockNum][wIndex];

        for (uint64_t wIndex = static_cast<uint64_t>(16); wIndex < static_cast<uint64_t>(64); wIndex++)
            W_Array[wIndex] = this->shaFun_SmlSigma1((W_Array[wIndex - 2])) + (W_Array[wIndex - 7]) + this->shaFun_SmlSigma0((W_Array[wIndex - 15])) + (W_Array[wIndex - 16]);

        for (uint64_t index = static_cast<uint64_t>(0); index < static_cast<uint64_t>(8); index++) {
            //orWorkingVar[index] = workingVar[index];
            workingVar[index] = hashVal[index];
        }

        for (uint64_t tIndex = static_cast<uint64_t>(0); tIndex < static_cast<uint64_t>(64); tIndex++) {
            uint32_t T1 = workingVar[7] + this->shaFun_BigSigma1(workingVar[4]) + this->shaFun_Ch(workingVar[4], workingVar[5], workingVar[6]) + SHA2_SHA256_CONST_K[tIndex] + W_Array[tIndex];
            uint32_t T2 = this->shaFun_BigSigma0(workingVar[0]) + shaFun_Maj(workingVar[0], workingVar[1], workingVar[2]);
            workingVar[7] = workingVar[6];
            workingVar[6] = workingVar[5];
            workingVar[5] = workingVar[4];
            workingVar[4] = workingVar[3] + T1;
            workingVar[3] = workingVar[2];
            workingVar[2] = workingVar[1];
            workingVar[1] = workingVar[0];
            workingVar[0] = T1 + T2;
        }

        for (uint64_t index = static_cast<uint64_t>(0); index < static_cast<uint64_t>(8); index++)
            hashVal[index] = workingVar[index] + hashVal[index];
    }

    shaVal.clear();

    //合并哈希值
    for (uint64_t index = static_cast<uint64_t>(0); index < static_cast<uint64_t>(8); index++)
        shaVal += shaValToStr(hashVal[index]);

    return true;
}