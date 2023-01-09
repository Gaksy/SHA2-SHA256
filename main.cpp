#include "SHA2_SHA256.h"

#include <stdio.h>
#include <time.h>

int main(void) {
    //TEST
    SHA2_SHA256 object;

    std::string testString = "abc"; 
    std::string testSha;

    setMessage_StdStr(object, testString);

    if (object.get_calculationShaVal(testSha)) {
        printf("%s\n", testSha.c_str());
    }
    else
        printf("计算哈希值失败\n");

    system("pause");
    return 0;
}