#include "my_memory_pool.h"
#include "my_cache_strategy.h"
#ifndef _FORWARD_H_
#define _FORWARD_H_


//自定义请求结构体
typedef struct request_t
{
    char key[KEY_LEN];// 存储key，比如前4个字符
    int tsb;//路径跳数
    uint64_t capacity;//路径缓存容量
}request_t;

//自定义转发数据包结构体
typedef struct forward_data_t
{
    char *start;
    int len;
    //跳数相关
    int tsi;//路径总跳数
    int tsb;//当前跳数
    int remainCapacity;//缓存容量
}forward_data_t;

void initForwardData(forward_data_t* myForwardData);
void receiveRequest(request_t *myRequest, uint64_t thisNodeCacheCapacity);
key_value_pair_t *forwardRequest(memory_pool_t *mp, request_t *myRequest);
void forwardDataANDPara(memory_pool_t *mp, forward_data_t *myForwardData);

#endif