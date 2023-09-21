#include "my_cache.h"


// 缓存模块
void cache_module(memory_pool_t *mp, char *payload_start, uint32_t len){
    if (memcmp(payload_start, "REQ", 3) == 0)
    {
        // 转发请求
        request_t *myRequest = (request_t *)(payload_start + 3);
        key_value_pair_t* kv;
        if((kv = forwardRequest(mp, myRequest)) == NULL){
            return;
        }
        // 缓存命中
        // TODO : 修改 skb(sk_buff) 的 五元组、payload;修改key(sw_flow_key)的五元组 

    }
    else if (memcmp(payload_start, "RES", 3) == 0)
    {
        // 转发响应
        forward_data_t *myForwardData;
        myForwardData = (forward_data_t *)(payload_start + 3);
        myForwardData->start = payload_start + 3 + sizeof(forward_data_t);
        myForwardData->len = len - 3 - sizeof(forward_data_t);
        forwardDataANDPara(mp, myForwardData);
    }
}



// 改数据包
void cache_data(memory_pool_t *mp, forward_data_t *myForwardData)
{
    // 更新myForwardData的tsb(44)、remainCapacity(57)
    myForwardData->tsb ++;

    //判断是否缓存
    struct cacheStrategyPara cacheStrategyPara = {0};
    cacheStrategyPara.tsb = myForwardData->tsb;
    cacheStrategyPara.tsi = myForwardData->tsi;
    cacheStrategyPara.remainCacheCapacity = myForwardData->remainCapacity;
    cacheStrategyPara.thisNodeCacheCapacity = mp->num_free_chunk * CHUNK_SIZE;
    if (whetherCache(&cacheStrategyPara)) {
        //满足缓存策略
        store_key_value_pair(mp, myForwardData->start, myForwardData->len);
    }

    myForwardData->remainCapacity -= mp->num_free_chunk * CHUNK_SIZE;
}
