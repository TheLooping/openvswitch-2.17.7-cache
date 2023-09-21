#include "my_forward.h"


//对请求结构体的字段进行修改
void receiveRequest(request_t *myRequest, uint64_t thisNodeCacheCapacity){
    myRequest->capacity = myRequest->capacity + thisNodeCacheCapacity;
    myRequest->tsb ++;
}

// 根据key判断缓存命中,成功返回key_value_pair的id，失败返回-1
key_value_pair_t *forwardRequest(memory_pool_t *mp, request_t *myRequest) {
    // 更新myRequest路径跳数、路径缓存容量
	receiveRequest(myRequest, mp->num_free_chunk * CHUNK_SIZE);
    // 根据key查找缓存
    // 如果缓存命中，删除缓存，更新tsb、tsi，根据结构体forwardData转发
    // 如果缓存未命中，直接返回
    int32_t id;
    if((id = find_key_value_pair_by_key(mp, myRequest->key)) == -1){
        //缓存未命中
        return NULL;
    }
    // LRU缓存替换策略
    // 缓存命中，把key_value_pair移到链表头部
    move_key_value_pair_to_head(mp, (key_value_pair_t*)(mp->hash_table_start + id * sizeof(key_value_pair_t)));
	return mp->key_value_pair_table_alloc_list;
    // TODO: 封装结构体forwardData
}



//根据缓存策略，判断是否缓存数据
void forwardDataANDPara(memory_pool_t *mp, forward_data_t *myForwardData) {
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


