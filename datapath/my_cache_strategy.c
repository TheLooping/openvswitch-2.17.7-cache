#include "my_cache_strategy.h"
#include "my_memory_pool.h"


//初始化缓存策略参数
void initCacheStrategyPara(struct cacheStrategyPara* cacheStrategyPara) {
    cacheStrategyPara->tsi = 10;
    cacheStrategyPara->tsb = 1;
    cacheStrategyPara->remainCacheCapacity = 10000;
    cacheStrategyPara->thisNodeCacheCapacity = 100;
}

//判断节点是否对数据缓存
bool whetherCache( struct cacheStrategyPara* cacheStrategyPara) {
    //LCD缓存策略
    return lcdCacheStrategy(cacheStrategyPara->tsb);
    //prob缓存策略
     //return probCacheStrategy(cacheStrategyPara);
}



//LCD缓存策略   0:不缓存  1:缓存
//感知上下邻居节点，每一次数据/文件请求，当缓存发生命中时，
//在数据信息命中节点的下一跳缓存数据包，即缓存概率为1，其他节点缓存概率为0
bool lcdCacheStrategy(int tsb) {
    if (tsb == 2) {//数据发送节点本身tsb=1，下一跳节点tsb=2
        return true;
    }
    else {
        return false;
    }
}

//prob缓存策略   p
//总跳数tsi、当前跳数tsb、剩余所有节点缓存总量remainCacheCapacity、当前节点缓存量thisNodeCacheCapacity
bool probCacheStrategy(struct cacheStrategyPara* cacheStrategyPara) {
    float cacheWeight = (float)cacheStrategyPara->tsb / (float)cacheStrategyPara->tsi;
    //TODO: TTW调参数
    float timesIn = (float)cacheStrategyPara->remainCacheCapacity /((float)cacheStrategyPara->thisNodeCacheCapacity * TTW) ;
    float prob = cacheWeight * timesIn;

    if (prob > CRITICAL_VALUE) {
        return true;
    }
    else {
        return false;
    }
}