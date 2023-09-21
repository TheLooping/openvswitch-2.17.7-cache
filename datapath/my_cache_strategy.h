#pragma once
#include <stdbool.h>

//设定prob缓存策略的参数
#define CRITICAL_VALUE 0.3
#define TTW 2

//缓存策略参数结构体
struct cacheStrategyPara {
    int tsi;
    int tsb;
    int remainCacheCapacity;
    int thisNodeCacheCapacity;
};
void initCacheStrategyPara(struct cacheStrategyPara* cacheStrategyPara);

bool whetherCache(struct cacheStrategyPara* cacheStrategyPara);
bool lcdCacheStrategy(int tsb);
bool probCacheStrategy(struct cacheStrategyPara* cacheStrategyPara);
