# openvswitch-2.17.7+cache
## OVS加缓存
0. 内存池
1. LCD、Prob缓存放置
2. LRU缓存替换

## 修改内容：
vswitchd\ovs-vswitchd.c的main函数里创建的memory_pool_t *mp内存池全局变量
datapath/vport.c
