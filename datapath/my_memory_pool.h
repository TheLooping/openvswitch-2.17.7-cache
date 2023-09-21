#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#ifndef _MEMORY_POOL_T_H_
#define _MEMORY_POOL_T_H_


#define KB (uint64_t)(1 << 10)
#define MB (uint64_t)(1 << 20)
#define GB (uint64_t)(1 << 30)
// 最多存放100条key-value pair
#define MAX_NUM_KEY_VALUE_PAIR 10
#define CHUNK_SIZE 64 //每个chunk大小为1KB
// 截取key-value pair的前4个字符作为key
#define KEY_LEN 4


// key-value pair
typedef struct key_value_pair_t {
    int32_t id;
    uint8_t is_alloc;// 用于标识key-value pair是否占用
    uint8_t pirority;// 用于标识key-value pair的优先级    

    char *value_start;// value起始地址
    uint64_t value_size;// value大小
    
    uint64_t hash_value;
    //intersete key
    char key[KEY_LEN];// 存储内容关键字，比如前4个字符

    int64_t start_chunk_id;//起始块号
    int64_t num_chunk;//块数
    struct key_value_pair_t *prev, *next;

} key_value_pair_t;

// chunk头部
typedef struct chunk_header_t {
    uint32_t chunk_id;// 用于标识chunk的id
    uint8_t is_alloc;// 用于标识chunk是否占用
    char* chunk_start;// chunk的起始地址
    struct chunk_header_t *prev, *next;
} chunk_header_t;

// 内存池
typedef struct memory_pool_t {
    uint64_t memory_pool_t_size;// 内存池大小  
    int64_t num_total_chunk;// chunk总数
    int64_t num_free_chunk;// 空闲chunk总数
    int64_t num_total_key_value_pair;// key_value_pair总数
    int64_t num_free_key_value_pair;// 空闲key_value_pair总数
    char *memory_pool_t_start;// 内存池起始地址 
    char *hash_table_start;// hash-table起始地址
    char *chunk_header_start;// chunk_header起始地址
    char *chunks_start;// chunk起始地址
    key_value_pair_t *key_value_pair_table_free_list;// key-value pair链表
    key_value_pair_t *key_value_pair_table_alloc_list;// key-value pair空闲链表
    chunk_header_t *free_list;// 空闲chunk链表
    chunk_header_t *alloc_list;// 已分配chunk链表
} memory_pool_t;

// 内存池初始化
memory_pool_t* memory_pool_t_init(uint64_t requir_size);
// 块分配，指定块从free_list移动到alloc_list
void chunk_alloc(memory_pool_t* mp, uint32_t chunk_id);
// 块分配，指定块从alloc_list移动到free_list
void chunk_free(memory_pool_t* mp, uint32_t chunk_id);
void key_value_pair_free(memory_pool_t* mp, key_value_pair_t* key_value_pair);
void key_value_pair_alloc(memory_pool_t* mp, key_value_pair_t* key_value_pair);


// key-value pair初始化
void key_value_pair_init(key_value_pair_t* key_value_pair, char* value_start, uint64_t value_size);
// hash生成key-value pair
uint64_t hash(void* value, uint64_t len);

// 释放key-value pair
void free_key_value_pair(memory_pool_t* mp, key_value_pair_t *key_value_pair);
// 从key_value_pair_table中根据key查找key_value_pair,成功返回key_value_pair的id，失败返回-1
int32_t find_key_value_pair_by_key(memory_pool_t* mp, char* key);

// 为key_value_pair分配chunk
void chunk_alloc_for_key_value_pair(memory_pool_t* mp, char* value_start, uint64_t value_size);

// 将key_value_pair的value写入chunk
void write_value_to_chunk(memory_pool_t* mp, key_value_pair_t* key_value_pair);
// 存储key-value pair
void store_key_value_pair(memory_pool_t *mp, char *value_start, uint64_t value_size);

// 把key-value pair从key_value_pair_table链表中移到链表头部
void move_key_value_pair_to_head(memory_pool_t* mp, key_value_pair_t* key_value_pair);

#endif // _MEMORY_POOL_t_H_