#include "my_memory_pool.h"

memory_pool_t *memory_pool_t_init(uint64_t requir_size)
{
    memory_pool_t *mp = (memory_pool_t *)malloc(sizeof(memory_pool_t)); // memory_pool_t，其中memory_pool_t_start指向内存池
    mp->num_total_chunk = requir_size / CHUNK_SIZE + 1;
    mp->num_free_chunk = mp->num_total_chunk;
    mp->num_total_key_value_pair = MAX_NUM_KEY_VALUE_PAIR;
    mp->num_free_key_value_pair = mp->num_total_key_value_pair;
    mp->memory_pool_t_size = mp->num_total_chunk * CHUNK_SIZE + mp->num_total_chunk * sizeof(chunk_header_t) + mp->num_total_key_value_pair * sizeof(key_value_pair_t);

    mp->memory_pool_t_start = (char *)malloc(mp->memory_pool_t_size); // hash-table + header + chunk

    memset(mp->memory_pool_t_start, 0, mp->memory_pool_t_size);
    mp->hash_table_start = mp->memory_pool_t_start;
    mp->chunk_header_start = mp->memory_pool_t_start + mp->num_total_key_value_pair * sizeof(key_value_pair_t);
    mp->chunks_start = mp->chunk_header_start + mp->num_total_chunk * sizeof(chunk_header_t);
    // 初始化key_value_pair_table链表，存在hash_table_start中
    mp->key_value_pair_table_alloc_list = NULL;
    mp->key_value_pair_table_free_list = (key_value_pair_t *)(mp->hash_table_start);
    int i = 0;
    while (i < mp->num_total_key_value_pair)
    {
        mp->key_value_pair_table_free_list[i].id = i;
        mp->key_value_pair_table_free_list[i].prev = (i == 0) ? NULL : &mp->key_value_pair_table_free_list[i - 1];
        mp->key_value_pair_table_free_list[i].next = (i == mp->num_total_key_value_pair - 1) ? NULL : &mp->key_value_pair_table_free_list[i + 1];
        i++;
    }
    mp->key_value_pair_table_free_list[0].prev = &mp->key_value_pair_table_free_list[mp->num_total_key_value_pair - 1];
    mp->key_value_pair_table_free_list[mp->num_total_key_value_pair - 1].next = &mp->key_value_pair_table_free_list[0];

    // 初始化所有chunk_header_t和free_list alloc_list
    chunk_header_t *chunk_header = (chunk_header_t *)(mp->chunk_header_start);
    mp->alloc_list = NULL;
    mp->free_list = &chunk_header[0]; // free_list指向第一个chunk_header_t
    i = 0;
    while (i < mp->num_total_chunk)
    {
        chunk_header[i].chunk_id = i;
        chunk_header[i].chunk_start = mp->chunks_start + i * CHUNK_SIZE;
        chunk_header[i].prev = (i == 0) ? NULL : &chunk_header[i - 1];
        chunk_header[i].next = (i == mp->num_total_chunk - 1) ? NULL : &chunk_header[i + 1];
        i++;
    }
    chunk_header[0].prev = &chunk_header[mp->num_total_chunk - 1];
    chunk_header[mp->num_total_chunk - 1].next = &chunk_header[0];

    return mp;
}

void chunk_alloc(memory_pool_t *mp, uint32_t chunk_id)
{
    chunk_header_t *chunk_header = (chunk_header_t *)(mp->chunk_header_start);
    chunk_header[chunk_id].is_alloc = 1;
    // 从free_list中移除
    if (chunk_header[chunk_id].prev == &chunk_header[chunk_id])
    {
        mp->free_list = NULL;
    }
    else
    {
        chunk_header[chunk_id].prev->next = chunk_header[chunk_id].next;
        chunk_header[chunk_id].next->prev = chunk_header[chunk_id].prev;
        if (mp->free_list == &chunk_header[chunk_id])
        {
            mp->free_list = chunk_header[chunk_id].next;
        }
    }
    // reset chunk_header
    chunk_header[chunk_id].is_alloc = 1;
    // 添加到alloc_list中
    if (mp->alloc_list != NULL)
    {
        chunk_header[chunk_id].prev = mp->alloc_list->prev; // 头插法
        chunk_header[chunk_id].next = mp->alloc_list;
        chunk_header[chunk_id].prev->next = &chunk_header[chunk_id];
        chunk_header[chunk_id].next->prev = &chunk_header[chunk_id];
    }
    else
    {
        chunk_header[chunk_id].prev = &chunk_header[chunk_id];
        chunk_header[chunk_id].next = &chunk_header[chunk_id];
    }
    mp->alloc_list = &chunk_header[chunk_id];
    mp->num_free_chunk--;
}

void chunk_free(memory_pool_t *mp, uint32_t chunk_id)
{
    chunk_header_t *chunk_header = (chunk_header_t *)(mp->chunk_header_start);
    chunk_header[chunk_id].is_alloc = 0;
    // 从alloc_list中移除
    if (chunk_header[chunk_id].prev == &chunk_header[chunk_id])
    {
        mp->alloc_list = NULL;
    }
    else
    {
        chunk_header[chunk_id].prev->next = chunk_header[chunk_id].next;
        chunk_header[chunk_id].next->prev = chunk_header[chunk_id].prev;
        if (mp->alloc_list == &chunk_header[chunk_id])
        {
            mp->alloc_list = chunk_header[chunk_id].next;
        }
    }
    // reset chunk_header
    chunk_header[chunk_id].is_alloc = 0;
    // 添加到free_list中
    if (mp->alloc_list != NULL)
    {
        chunk_header[chunk_id].prev = mp->free_list->prev; // 头插法
        chunk_header[chunk_id].next = mp->free_list;
        chunk_header[chunk_id].prev->next = &chunk_header[chunk_id];
        chunk_header[chunk_id].next->prev = &chunk_header[chunk_id];
    }
    else
    {
        chunk_header[chunk_id].prev = &chunk_header[chunk_id];
        chunk_header[chunk_id].next = &chunk_header[chunk_id];
    }
    mp->free_list = &chunk_header[chunk_id];
    mp->num_free_chunk++;
    memset(chunk_header[chunk_id].chunk_start, 0, CHUNK_SIZE);
}

// 根据key_value_pair->key，从key_value_pair_table中移除key_value_pair
void key_value_pair_free(memory_pool_t *mp, key_value_pair_t *key_value_pair)
{
    uint64_t hash_value = key_value_pair->hash_value;
    key_value_pair = (key_value_pair_t *)(mp->key_value_pair_table_alloc_list);
    // 遍历key_value_pair_table，找到key对应的key_value_pair
    while (key_value_pair->hash_value != NULL)
    {
        if (key_value_pair->hash_value == hash_value)
        {
            break;
        }
        key_value_pair = key_value_pair->next;
    }
    // 从key_value_pair_table中移除
    if (key_value_pair->prev == key_value_pair)
    {
        mp->key_value_pair_table_alloc_list = NULL;
    }
    else
    {
        key_value_pair->prev->next = key_value_pair->next;
        key_value_pair->next->prev = key_value_pair->prev;
        if (mp->key_value_pair_table_alloc_list == key_value_pair)
        {
            mp->key_value_pair_table_alloc_list = key_value_pair->next;
        }
    }
    // reset key_value_pair
    uint32_t id = key_value_pair->id;
    memset(key_value_pair, 0, sizeof(key_value_pair_t));
    key_value_pair->id = id;
    // 添加到key_value_pair_table_free_list中
    if (mp->key_value_pair_table_alloc_list != NULL)
    {
        key_value_pair->prev = mp->key_value_pair_table_free_list->prev; // 头插法
        key_value_pair->next = mp->key_value_pair_table_free_list;
        key_value_pair->prev->next = key_value_pair;
        key_value_pair->next->prev = key_value_pair;
    }
    else
    {
        key_value_pair->prev = key_value_pair;
        key_value_pair->next = key_value_pair;
    }
    mp->key_value_pair_table_free_list = key_value_pair;
    mp->num_free_key_value_pair++;
}

// 接收key_value_pair动态变量
void key_value_pair_alloc(memory_pool_t *mp, key_value_pair_t *add_key_value_pair)
{
    key_value_pair_t *key_value_pair = (key_value_pair_t *)(mp->key_value_pair_table_free_list);
    // 从key_value_pair_table_free_list中移除
    if (key_value_pair->prev == key_value_pair)
    {
        mp->key_value_pair_table_free_list = NULL;
    }
    else
    {
        key_value_pair->prev->next = key_value_pair->next;
        key_value_pair->next->prev = key_value_pair->prev;
        if (mp->key_value_pair_table_free_list == key_value_pair)
        {
            mp->key_value_pair_table_free_list = key_value_pair->next;
        }
    }
    // 添加到key_value_pair_table_alloc_list中
    if (mp->key_value_pair_table_alloc_list != NULL)
    {
        key_value_pair->prev = mp->key_value_pair_table_alloc_list->prev; // 头插法
        key_value_pair->next = mp->key_value_pair_table_alloc_list;
        key_value_pair->prev->next = key_value_pair;
        key_value_pair->next->prev = key_value_pair;
    }
    else
    {
        key_value_pair->prev = key_value_pair;
        key_value_pair->next = key_value_pair;
    }
    mp->key_value_pair_table_alloc_list = key_value_pair;
    mp->num_free_key_value_pair--;
    // reset key_value_pair
    key_value_pair->is_alloc = 1;
    key_value_pair->pirority = 0;
    key_value_pair->value_start = add_key_value_pair->value_start;
    key_value_pair->value_size = add_key_value_pair->value_size;
    key_value_pair->hash_value = add_key_value_pair->hash_value;
    key_value_pair->start_chunk_id = add_key_value_pair->start_chunk_id;
    key_value_pair->num_chunk = add_key_value_pair->num_chunk;
}

void key_value_pair_init(key_value_pair_t *key_value_pair, char *value_start, uint64_t value_size)
{
    // 截取value的前4个字符作为key
    memcpy(key_value_pair->key, value_start, KEY_LEN);
    key_value_pair->hash_value = hash(key_value_pair->key, KEY_LEN);
    key_value_pair->value_start = value_start;
    key_value_pair->value_size = value_size;
    key_value_pair->start_chunk_id = 0;
    key_value_pair->num_chunk = 0;
}

uint64_t hash(void *value, uint64_t len)
{
    uint64_t hash = 0;
    uint64_t seed = 131;
    uint64_t i = 0;
    // 提升速度
    uint64_t *p = (uint64_t *)value;
    while (i < len / sizeof(uint64_t))
    {
        hash = hash * seed + p[i++];
    }
    return hash;
}

// 为key_value_pair分配chunk, 并将key_value_pair加入到key_value_pair_table中
void chunk_alloc_for_key_value_pair(memory_pool_t *mp, key_value_pair_t *key_value_pair)
{
    // 计算需要的chunk数
    key_value_pair->num_chunk = (key_value_pair->value_size + CHUNK_SIZE - 1) / CHUNK_SIZE;
    // 从free_list中取出num_chunk个chunk到alloc_list中
    while (mp->num_free_chunk < key_value_pair->num_chunk || mp->num_free_key_value_pair == 0)
    {
        // 释放低优先级的key_value_pair，释放对应的chunk和key_value_pair节点
        // key_value_pair_t *min_key_value_pair = find_key_value_pair_by_pirority(mp);
        // free_key_value_pair(mp, min_key_value_pair);

        // LRU 替换，释放链表结尾的key_value_pair
        free_key_value_pair(mp, mp->key_value_pair_table_alloc_list->prev);
    }
    for (int i = 0; i < key_value_pair->num_chunk; i++)
    {
        chunk_alloc(mp, mp->free_list->chunk_id);
    }
    key_value_pair->start_chunk_id = mp->alloc_list->chunk_id;
    // 将key_value_pair加入到key_value_pair_table中
    key_value_pair_alloc(mp, key_value_pair);
}

int32_t find_key_value_pair_by_key(memory_pool_t *mp, char *key)
{
    key_value_pair_t *key_value_pair = (key_value_pair_t *)(mp->key_value_pair_table_alloc_list);
    if(key_value_pair == NULL){
        return -1;
    }
    while (key_value_pair->next != (key_value_pair_t *)(mp->key_value_pair_table_alloc_list))
    {
        if (memcmp(key_value_pair->key, key, KEY_LEN) == 0)
        {
            return key_value_pair->id;
        }
        key_value_pair = key_value_pair->next;
    }
    // 少比较一次
    if (memcmp(key_value_pair->key, key, KEY_LEN) == 0)
    {
        return key_value_pair->id;
    }
    return -1;
}

// 释放key_value_pair占用的chunk，调用key_value_pair_free()释放key_value_pair的链表节点
void free_key_value_pair(memory_pool_t *mp, key_value_pair_t *key_value_pair)
{

    // 从alloc_list中依次移除chunk
    chunk_header_t *chunk_header_ptr = (chunk_header_t *)(mp->chunk_header_start);
    chunk_header_ptr = chunk_header_ptr[key_value_pair->start_chunk_id].prev;
    for (int i = 0; i < key_value_pair->num_chunk; i++)
    {
        chunk_free(mp, chunk_header_ptr->next->chunk_id);
    }
    // 从key_value_pair_table中移除key_value_pair
    key_value_pair_free(mp, key_value_pair);
}

// 将key_value_pair的value写入chunk
void write_value_to_chunk(memory_pool_t *mp, key_value_pair_t *key_value_pair)
{
    chunk_header_t *chunk_header_ptr = (chunk_header_t *)(mp->chunk_header_start + key_value_pair->start_chunk_id * sizeof(chunk_header_t));
    for (int i = 0; i < key_value_pair->num_chunk - 1; i++)
    {
        memcpy(chunk_header_ptr->chunk_start, key_value_pair->value_start + i * CHUNK_SIZE, CHUNK_SIZE);
        chunk_header_ptr = chunk_header_ptr->next;
    }
    // 最后一个chunk
    uint32_t last_chunk_size = key_value_pair->value_size - (key_value_pair->num_chunk - 1) * CHUNK_SIZE;
    char *last_chunk_start = key_value_pair->value_start + (key_value_pair->num_chunk - 1) * CHUNK_SIZE;
    memcpy(chunk_header_ptr->chunk_start, last_chunk_start, last_chunk_size);
}

void store_key_value_pair(memory_pool_t *mp, char *value_start, uint64_t value_size)
{
    key_value_pair_t key_value_pair;
    key_value_pair_init(&key_value_pair, value_start, value_size);
    if (find_key_value_pair_by_key(mp, key_value_pair.key) != -1)
    {
        return;
    }

    chunk_alloc_for_key_value_pair(mp, &key_value_pair);
    write_value_to_chunk(mp, &key_value_pair);
}

void move_key_value_pair_to_head(memory_pool_t *mp, key_value_pair_t *key_value_pair)
{
    // 本身就是头节点
    if (mp->key_value_pair_table_alloc_list == key_value_pair)
    {
        return;
    }
    // 从key_value_pair_table中移除
    key_value_pair->prev->next = key_value_pair->next;
    key_value_pair->next->prev = key_value_pair->prev;
    // 添加到key_value_pair_table中
    key_value_pair->prev = mp->key_value_pair_table_alloc_list->prev; // 头插法
    key_value_pair->next = mp->key_value_pair_table_alloc_list;
    key_value_pair->prev->next = key_value_pair;
    key_value_pair->next->prev = key_value_pair;
    mp->key_value_pair_table_alloc_list = key_value_pair;
    
}