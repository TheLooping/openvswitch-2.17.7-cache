/*
 * Copyright (c) 2007-2015 Nicira, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 */

#include <linux/etherdevice.h>
#include <linux/if.h>
#include <linux/if_vlan.h>
#include <linux/jhash.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/percpu.h>
#include <linux/rcupdate.h>
#include <linux/rtnetlink.h>
#include <linux/compat.h>
#include <linux/module.h>
#include <linux/if_link.h>
#include <net/net_namespace.h>
#include <net/lisp.h>
#include <net/gre.h>
#include <net/geneve.h>
#include <net/stt.h>
#include <net/vxlan.h>

#include "datapath.h"
#include "gso.h"
#include "vport.h"
#include "vport-internal_dev.h"

static LIST_HEAD(vport_ops_list);
static bool compat_gre_loaded = false;
static bool compat_ip6_tunnel_loaded = false;

/* Protected by RCU read lock for reading, ovs_mutex for writing. */
static struct hlist_head *dev_table;
#define VPORT_HASH_BUCKETS 1024

/**
 *	ovs_vport_init - initialize vport subsystem
 *
 * Called at module load time to initialize the vport subsystem.
 */
int ovs_vport_init(void)
{
	int err;

	dev_table = kcalloc(VPORT_HASH_BUCKETS, sizeof(struct hlist_head),
						GFP_KERNEL);
	if (!dev_table)
		return -ENOMEM;

	err = lisp_init_module();
	if (err)
		goto err_lisp;
	err = gre_init();
	if (err && err != -EEXIST)
	{
		goto err_gre;
	}
	else
	{
		if (err == -EEXIST)
		{
			pr_warn("Cannot take GRE protocol rx entry"
					"- The GRE/ERSPAN rx feature not supported\n");
			/* continue GRE tx */
		}

		err = ipgre_init();
		if (err && err != -EEXIST)
			goto err_ipgre;
		compat_gre_loaded = true;
	}
	err = ip6gre_init();
	if (err && err != -EEXIST)
	{
		goto err_ip6gre;
	}
	else
	{
		if (err == -EEXIST)
		{
			pr_warn("IPv6 GRE/ERSPAN Rx mode is not supported\n");
			goto skip_ip6_tunnel_init;
		}
	}

	err = ip6_tunnel_init();
	if (err)
		goto err_ip6_tunnel;
	else
		compat_ip6_tunnel_loaded = true;

skip_ip6_tunnel_init:
	err = geneve_init_module();
	if (err)
		goto err_geneve;
	err = vxlan_init_module();
	if (err)
		goto err_vxlan;
	err = ovs_stt_init_module();
	if (err)
		goto err_stt;

	return 0;
	ovs_stt_cleanup_module();
err_stt:
	vxlan_cleanup_module();
err_vxlan:
	geneve_cleanup_module();
err_geneve:
	ip6_tunnel_cleanup();
err_ip6_tunnel:
	ip6gre_fini();
err_ip6gre:
	ipgre_fini();
err_ipgre:
	gre_exit();
err_gre:
	lisp_cleanup_module();
err_lisp:
	kfree(dev_table);
	return err;
}

/**
 *	ovs_vport_exit - shutdown vport subsystem
 *
 * Called at module exit time to shutdown the vport subsystem.
 */
void ovs_vport_exit(void)
{
	if (compat_gre_loaded)
	{
		gre_exit();
		ipgre_fini();
	}
	ovs_stt_cleanup_module();
	vxlan_cleanup_module();
	geneve_cleanup_module();
	if (compat_ip6_tunnel_loaded)
		ip6_tunnel_cleanup();
	ip6gre_fini();
	lisp_cleanup_module();
	kfree(dev_table);
}

static struct hlist_head *hash_bucket(const struct net *net, const char *name)
{
	unsigned int hash = jhash(name, strlen(name), (unsigned long)net);
	return &dev_table[hash & (VPORT_HASH_BUCKETS - 1)];
}

int __ovs_vport_ops_register(struct vport_ops *ops)
{
	int err = -EEXIST;
	struct vport_ops *o;

	ovs_lock();
	list_for_each_entry(o, &vport_ops_list, list) if (ops->type == o->type) goto errout;

	list_add_tail(&ops->list, &vport_ops_list);
	err = 0;
errout:
	ovs_unlock();
	return err;
}
EXPORT_SYMBOL_GPL(__ovs_vport_ops_register);

void ovs_vport_ops_unregister(struct vport_ops *ops)
{
	ovs_lock();
	list_del(&ops->list);
	ovs_unlock();
}
EXPORT_SYMBOL_GPL(ovs_vport_ops_unregister);

/**
 *	ovs_vport_locate - find a port that has already been created
 *
 * @name: name of port to find
 *
 * Must be called with ovs or RCU read lock.
 */
struct vport *ovs_vport_locate(const struct net *net, const char *name)
{
	struct hlist_head *bucket = hash_bucket(net, name);
	struct vport *vport;

	hlist_for_each_entry_rcu(vport, bucket, hash_node) if (!strcmp(name, ovs_vport_name(vport)) &&
														   net_eq(ovs_dp_get_net(vport->dp), net)) return vport;

	return NULL;
}

/**
 *	ovs_vport_alloc - allocate and initialize new vport
 *
 * @priv_size: Size of private data area to allocate.
 * @ops: vport device ops
 *
 * Allocate and initialize a new vport defined by @ops.  The vport will contain
 * a private data area of size @priv_size that can be accessed using
 * vport_priv().  vports that are no longer needed should be released with
 * vport_free().
 */
struct vport *ovs_vport_alloc(int priv_size, const struct vport_ops *ops,
							  const struct vport_parms *parms)
{
	struct vport *vport;
	size_t alloc_size;

	alloc_size = sizeof(struct vport);
	if (priv_size)
	{
		alloc_size = ALIGN(alloc_size, VPORT_ALIGN);
		alloc_size += priv_size;
	}

	vport = kzalloc(alloc_size, GFP_KERNEL);
	if (!vport)
		return ERR_PTR(-ENOMEM);

	vport->dp = parms->dp;
	vport->port_no = parms->port_no;
	vport->ops = ops;
	INIT_HLIST_NODE(&vport->dp_hash_node);

	if (ovs_vport_set_upcall_portids(vport, parms->upcall_portids))
	{
		kfree(vport);
		return ERR_PTR(-EINVAL);
	}

	return vport;
}
EXPORT_SYMBOL_GPL(ovs_vport_alloc);

/**
 *	ovs_vport_free - uninitialize and free vport
 *
 * @vport: vport to free
 *
 * Frees a vport allocated with vport_alloc() when it is no longer needed.
 *
 * The caller must ensure that an RCU grace period has passed since the last
 * time @vport was in a datapath.
 */
void ovs_vport_free(struct vport *vport)
{
	/* vport is freed from RCU callback or error path, Therefore
	 * it is safe to use raw dereference.
	 */
	kfree(rcu_dereference_raw(vport->upcall_portids));
	kfree(vport);
}
EXPORT_SYMBOL_GPL(ovs_vport_free);

static struct vport_ops *ovs_vport_lookup(const struct vport_parms *parms)
{
	struct vport_ops *ops;

	list_for_each_entry(ops, &vport_ops_list, list) if (ops->type == parms->type) return ops;

	return NULL;
}

/**
 *	ovs_vport_add - add vport device (for kernel callers)
 *
 * @parms: Information about new vport.
 *
 * Creates a new vport with the specified configuration (which is dependent on
 * device type).  ovs_mutex must be held.
 */
struct vport *ovs_vport_add(const struct vport_parms *parms)
{
	struct vport_ops *ops;
	struct vport *vport;

	ops = ovs_vport_lookup(parms);
	if (ops)
	{
		struct hlist_head *bucket;

		if (!try_module_get(ops->owner))
			return ERR_PTR(-EAFNOSUPPORT);

		vport = ops->create(parms);
		if (IS_ERR(vport))
		{
			module_put(ops->owner);
			return vport;
		}

		bucket = hash_bucket(ovs_dp_get_net(vport->dp),
							 ovs_vport_name(vport));
		hlist_add_head_rcu(&vport->hash_node, bucket);
		return vport;
	}

	if (parms->type == OVS_VPORT_TYPE_GRE && !compat_gre_loaded)
	{
		pr_warn("GRE protocol already loaded!\n");
		return ERR_PTR(-EAFNOSUPPORT);
	}
	/* Unlock to attempt module load and return -EAGAIN if load
	 * was successful as we need to restart the port addition
	 * workflow.
	 */
	ovs_unlock();
	request_module("vport-type-%d", parms->type);
	ovs_lock();

	if (!ovs_vport_lookup(parms))
		return ERR_PTR(-EAFNOSUPPORT);
	else
		return ERR_PTR(-EAGAIN);
}

/**
 *	ovs_vport_set_options - modify existing vport device (for kernel callers)
 *
 * @vport: vport to modify.
 * @options: New configuration.
 *
 * Modifies an existing device with the specified configuration (which is
 * dependent on device type).  ovs_mutex must be held.
 */
int ovs_vport_set_options(struct vport *vport, struct nlattr *options)
{
	if (!vport->ops->set_options)
		return -EOPNOTSUPP;
	return vport->ops->set_options(vport, options);
}

/**
 *	ovs_vport_del - delete existing vport device
 *
 * @vport: vport to delete.
 *
 * Detaches @vport from its datapath and destroys it.  ovs_mutex must be
 * held.
 */
void ovs_vport_del(struct vport *vport)
{
	ASSERT_OVSL();

	hlist_del_rcu(&vport->hash_node);
	module_put(vport->ops->owner);
	vport->ops->destroy(vport);
}

/**
 *	ovs_vport_get_stats - retrieve device stats
 *
 * @vport: vport from which to retrieve the stats
 * @stats: location to store stats
 *
 * Retrieves transmit, receive, and error stats for the given device.
 *
 * Must be called with ovs_mutex or rcu_read_lock.
 */
void ovs_vport_get_stats(struct vport *vport, struct ovs_vport_stats *stats)
{
	const struct rtnl_link_stats64 *dev_stats;
	struct rtnl_link_stats64 temp;

	dev_stats = dev_get_stats(vport->dev, &temp);
	stats->rx_errors = dev_stats->rx_errors;
	stats->tx_errors = dev_stats->tx_errors;
	stats->tx_dropped = dev_stats->tx_dropped;
	stats->rx_dropped = dev_stats->rx_dropped;

	stats->rx_bytes = dev_stats->rx_bytes;
	stats->rx_packets = dev_stats->rx_packets;
	stats->tx_bytes = dev_stats->tx_bytes;
	stats->tx_packets = dev_stats->tx_packets;
}

/**
 *	ovs_vport_get_options - retrieve device options
 *
 * @vport: vport from which to retrieve the options.
 * @skb: sk_buff where options should be appended.
 *
 * Retrieves the configuration of the given device, appending an
 * %OVS_VPORT_ATTR_OPTIONS attribute that in turn contains nested
 * vport-specific attributes to @skb.
 *
 * Returns 0 if successful, -EMSGSIZE if @skb has insufficient room, or another
 * negative error code if a real error occurred.  If an error occurs, @skb is
 * left unmodified.
 *
 * Must be called with ovs_mutex or rcu_read_lock.
 */
int ovs_vport_get_options(const struct vport *vport, struct sk_buff *skb)
{
	struct nlattr *nla;
	int err;

	if (!vport->ops->get_options)
		return 0;

	nla = nla_nest_start_noflag(skb, OVS_VPORT_ATTR_OPTIONS);
	if (!nla)
		return -EMSGSIZE;

	err = vport->ops->get_options(vport, skb);
	if (err)
	{
		nla_nest_cancel(skb, nla);
		return err;
	}

	nla_nest_end(skb, nla);
	return 0;
}

/**
 *	ovs_vport_set_upcall_portids - set upcall portids of @vport.
 *
 * @vport: vport to modify.
 * @ids: new configuration, an array of port ids.
 *
 * Sets the vport's upcall_portids to @ids.
 *
 * Returns 0 if successful, -EINVAL if @ids is zero length or cannot be parsed
 * as an array of U32.
 *
 * Must be called with ovs_mutex.
 */
int ovs_vport_set_upcall_portids(struct vport *vport, const struct nlattr *ids)
{
	struct vport_portids *old, *vport_portids;

	if (!nla_len(ids) || nla_len(ids) % sizeof(u32))
		return -EINVAL;

	old = ovsl_dereference(vport->upcall_portids);

	vport_portids = kmalloc(sizeof(*vport_portids) + nla_len(ids),
							GFP_KERNEL);
	if (!vport_portids)
		return -ENOMEM;

	vport_portids->n_ids = nla_len(ids) / sizeof(u32);
	vport_portids->rn_ids = reciprocal_value(vport_portids->n_ids);
	nla_memcpy(vport_portids->ids, ids, nla_len(ids));

	rcu_assign_pointer(vport->upcall_portids, vport_portids);

	if (old)
		kfree_rcu(old, rcu);
	return 0;
}

/**
 *	ovs_vport_get_upcall_portids - get the upcall_portids of @vport.
 *
 * @vport: vport from which to retrieve the portids.
 * @skb: sk_buff where portids should be appended.
 *
 * Retrieves the configuration of the given vport, appending the
 * %OVS_VPORT_ATTR_UPCALL_PID attribute which is the array of upcall
 * portids to @skb.
 *
 * Returns 0 if successful, -EMSGSIZE if @skb has insufficient room.
 * If an error occurs, @skb is left unmodified.  Must be called with
 * ovs_mutex or rcu_read_lock.
 */
int ovs_vport_get_upcall_portids(const struct vport *vport,
								 struct sk_buff *skb)
{
	struct vport_portids *ids;

	ids = rcu_dereference_ovsl(vport->upcall_portids);

	if (vport->dp->user_features & OVS_DP_F_VPORT_PIDS)
		return nla_put(skb, OVS_VPORT_ATTR_UPCALL_PID,
					   ids->n_ids * sizeof(u32), (void *)ids->ids);
	else
		return nla_put_u32(skb, OVS_VPORT_ATTR_UPCALL_PID, ids->ids[0]);
}

/**
 *	ovs_vport_find_upcall_portid - find the upcall portid to send upcall.
 *
 * @vport: vport from which the missed packet is received.
 * @skb: skb that the missed packet was received.
 *
 * Uses the skb_get_hash() to select the upcall portid to send the
 * upcall.
 *
 * Returns the portid of the target socket.  Must be called with rcu_read_lock.
 */
u32 ovs_vport_find_upcall_portid(const struct vport *vport, struct sk_buff *skb)
{
	struct vport_portids *ids;
	u32 ids_index;
	u32 hash;

	ids = rcu_dereference(vport->upcall_portids);

	/* If there is only one portid, select it in the fast-path. */
	if (ids->n_ids == 1)
		return ids->ids[0];

	hash = skb_get_hash(skb);
	ids_index = hash - ids->n_ids * reciprocal_divide(hash, ids->rn_ids);
	return ids->ids[ids_index];
}

/**
 *	ovs_vport_receive - pass up received packet to the datapath for processing
 *
 * @vport: vport that received the packet
 * @skb: skb that was received
 * @tun_key: tunnel (if any) that carried packet
 *
 * Must be called with rcu_read_lock.  The packet cannot be shared and
 * skb->data should point to the Ethernet header.
 */
int ovs_vport_receive(struct vport *vport, struct sk_buff *skb,
					  const struct ip_tunnel_info *tun_info)
{
	struct sw_flow_key key;
	int error;

#ifndef CREATE_MEMPOOL_T
#define CREATE_MEMPOOL_T
    // 初始化内存池
    static memory_pool_t* mp = memory_pool_t_init(REQUEST_SIZE);
    static bool memory_pool_lock = false;// 内存池锁,0表示未加锁,1表示加锁
#endif

	/* 自定义缓存 */
	key_value_pair_t *kv = NULL;
	int forward_times = 1;
	int iscache = 0;
	struct sk_buff *response_skb;
	struct iphdr *request_iph, *response_iph;
	struct udphdr *request_udph, *response_udph;
	struct ethhdr *request_ethh, *response_ethh;
	struct net_device *dev = NULL;
	int response_protocol;
	uint16_t response_id = rand() % 65535;
	
	forward_data_t *myForwardData;
	chunk_header_t *chunk_header;
	// 负载的起始位置 = data + sizeof(以太网头部) + sizeof(IP头部) + sizeof(UDP头部)
	int header_len = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
	char *payload_start = skb->data + header_len;
	int payload_len = skb->tail - payload_start;
	// 内存池加锁
	while(memory_pool_lock != 0){
		// 等待
	}
	memory_pool_lock = 1;
	if ((iscache = cache_module(mp, payload_start, payload_len, kv)) == 1)
	{
		// kv 指向命中的key_value_pair(链表头部)
		// TODO : 生成一个完整转发数据包 生成myForwardData结构体
		// TODO :  skb(sk_buff) 的 五元组、payload;修改key(sw_flow_key)的五元组
		request_t *myRequest = (request_t *)(skb->data + header_len + 3);
		makeForwardData(myRequest, myForwardData, kv);
		// 每次转发key_value_pair的一个块
		chunk_header = (chunk_header_t *)(mp->chunk_start + kv->chunk_id * CHUNK_SIZE);
		forward_times = kv->num_chunk;

		
		request_ethh = (struct ethhdr *)skb->data;		
		request_iph = (struct iphdr *)(skb->data + sizeof(struct ethhdr));		
		request_udph = (struct udphdr *)(skb->data + sizeof(struct ethhdr) + sizeof(struct iphdr));
		
		// 获取当前设备
		dev = dev_get_by_name(&init_net, "ens33");


		// UDP 返回
		response_protocol = 17;
	}
	for (int i = 0; i < forward_times; i++)
	{
		if (iscache == 0)
		{
			forward_times = 1;
		}
		else if (iscache == 1)
		{
			// 更新myForwardData结构体
			myForwardData->start = chunk_header->chunk_start;
			myForwardData->len = (i == forward_times - 1) ? (kv->value_size % CHUNK_SIZE) : CHUNK_SIZE;
			

			
			// TODO : kfree掉原有的skb，重新分配skb
			response_skb = alloc_skb(skb->data - skb->head + header_len + myForwardData->len + sizeof(forward_data_t) + 3, GFP_ATOMIC);

			
			response_skb->len = 0;
			skb_reserve(response_skb, skb->data - skb->head);
			skb_reserve(response_skb, header_len);// 预留出以太网头部、IP头部、UDP头部的空间
			// 向后填充数据，tail指针后移
			skb_put(response_skb, sizeof(forward_data_t) + myForwardData->len + 3);
			strcpy(response_skb->data, "RES");
			memcpy(response_skb->data + 3, myForwardData, sizeof(forward_data_t));
			memcpy(response_skb->data + 3 + sizeof(forward_data_t), myForwardData->start, myForwardData->len);
			// 向前填充头部，data指针前移
			skb_push(response_skb, sizeof(struct udphdr));
			response_skb->h.uh = response_skb->data;
			response_udph = (struct udphdr *)response_skb->data;

			skb_push(response_skb, sizeof(struct iphdr));
			response_skb->nh.iph = response_skb->data;
			response_iph = (struct iphdr *)response_skb->data;

			skb_push(response_skb, sizeof(struct ethhdr));
			response_skb->mac.raw = response_skb->data;
			response_ethh = (struct ethhdr *)response_skb->data;

			response_skb->len = sizeof(forward_data_t) + myForwardData->len + sizeof(struct udphdr) + sizeof(struct iphdr) + sizeof(struct ethhdr);

			// 填充头部信息
			response_udph->source = request_udph->dest;
			response_udph->dest = request_udph->source;
			response_udph->len = htons(sizeof(forward_data_t) + myForwardData->len + sizeof(struct udphdr));
			response_udph->check = 0;
			//skb_reset_transport_header(response_skb);
			
			response_iph->version = 4;
			response_iph->ihl = 5;
			response_iph->tos = 0;
			response_iph->tot_len = htons(sizeof(forward_data_t) + myForwardData->len + sizeof(struct udphdr) + sizeof(struct iphdr));
			response_iph->id = htons(response_id + i);
			response_iph->frag_off = 0;
			response_iph->ttl = 64;
			response_iph->protocol = 0x11;
			response_iph->check = ip_fast_csum(response_skb->nh.iph,response_skb->nh.iph->ihl);
			response_iph->saddr = request_iph->daddr;
			response_iph->daddr = request_iph->saddr;

			response_ethh->h_proto = htons(0x0800);
			memcpy(response_ethh->h_dest, request_ethh->h_source, 6);
			memcpy(response_ethh->h_source, request_ethh->h_dest, 6);

			response_skb->protocol = htons(ETH_P_IP);
			response_skb->dev = dev;


			// 释放掉旧skb，将response_skb改名字成skb，加入到vport_receive中
			if(i == 0)
			{
				kfree_skb(skb);
			}
			skb = response_skb;



		}

		OVS_CB(skb)->input_vport = vport;
		OVS_CB(skb)->mru = 0;

		OVS_CB(skb)->cutlen = 0;
		if (unlikely(dev_net(skb->dev) != ovs_dp_get_net(vport->dp)))
		{
			u32 mark;

			mark = skb->mark;
			skb_scrub_packet(skb, true);
			skb->mark = mark;
			tun_info = NULL;
		}

		ovs_skb_init_inner_protocol(skb);
		skb_clear_ovs_gso_cb(skb);
		/* Extract flow from 'skb' into 'key'. */
		error = ovs_flow_key_extract(tun_info, skb, &key);
		if (unlikely(error))
		{
			kfree_skb(skb);
			return error;
		}

		ovs_dp_process_packet(skb, &key);
	}
	memory_pool_lock = 0;
	return 0;
}

static int packet_length(const struct sk_buff *skb,
						 struct net_device *dev)
{
	int length = skb->len - dev->hard_header_len;

	if (!skb_vlan_tag_present(skb) &&
		eth_type_vlan(skb->protocol))
		length -= VLAN_HLEN;

	/* Don't subtract for multiple VLAN tags. Most (all?) drivers allow
	 * (ETH_LEN + VLAN_HLEN) in addition to the mtu value, but almost none
	 * account for 802.1ad. e.g. is_skb_forwardable().
	 */

	return length > 0 ? length : 0;
}

void ovs_vport_send(struct vport *vport, struct sk_buff *skb, u8 mac_proto)
{
	int mtu = vport->dev->mtu;

	switch (vport->dev->type)
	{
	case ARPHRD_NONE:
		if (mac_proto == MAC_PROTO_ETHERNET)
		{
			skb_reset_network_header(skb);
			skb_reset_mac_len(skb);
			skb->protocol = htons(ETH_P_TEB);
		}
		else if (mac_proto != MAC_PROTO_NONE)
		{
			WARN_ON_ONCE(1);
			goto drop;
		}
		break;
	case ARPHRD_ETHER:
		if (mac_proto != MAC_PROTO_ETHERNET)
			goto drop;
		break;
	default:
		goto drop;
	}

	if (unlikely(packet_length(skb, vport->dev) > mtu &&
				 !skb_is_gso(skb)))
	{
		net_warn_ratelimited("%s: dropped over-mtu packet: %d > %d\n",
							 vport->dev->name,
							 packet_length(skb, vport->dev), mtu);
		vport->dev->stats.tx_errors++;
		goto drop;
	}

	skb->dev = vport->dev;
	vport->ops->send(skb);
	return;

drop:
	kfree_skb(skb);
}
