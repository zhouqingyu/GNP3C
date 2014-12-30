#include <net/ipv6.h>
#include <linux/rwsem.h>

struct bonding_ipv6_ops {
	struct sk_buff* (*ndisc_build_skb)(struct net_device *dev,
                                                 const struct in6_addr *daddr,
                                                 const struct in6_addr *saddr,
                                                 struct icmp6hdr *icmp6h,
                                                 const struct in6_addr *target,
                                                 int llinfo);
	void (*ndisc_send_skb)(struct sk_buff *skb,
                                               struct net_device *dev,
                                               struct neighbour *neigh,
                                               const struct in6_addr *daddr,
                                               const struct in6_addr *saddr,
                                               struct icmp6hdr *icmp6h);

	void (*in6_dev_put)(struct inet6_dev *idev);
	int (*register_inet6addr_notifier)(struct notifier_block *nb);
	int (*unregister_inet6addr_notifier)(struct notifier_block *nb);
};


extern struct bonding_ipv6_ops bonding_ipv6_ops_dummy;
extern struct bonding_ipv6_ops *bonding_ipv6_ops;
extern struct rw_semaphore bonding_ipv6_ops_sem;

