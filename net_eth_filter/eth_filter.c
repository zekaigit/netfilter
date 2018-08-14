/* ************************************************************************
 *       Filename:  hook_learn.c
 *    Description:  
 *        Version:  1.0
 *        Created:  2018年04月13日 23时42分47秒
 *       Revision:  none
 *       Compiler:  gcc
 *         Author:  YOUR NAME (), 
 *        Company:  
 * ************************************************************************/

/* 
* 安装一个丢弃所有到达的数据包的Netfilter hook函数的示例代码 
*/

#define __KERNEL__
#define MODULE

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netdevice.h>
#include <linux/ip.h>

/* 用于注册我们的函数的数据结构 */
static struct nf_hook_ops nfho;

/* 过滤接口 */
static char *drop_if="lo";
/* 过滤ip */
static char *drop_ip="/x7f/x00/x00/x01";  /*  127.0.0.1 */ 


static int check_ip_packet(struct sk_buff *skb)
{
	struct iphdr *iph = (struct iphdr *)ip_hdr(skb);
	/* We don't want any NULL pointer in the
	 *  chain to the IP header.*/	
	if (!skb) {
		printk( KERN_ALERT "zzk skb is null !\n" );
		return NF_DROP;
	}

	
	if (!iph) {
		printk( KERN_ALERT "zzk iph is null !\n" );
		return NF_ACCEPT;
	}
	printk( KERN_ALERT "zzk check ip packet !\n" );

	if (iph->saddr == *(unsigned int *)drop_ip) {
		printk("Dropped packet from... %d.%d.%d.%d\n",
			*drop_ip, *(drop_ip + 1),*(drop_ip + 2), *(drop_ip + 3));
		//return NF_DROP;
		return NF_ACCEPT;
	}
		printk("source packet from... %d.%d.%d.%d\n",
			iph->saddr , (iph->saddr + 1),(iph->saddr + 2), (iph->saddr + 3));
		printk("Dropped packet from... %d.%d.%d.%d\n",
			*drop_ip, *(drop_ip + 1),*(drop_ip + 2), *(drop_ip + 3));
		
	return NF_ACCEPT;
}

/* 注册的hook函数的实现 */
unsigned int hook_func(unsigned int hooknum,
                       struct sk_buff *skb,
                       const struct net_device *in,
                       const struct net_device *out,
                       int (*okfn)(struct sk_buff *))
{
	
	struct iphdr* iph = ip_hdr(skb);
//	printk( KERN_ALERT "zzk lo NF_DROP !\n");

	if (strcmp(in->name, drop_if)==0)
	{
		printk( KERN_ALERT "zzk drop if is %s !\n", drop_if);
	//	return NF_DROP;
	}

	check_ip_packet(skb);
#if 0
	if (iph->saddr == *(unsigned int *)drop_ip) {
		printk("Dropped packet from... %d.%d.%d.%d/n",
			*drop_ip, *(drop_ip + 1),*(drop_ip + 2), *(drop_ip + 3));
		//return NF_DROP;
		return NF_ACCEPT;
	}
#endif

    return NF_ACCEPT;           /* 丢弃所有的数据包 */
}

/* 初始化程序 */
int init_module()
{
    /* 填充我们的hook数据结构 */
    nfho.hook	  = hook_func;         /* 处理函数 */
    nfho.hooknum  = NF_INET_PRE_ROUTING; /* 使用IPv4的第一个hook */
    nfho.pf       = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;   /* 让我们的函数首先执行 */

    nf_register_hook(&nfho);

    return 0;
}

/* 清除程序 */
void cleanup_module()
{
    nf_unregister_hook(&nfho);
}


