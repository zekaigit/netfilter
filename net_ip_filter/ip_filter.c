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

#include <linux/kernel.h>  
#include <linux/init.h>  
#include <linux/module.h>  
#include <linux/version.h>  
#include <linux/string.h>  
#include <linux/kmod.h>  
#include <linux/vmalloc.h>  
#include <linux/workqueue.h>  
#include <linux/spinlock.h>  
#include <linux/socket.h>  
#include <linux/net.h>  
#include <linux/in.h>  
#include <linux/skbuff.h>  
#include <linux/ip.h>  
#include <linux/tcp.h>  
#include <linux/netfilter.h>  
#include <linux/netfilter_ipv4.h>  
#include <linux/icmp.h>  
#include <net/sock.h>  
#include <asm/uaccess.h>  
#include <asm/unistd.h>  
  
MODULE_LICENSE("GPL");  
MODULE_AUTHOR("xsc");  

/* 用于注册我们的函数的数据结构 */
static struct nf_hook_ops nfho;

/* 过滤接口 */
static char *drop_if="lo";
/* 过滤ip */
//static char *drop_ip="/x7f/x00/x00/x01";  /*  127.0.0.1 */ 
static char *parg="192.168.2.1";
module_param(parg, charp, S_IRUGO);

/* 
 * there is not a inet_addr in kernel.use in_aton or write one.
*/
unsigned int inet_addr(char *str)
{
	int a,b,c,d;
	char arr[4];

	sscanf(str,"%d.%d.%d.%d",&a,&b,&c,&d);
	arr[0] = a;arr[1] = b;
	arr[2] = c;arr[3] = d;
	return *(unsigned int*)arr;
}


/* 注册的hook函数的实现 */
unsigned int hook_func(unsigned int hooknum,
                       struct sk_buff *skb,
                       const struct net_device *in,
                       const struct net_device *out,
                       int (*okfn)(struct sk_buff *))
{
	struct sk_buff *sk = skb_copy(skb,1);
	struct iphdr *ip;
	ip = ip_hdr(sk);
//	printk( KERN_ALERT "zzk lo NF_DROP !\n");

	if( ip->saddr == inet_addr(parg) )
	{
		printk("zzk same\n");
		return NF_DROP;
	}
	else
	{
		return NF_ACCEPT;
	}
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

