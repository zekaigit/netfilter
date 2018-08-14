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

/* 用于注册我们的函数的数据结构 */
static struct nf_hook_ops nfho;

/* 注册的hook函数的实现 */
unsigned int hook_func(unsigned int hooknum,
                       struct sk_buff **skb,
                       const struct net_device *in,
                       const struct net_device *out,
                       int (*okfn)(struct sk_buff *))
{
	printk("NF_DROP !\n");
    return NF_DROP;           /* 丢弃所有的数据包 */
}

/* 初始化程序 */
int init_module()
{
    /* 填充我们的hook数据结构 */
    nfho.hook = hook_func;         /* 处理函数 */
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


