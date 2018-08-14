/* ************************************************************************
 *       Filename:  test.c
 *    Description:  
 *        Version:  1.0
 *        Created:  2018年04月18日 11时22分59秒
 *       Revision:  none
 *       Compiler:  gcc
 *         Author:  YOUR NAME (), 
 *        Company:  
 * ************************************************************************/

#include <stdio.h>  
#include <getopt.h>   
#include <sys/ioctl.h>   
#include <fcntl.h>  
  
#include "lwfw.h"  
  
char* const short_options = "adgf:p:t:";   
  
struct option long_options[] = {  
    { "active"  , 0, NULL, 'a' },  
    { "deactive"    , 0, NULL, 'd' },  
    { "getstatus"   , 0, NULL, 'g' },  
    { "denyif"  , 1, NULL, 'f' },  
    { "denyip"  , 1, NULL, 'p' },  
    { "denyport"    , 1, NULL, 't' },  
    { 0     , 0, NULL,  0  },  
};   
  
int main(int argc, char *argv[])  
{  
    int c;   
    int fd;  
    struct lwfw_stats status;  
    fd = open("/dev/lwfw",O_RDWR);  
    if(fd == -1 ){  
        perror("open");  
        return 0;  
    }  
    while((c = getopt_long (argc, argv, short_options, long_options, NULL)) != -1)  {  
        switch(c){  
            case 'a':  
                ioctl(fd,LWFW_ACTIVATE);  
                break;  
            case 'd':  
                ioctl(fd,LWFW_DEACTIVATE);  
                break;  
            case 'g':  
                ioctl(fd,LWFW_GET_STATS,status);  
                printf("if_dropped is %x\n",status.if_dropped);  
                printf("ip_dropped is %x\n",status.ip_dropped);  
                printf("tcp_dropped is %x\n",status.tcp_dropped);  
                printf("total_dropped is %x\n",status.total_dropped);  
                printf("total_seen is %x\n",status.total_seen);  
                break;  
            case 'f':  
                ioctl(fd,LWFW_DENY_IF,optarg);  
                printf("optarg is %s\n",optarg);  
                break;  
            case 'p':  
                ioctl(fd,LWFW_DENY_IP,optarg);  
                printf("optarg is %s\n",optarg);  
                break;  
            case 't':  
                ioctl(fd,LWFW_DENY_PORT,optarg);  
                printf("optarg is %s\n",optarg);  
                break;  
            default:  
                printf("sadf\n");     
        }  
  
    }  
    close(fd);  
}  



