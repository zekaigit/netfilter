cmd_/home/zzk/demo/net_eth_filter/eth_filter.ko := ld -r -m elf_i386 -T /usr/src/linux-headers-3.2.0-23-generic-pae/scripts/module-common.lds --build-id  -o /home/zzk/demo/net_eth_filter/eth_filter.ko /home/zzk/demo/net_eth_filter/eth_filter.o /home/zzk/demo/net_eth_filter/eth_filter.mod.o