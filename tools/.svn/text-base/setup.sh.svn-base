#

xgbe_inc=(eth3 eth2)

PORT_BIND_SCRIPT=dpdk_nic_bind.py

PORT_BIND=./$PORT_BIND_SCRIPT

sh kill.sh

sleep 1

#install the required package
#libev,libev-devel,python-argparse
yum install -y python-argparse > /dev/null 2>&1
if [ $? != 0 ]; then
	echo "yum install argparse error,check your yum configuration!"
	exit 0
fi

yum install -y libev
if [ $? != 0 ]; then
        echo "yum install libev error,check your yum configuration!"
        exit 0
fi

yum install -y libev-devel
if [ $? != 0 ]; then
        echo "yum install libev-devel error,check your yum configuration!"
        exit 0
fi



#mount the hugetlbfs
#if [ -d /mnt/huge ]; then
#	umount /mnt/huge
#	rm -rf /mnt/huge
#fi
#mkdir -p /mnt/huge
#mount -t hugetlbfs hugetlbfs /mnt/huge > /dev/null 2>&1
#if [ $? != 0 ]; then 
#	echo  "mount huge page failed"
#	exit 0
#fi

# rmmod old rte_kni mod
kni=`lsmod |grep rte_kni`
if [ -n "$kni" ]; then
	rmmod rte_kni
fi

kni=`lsmod |grep rte_kni`
if [ -n "$kni" ]; then
	echo 'rte_kni rmmod error, exit'
	exit 0
fi

# rmmod old igb_uio mod
uio=`lsmod |grep igb_uio`
if [ -n "$uio" ]; then
	rmmod igb_uio
fi

# rmmod old igb_uio
uio=`lsmod |grep igb_uio`
if [ -n "$uio" ]; then
	echo 'igb_uio rmmod error, exit'
	exit 0
fi

# insmod ixgbe
xgbe=`lsmod |grep ixgbe`
if [ -z "$xgbe" ]; then
	modprobe ixgbe
fi

xgbe=`lsmod |grep ixgbe`
if [ -z "$xgbe" ]; then
	echo 'ixgbe insmod error, exit'
	exit 0
fi

# insmod rte_kni and igb_uio
insmod ../kmod/rte_kni.ko
kni=`lsmod |grep rte_kni`
if [ -z "$kni" ]; then
	echo 'rte_kni insmod error, exit'
	exit 0
fi

insmod ../kmod/igb_uio.ko
uio=`lsmod |grep igb_uio`
if [ -z "$uio" ]; then
	echo 'igb_uio rmmod error, exit'
	exit 0
fi

# bind uio port
for inc in ${xgbe_inc[@]};
	do
		$PORT_BIND -b igb_uio $inc
	done
#./tools/dpdk_nic_bind.py -b igb_uio eth3
#./tools/dpdk_nic_bind.py -b igb_uio eth4
#./tools/dpdk_nic_bind.py -b igb_uio eth5
#./tools/dpdk_nic_bind.py -b igb_uio eth12

#rmmod ixgbe

echo 'runtime environment is ready, good luck'
