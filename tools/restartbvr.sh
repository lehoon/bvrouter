# !/bin/bash
if [ $# != 1 ]; then
	echo "$0 pnetip/mask"
	exit 1
fi
BVRID=`ps aux |grep bvrouter|grep -v grep|awk '{print $2}'`
if [ -n "$BVRID" ];then
        kill -9 $BVRID
else
        echo "no bvrouter running"
fi
sleep 10
/home/zhangyu/bvrouter/output/bvrouter -f /home/zhangyu/bvrouter/output/bvrouter.conf -m 


sleep 45

#ip addr add 10.32.44.0/24 dev vnic0
ip addr add $1 dev vnic0
ZEBRA_ID=`ps aux |grep zeb |grep -v grep|awk '{print $2}'`
if [ -n "$ZEBRA_ID" ];then
        kill -9 $ZEBRA_ID
else
        echo "no zebra running"
fi

OSPF_ID=`ps aux |grep ospfd |grep -v grep|awk '{print $2}'`
if [ -n "OSPF_ID" ];then
        kill -9 $OSPF_ID
else
        echo "no ospf running"
fi    

zebra -d -f /usr/local/etc/zebra.conf
ospfd -d -f /usr/local/etc/ospfd.conf





