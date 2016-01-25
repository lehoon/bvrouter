pid=`ps aux |grep bvrouter|grep -v grep|awk '{print $2}'`
if [ -n "$pid" ];then
	kill -9 $pid
else
	echo "no bvrouter running"
fi

