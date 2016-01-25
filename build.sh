#  build.sh
#svn co https://svn.baidu.com/sys/ip/trunk/pal/pal/
APP=bvrouter
OBJ_DIR=build
OUTPUT_PATH=./output

PWD=`pwd`

DPDK_VERSION='dpdk1.7.1.bond'

DPDK_RTE_TARGET=x86_64-native-linuxapp-gcc
DPDK_NIC_BIND_SCRIPT=dpdk_nic_bind.py

DPDK_PATH=/home/scmpf/dpdk

cd $PWD

CONF=./conf/"$APP".conf 

APP_PATH=./"$OBJ_DIR"/"$APP"
MAP_PATH=./"$OBJ_DIR"/"$APP".map

RTE_DPDK_PATH=$DPDK_PATH/$DPDK_VERSION


VER=`echo $SCMPF_MODULE_VERSION`
#VER=`svn info |grep URL | awk -F '/' '{print $NF}'`
B_DATE=`/bin/date  "+%D %R"`
SVN_VERSION=`sudo svn info | /bin/awk '$1=="Revision:"{print $2}'`

echo "#ifndef _BVR_VER_H_" > ./includes/bvr_ver.h
echo "#define _BVR_VER_H_" >> ./includes/bvr_ver.h
echo "#define BVR_TAG ""\""$VER"\"" >> ./includes/bvr_ver.h
echo "#define BVR_SVN_VERSION ""\""$SVN_VERSION"\"" >> ./includes/bvr_ver.h
echo "#define BVR_BUILD_TIME ""\""$B_DATE"\"" >> ./includes/bvr_ver.h
echo "#endif" >>./includes/bvr_ver.h

sudo make -j8 RTE_SDK=$RTE_DPDK_PATH RTE_TARGET=$DPDK_RTE_TARGET

if [ -d $OUTPUT_PATH ];then
	rm -rf $OUTPUT_PATH/$APP
else
	mkdir $OUTPUT_PATH
fi

cp $APP_PATH $OUTPUT_PATH
cp $MAP_PATH $OUTPUT_PATH

CONF_FILE=$OUTPUT_PATH/$CONF
if [ ! -f "$CONF_FILE" ]; then
	cp $CONF $OUTPUT_PATH
fi

ENV_FILE=$OUTPUT_PATH/setup.sh
if [ ! -f "$ENV_FILE" ]; then
	cp ./setup.sh $OUTPUT_PATH
fi

cp ./kill.sh $OUTPUT_PATH

mkdir -p $OUTPUT_PATH/tools
cp tools/* $OUTPUT_PATH/tools
cp $RTE_DPDK_PATH/tools/$DPDK_NIC_BIND_SCRIPT $OUTPUT_PATH/tools

mkdir -p $OUTPUT_PATH/kmod
cp $RTE_DPDK_PATH/$DPDK_RTE_TARGET/kmod/*.ko $OUTPUT_PATH/kmod

