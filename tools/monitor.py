# !/usr/bin/python
#########################################################
#         zhangyu09@baidu.com                           #
#         monitor for bvrouter                          # 
#         ps_stat:monitor the process status of ospf    #
#                 zebra and bvrouter                    #
#         cpu_stat:monitor the cpu status of datapath   #
#         icmp_stat:monitor whether can access to gw    #
#                   or not                              #
#         port_stat:throughoutput and rx or tx error    #
#########################################################
import os
import commands
import json
import telnetlib
import sys
import cStringIO
import re


HOST = "localhost"
PORT = ["ospfd"]
PASSWD = "zebra"
#need to be change to gateway ip (gwip on vnic0)
GW = "44.44.44.1"
THROUGHOUT = 6710886400*2#10Gbps
RXMISS = 1000
RXBADCRC = 1000
RXBADLEN = 1000
RXERROR = 1000
TXERROR = 1000
CPU_RATIO = 80

def telnet(cmds, PORT):
    try:
        telnet = telnetlib.Telnet(HOST, PORT)
        telnet.read_until("Password:")
        telnet.write(PASSWD + "\r")
        telnet.read_until(">")
        for cmd in cmds:
            telnet.write(cmd)
        out = telnet.read_all()
        return out
    except Exception as e:
        print e
        return None


def ospf_stat():
    cmds = ['show ip ospf nei \r', 'quit \r']
    ok = 0
    warning = ""
    out = telnet(cmds, PORT[0])

    output = cStringIO.StringIO(out)
    for i in output.readlines():
        if re.search(GW, i) and re.search('Full', i):
            warning = warning + 'YES'

    if not warning:
        warning = warning + 'ospf neigh error'
    return warning

def ps_stat():
    """check if the zebra,ospfd,bvrouter exist"""
    ret1,zebra_id = commands.getstatusoutput('pidof zebra | wc -l')
    ret2,ospf_id = commands.getstatusoutput('pidof ospfd | wc -l')
    ret3,bvrouter_id = commands.getstatusoutput('pidof bvrouter | wc -l')
    warning = ""
    if int(zebra_id) == 0:
	warning = warning + "zebra killed "
    if int(ospf_id) == 0:
        warning = warning + "ospfd killed "
    if int(bvrouter_id) == 0:
        warning = warning + "bvrouter killed"

    if not warning:
        warning = warning + "YES"

    return warning


def cpu_stat():
    """check the cpu usage not overload"""
    ret,cpu_usage = commands.getstatusoutput('bvr-agent cpu-usage-show')
    warning = ""
    index = 0 

    if ret != 0:
        warning = warning + "connect to bvrouter error."
        return warning
    
    cpu_usage_json = json.loads(cpu_usage)
    for datapath in cpu_usage_json:
        usage = datapath["datapath_core"]
        if usage >= CPU_RATIO:
            warning = warning + ('core %s CPU overload %s. '%(index, usage))
        index += 1
    if not warning:
        warning  = warning + "YES"
    return warning


def icmp_stat():
    """check the connection with gateway"""
    ret,result = commands.getstatusoutput('ping -c 1 %s -w 1 |grep "1 received"|wc -l'%GW)
    warning = ""
    if int(result) == 1:
        warning = warning + 'YES'
    else:
        warning = warning + "can not connected to gateway."

    return warning

def link_stat():
    """show port link status. we use bonding port, one slave error, report warning"""
    ret,link = commands.getstatusoutput('bvr-agent if-link-show')
    warning = ""
    if ret != 0:
        warning = warning + "connect to bvrouter error."
        return warning
    link_json = json.loads(link)
    for port_link in link_json:
        linkstatus = port_link['link_status']
        if linkstatus == 0:
            warning = warning + ('port %s link down. '%port_link['port_id'])
    if not warning:
        warning  = warning + "YES"
    return warning
        

def port_stat():
    """port status include port throughout and error count"""
    ret,stat = commands.getstatusoutput('bvr-agent bond-interface-stat-show')
    warning = ""
    index = 0    

    if ret != 0:
        warning = warning + "connect to bvrouter error"
        return warning
   
    stat_json = json.loads(stat)
    rx_bytes = long(stat_json[0]["rxbytes"])
    rx_missed = long(stat_json[0]["rxmissed"])
    rx_badcrc = long(stat_json[0]["rxbadcrc"])
    rx_badlen = long(stat_json[0]["rxbadlen"])
    rx_errors = long(stat_json[0]["rxerrors"])
    tx_errors = long(stat_json[0]["txerrors"])
      	
    f = open('./port_stat', 'r+')
    stat_last = f.read()
    stat_last_json = json.loads(stat_last)
    f.close()

    if not stat_last_json:
        rx_bytes_last = rx_bytes
        rx_missed_last = 0
        rx_badcrc_last = 0
        rx_badlen_last = 0
        rx_errors_last = 0
        tx_errors_last = 0
    else:
        rx_bytes_last = long(stat_last_json[0]["rxbytes"])
        rx_missed_last = long(stat_last_json[0]["rxmissed"])
        rx_badcrc_last = long(stat_last_json[0]["rxbadcrc"])
        rx_badlen_last = long(stat_last_json[0]["rxbadlen"])
        rx_errors_last = long(stat_last_json[0]["rxerrors"])
        tx_errors_last = long(stat_last_json[0]["txerrors"])
    
    rx_bytes_delta = rx_bytes - rx_bytes_last
    #print 'thoughoutput %s'%(rx_bytes_delta*8/10/1024/1024)
    if rx_bytes_delta > THROUGHOUT:
        warning = warning + ("rx flow (%s) Mbps is greater than 5Gbps. "%(rx_bytes_delta*8/10/1024/1024))
    
    rx_missed_delta = rx_missed - rx_missed_last
    #print 'rx missed %s'%rx_missed_delta
    if rx_missed_delta > RXMISS:
        warning = warning + ("rx missed pkts %s. "%rx_missed_delta)
 
    rx_badcrc_delta = rx_badcrc - rx_badcrc_last
    #print 'rx badcrc %s'%rx_badcrc_delta
    if rx_badcrc_delta > RXBADCRC:
        warning = warning + ("rx badcrc pkts %s. "%rx_badcrc_delta)

    rx_badlen_delta = rx_badlen - rx_badlen_last
    #print 'rx badlen %s'%rx_badlen_delta
    if rx_badlen_delta > RXBADLEN:
        warning = warning + ("rx badlen pkts %s. "%rx_badlen_delta)

    rx_errors_delta = rx_errors - rx_errors_last
    #print 'rx error delta %s'%rx_errors_delta
    if rx_errors_delta > RXERROR:
        warning = warning + ("rx errors pkts %s. "%rx_errors_delta)
    
    tx_errors_delta = tx_errors - tx_errors_last
    #print 'tx error delta %s'%tx_errors_delta
    if tx_errors_delta > TXERROR:
        warning = warning + ("tx erros pkts %s. "%tx_errors_delta)

    f = open("./port_stat", "w+")
    f.write(json.dumps(stat_json))
    f.close()

    if not warning:
       warning = warning + ("YES")
    return warning

           

def main():
    if not os.path.isfile("./port_stat"):
        f = open("./port_stat", 'w')
        f.write("[]")
        f.close()
        
    ret = ospf_stat()
    print "ospf_stat : %s"%ret
    ret = ps_stat()
    print "ps_stat : %s"%ret
    ret = cpu_stat()
    print "cpu_stat : %s"%ret
    ret = icmp_stat()
    print "icmp_stat : %s"%ret
    ret = port_stat()
    print "port_stat : %s"%ret
    ret = link_stat()
    print "link_stat : %s"%ret
    print "BDEOF"

if __name__ == '__main__':
    main()

