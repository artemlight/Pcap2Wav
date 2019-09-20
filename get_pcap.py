#!/usr/bin/python3
from argparse import Namespace
import pymysql
import sys
from pcap2wav import pcap2wav

mysql_addr = '10.1.0.20'
mysql_login = 'root'
mysql_password = 'rootpassword'
mysql_db = 'voipmonitor'

callerid_array = []
for arg in sys.argv[1:]:
    callerid_array.append(arg)

basepath = '/var/spool/voipmonitor'

conn = pymysql.connect(host=mysql_addr,user=mysql_login, password=mysql_password,db=mysql_db)
cur = conn.cursor()

sql_query = """
            SELECT cdr.calldate, duration, caller, called, fbasename from cdr left join cdr_next on cdr.id = cdr_next.cdr_ID
  where ((caller in @CALLERID_ARRAY AND LENGTH(called)>4) OR (LENGTH(caller)>4 AND called in @CALLERID_ARRAY) )AND DATEDIFF(now(),cdr.calldate) < 11 AND lastSIPresponseNum = 200
"""

callerid_string = '('
for num in callerid_array:
    callerid_string = callerid_string+"'"+num+"',"
callerid_string = callerid_string[:-1]+')'
sql_query.replace('@CALLERID_ARRAY',callerid_string)

cur.execute (sql_query)
for calldate, duration, caller, called, fbasename in cur:
    print(calldate,': ',caller,'->',called,sep='')
    rtp_path = basepath + '/' + str(calldate.year) + '-' + str(calldate.month).zfill(2) + '-' + str(calldate.day).zfill(2) + '/' + str(
        calldate.hour).zfill(2) + '/' + str(calldate.minute).zfill(2) + '/RTP/' + fbasename + '.pcap'
    sip_path = basepath + '/' + str(calldate.year) + '-' + str(calldate.month).zfill(2) + '-' + str(calldate.day).zfill(2) + '/' + str(
        calldate.hour).zfill(2) + '/' + str(calldate.minute).zfill(2) + '/SIP/' + fbasename + '.pcap'
    pcap2wav(sip_path,rtp_path,str(calldate.replace(':','-')+' '+caller+' - '+called)+'.wav')