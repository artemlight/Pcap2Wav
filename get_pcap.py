import pymysql
import datetime
import dpkt
import gzip
import socket
import ipaddress
import argparse
from collections import namedtuple
import os
import struct
import wave
import audioop
import base64
from .pcap2wav import pcap2wav

# Can be true or false, depending on TCPDump version.
# If you're experiencing some weird exceptions in DPKT - try to change this to false.
# Also, you can check a dump in Wireshark - if no Ethernet headers there you have to use this option
new_tcpdump_format = True

# Establish the connection
conn = pymysql.connect(
    host='localhost',
    user='root',
    password='rootpassword',
    database='voipmonitor'
)

basepath = '/var/spool/voipmonitor'

callerid_array = [str(x) for x in [1139, 1159, 1102, 1149, 1175, 1510, 1605, 1617, 214, 1118, 209, 1512]]
start_date = str(datetime.date(year=2024, month=11, day=25))
end_date = str(datetime.date(year=2024, month=11, day=28))

sql_query = f"""
  SELECT cdr.calldate, duration, caller, called, fbasename from cdr left join cdr_next on cdr.id = cdr_next.cdr_ID
  where 
   cdr.calldate BETWEEN %s and %s 
   AND
   lastSIPresponseNum = 200 
   AND
   (
    (caller in ({','.join(['%s'] * len(callerid_array))}) AND LENGTH(called)>4)
     OR 
    (LENGTH(caller)>4 AND called in ({','.join(['%s'] * len(callerid_array))}))
   )
"""

cur = conn.cursor()
cur.execute(sql_query, [start_date, end_date] + callerid_array + callerid_array)

for calldate, duration, caller, called, fbasename in cur:
    print(calldate, ': ', caller, '->', called, sep='')
    rtp_path = f"{basepath}/{calldate.strftime('%Y-%m-%d/%H/%M')}/RTP/{fbasename}.pcap"
    sip_path = f"{basepath}/{calldate.strftime('%Y-%m-%d/%H/%M')}/SIP/{fbasename}.pcap"
    pcap2wav(sip_path, rtp_path, str(calldate).replace(':', '-') + ' ' + caller + ' - ' + called + '.wav', new_tcpdump_format=new_tcpdump_format)
