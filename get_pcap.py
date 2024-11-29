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

from datetime import datetime


def valid_date(date_string):
    try:
        return datetime.strptime(date_string, "%Y-%m-%d")
    except ValueError:
        raise argparse.ArgumentTypeError(f"Invalid date: '{date_string}'. Format should be YYYY-MM-DD.")


parser = argparse.ArgumentParser()

# Caller ID array
parser.add_argument(
    "--caller-ids",
    type=int,
    nargs="+",
    default=[],
    help="List of caller IDs (space-separated integers).",
)

# Start date
parser.add_argument(
    "--start",
    type=valid_date,
    required=True,
    help="Start date in the format YYYY-MM-DD (e.g., 2023-01-01).",
)

# End date
parser.add_argument(
    "--end",
    type=valid_date,
    required=True,
    help="End date in the format YYYY-MM-DD (e.g., 2023-12-31).",
)

# Optional boolean flag for new tcpdump format
parser.add_argument(
    "--new-tcpdump-format",
    action="store_true",
    help="Enable the new tcpdump format if specified. Defaults to False.",
)

# MySQL connection parameters
parser.add_argument(
    "--mysql-host",
    type=str,
    default='localhost',
    help="MySQL server host (e.g., 'localhost', '127.0.0.1').",
)
parser.add_argument(
    "--mysql-user",
    type=str,
    default='root',
    help="MySQL username.",
)
parser.add_argument(
    "--mysql-password",
    type=str,
    required=True,
    help="MySQL password.",
)
parser.add_argument(
    "--mysql-database",
    type=str,
    default='voipmonitor',
    help="MySQL database name.",
)
parser.add_argument(
    "--mysql-port",
    type=int,
    default=3306,
    help="MySQL server port. Defaults to 3306.",
)

parser.add_argument(
    "--base-path",
    type=str,
    default='/var/spool/voipmonitor',
    help="Base path for pcap files.",
)
args = parser.parse_args()

# Can be true or false, depending on TCPDump version.
# If you're experiencing some weird exceptions in DPKT - try to change this to false.
# Also, you can check a dump in Wireshark - if no Ethernet headers there you have to use this option
new_tcpdump_format = args.new_tcpdump_format

# Establish the connection
conn = pymysql.connect(
    host=args.mysql_host,
    user=args.mysql_user,
    password=args.mysql_password,
    database=args.mysql_database,
    port=args.mysql_port,
)

basepath = args.base_path

callerid_array = [str(x) for x in args.caller_ids]
start_date = str(args.start)
end_date = str(args.end)

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
    pcap2wav(sip_path, rtp_path, str(calldate).replace(':', '-') + ' ' + caller + ' - ' + called + '.wav',
             new_tcpdump_format=new_tcpdump_format)
