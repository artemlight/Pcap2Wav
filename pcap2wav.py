#!/usr/bin/python3
import dpkt
import gzip
import socket
import ipaddress
import argparse
from collections import namedtuple
import os
import struct
import sdpparser
import wave
import audioop
class SipMessage:
    sip_request_methods = dict.fromkeys((
        'ACK', 'BYE', 'CANCEL', 'INFO', 'INVITE', 'MESSAGE', 'NOTIFY',
        'OPTIONS', 'PRACK', 'PUBLISH', 'REFER', 'REGISTER', 'SUBSCRIBE',
        'UPDATE'))

    sip_response_header = ['SIP/2.0']

    def parse_headers(self):
        line_number = 0
        char_offset = 0
        for line in self.data.splitlines():
            if line == '':
                self.content = self.data[char_offset + (line_number + 1) * len(os.linesep):]
                return
            # Method
            if line_number == 0:
                pass
            else:
                # Headers
                header, value = line.split(':', 1)
                self.headers[header.strip()] = value.strip()
                pass
            char_offset += len(line)
            line_number += 1
        pass

    def check_request_or_responce(self):
        # Понять запрос это или ответ
        first_sentence = self.data[:self.data.find(' ')]
        if first_sentence in self.sip_request_methods:
            self.message_type = 'request'
            self.method = first_sentence
        elif first_sentence in self.sip_response_header:
            self.message_type = 'response'
        else:
            self.message_type = 'undefined'
            print('Warning: undefined packet first sentence:', first_sentence)
        pass

    def __init__(self, data, src_ip, dst_ip, timestamp):
        self.sdp_data = None
        self.source_ip = ''
        self.destination_ip = ''
        self.message_type = ''
        self.content_type = ''
        self.data = ''
        self.headers = {}
        self.content_position = 0
        self.content = ''
        self.timestamp = timestamp
        self.data = data
        self.source_ip = src_ip
        self.destination_ip = dst_ip
        self.method = ''

        self.check_request_or_responce()
        self.parse_headers()

        if 'Content-Type' in self.headers:
            self.content_type = self.headers['Content-Type']

        if self.content_type == 'application/sdp':
            self.sdp_data = sdpparser.SDPParser(self.content)
class SipSession:
    def __init__(self, callid):
        self.callid = callid
        self.requests = list()
        self.session_start = -1
        self.session_complete = -1
        self.initiator_ip = None
        self.target_ip = None
        self.sdp = list()

    def AddMessage(self, msg):
        self.requests.append(msg)
        if not (msg.sdp_data is None):
            self.sdp.append(len(self.requests) - 1)

        if msg.message_type == 'request' and msg.method == 'INVITE':
            self.initiator_ip = msg.source_ip
            self.target_ip = msg.destination_ip
        pass


# Main routine
def pcap2wav(param_sip_file,param_rtp_file,param_out_file):
    file_sip = gzip.open(param_sip_file, 'rb')
    pcap = dpkt.pcap.Reader(file_sip)
    sip_sessions = {}
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        if ip.p == socket.IPPROTO_UDP:
            if ip.udp.dport == 5060:
                sip_msg = SipMessage(ip.udp.data.decode('utf-8'),
                                     src_ip=ipaddress.ip_address(ip.src),
                                     dst_ip=ipaddress.ip_address(ip.dst),
                                     timestamp=ts)

                if 'Call-ID' in sip_msg.headers:
                    callid = sip_msg.headers['Call-ID']
                    if callid not in sip_sessions:
                        sip_sessions[callid] = SipSession(callid)
                    sip_sessions[callid].AddMessage(sip_msg)
                else:
                    print('SIP message without call-id!')

    file_sip.close()

    print('SIP sessions found:')
    for session in sip_sessions:
        print(session, str(sip_sessions[session].initiator_ip) + '->' + str(sip_sessions[session].target_ip))
        print('     RTP Streams:')
        if len(sip_sessions[session].sdp) != 2:
            print('Error: more or less than 2 RTP streams per channel!')
            # exit()
        for sdp_request_index in sip_sessions[session].sdp:
            print('     ',
                  sip_sessions[session].requests[sdp_request_index].source_ip, ':',
                  sip_sessions[session].requests[sdp_request_index].sdp_data.media_descriptions['audio'].port)

    jb_size_ms = 100  # jitterbuffer in ms

    wav_file = wave.open(param_out_file, 'wb')
    sample_rate_ms = 8
    sample_width = 2

    wav_file.setsampwidth(sample_width)
    wav_file.setnchannels(1)
    wav_file.setframerate(sample_rate_ms * 1000)

    # jb double size
    # Первый джиттербуффер находится в нулевой точке
    # второй -  в jb_samples точке

    jb_samples = int(sample_rate_ms * jb_size_ms)
    jb = bytearray(jb_samples * 2)

    jb_cur = 0

    jb_start = 0
    jb_end = jb_start + jb_samples - 1
    jb_first_sample = 0
    # Первый RTP семпл
    first_packet_time = 0

    unpack_ushort = struct.Struct('<h').unpack_from
    pack_ushort = struct.Struct('<h').pack_into

    for session_id in sip_sessions:
        session = sip_sessions[session_id]
        rtp_stream = {}
        rtp_ports = []
        # Получаем список стримов ртп
        for sdp_index in session.sdp:
            rtp_ports.append(session.requests[sdp_index].sdp_data.media_descriptions['audio'].port)

        file_rtp = open(param_rtp_file, 'rb')
        pcap = dpkt.pcap.Reader(file_rtp)
        jb_start_ms = 0
        packets_in_jb = 0
        jb_skipped_samples = 0
        seqno = 0

        for abs_ts, buf in pcap:

            seqno += 1
            ts = int(abs_ts * 1000 - first_packet_time)
            # Время прибытия первого пакета в разговор
            if first_packet_time == 0:
                print("First packet time: ", abs_ts)
                first_packet_time = abs_ts * 1000
                ts = 0
                jb_start_ms = ts

            out_buffer = bytes(jb_samples * 2)

            # Восстанавливаем естественное течение времени.

            # Очередной пакет - нам нужно понять, что делать
            # Есть три варианта
            # jb_start_ms  =< ts < jb_start_ms + jb_size_ms

            # 1 - пакет не попадает в наш джиттербуфер (пришел раньше, чем начало JB). Его придётся дропнуть.
            # Этого не должно произойти, т.к. все пакеты сохранены в порядке прибытия
            if ts < jb_start_ms:
                print("Packet time:", ts, " Jitterbuffer range:", jb_start_ms, jb_start_ms + jb_size_ms * 2, ': Skipped.')
                continue

            # 2 - пакет не попадает в наш джиттербуфер (пришел позже, чем конец JB). Тогда нужно флашить джиттербуфер до тех пор, пока мы не сможем этот пакет принять
            while ts >= jb_start_ms + jb_size_ms * 2:
                # flush_jb()
                jb_result = bytearray(jb_samples * sample_width)

                for flush_ssrc in rtp_stream:
                    out_buf = audioop.alaw2lin(rtp_stream[flush_ssrc].jb[0:jb_samples], 2)
                    jb_result = audioop.add(jb_result, out_buf, 2)
                    # Перемещаем данные из джиттербуфера в начало
                    rtp_stream[flush_ssrc].jb[0:jb_samples] = rtp_stream[flush_ssrc].jb[jb_samples:jb_samples * 2]
                    rtp_stream[flush_ssrc].jb[jb_samples:jb_samples * 2] = bytearray(jb_samples)

                wav_file.writeframes(jb_result)
                # print ("JB Flushed at ",jb_start_ms,'-',jb_start_ms+jb_size_ms,'ts=',ts,'packets=',packets_in_jb, 'seqno=',seqno)
                packets_in_jb = 0
                jb_start_ms += jb_size_ms

            # 3 - пакет попадает в наш джиттербуфер, тогда его нужно туда добавить

            # Наполняем джиттербуферы информацией за последние jb_size_ms * 2 миллисекунд
            # Разбираем пакет на запчасти
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            if ip.p == socket.IPPROTO_UDP:
                if ip.udp.dport in rtp_ports:
                    packets_in_jb += 1
                    rtp_data = dpkt.rtp.RTP(ip.udp.data)

                    ssrc = rtp_data.ssrc

                    if ssrc not in rtp_stream:
                        rtp_stream[ssrc] = namedtuple('RtpStream',
                                                      ['last_seqno', 'jb', 'first_rtp_timestamp', 'first_cap_timestamp',
                                                       'mix_start_sample'])
                        rtp_stream[ssrc].last_seqno = 0
                        rtp_stream[ssrc].jb = bytearray(jb_samples)  # *2 todo:fix!
                        # Таймстемп из RTP
                        rtp_stream[ssrc].first_rtp_timestamp = rtp_data.ts
                        # Таймстемп из файла
                        rtp_stream[ssrc].first_cap_timestamp = ts
                        # Вычисляем номер стартового семпла в выходном потоке
                        # Берем время фактического получения пакета, добавляем размер життербуфера и умножаем на количество семплов в секунде.
                        # Если добавлять джиттербуфер ко всем потокам, то мы просто смещаем весь микс на ширину життербуфера. Поэтому его добавлять не будем.
                        rtp_stream[ssrc].mix_start_sample = int((ts) * sample_rate_ms)

                    # Вычисляем номер семпла в выходном потоке, куда должен быть замикширован текущий семпл
                    # todo: оно не учитывает различный битрейт!
                    # Преобразуем таймстемп пакета
                    # Таймстемп пакета представляет из себя номер семпла. Зная первый таймстемп
                    out_file_sample_num = rtp_data.ts - rtp_stream[ssrc].first_rtp_timestamp + rtp_stream[
                        ssrc].mix_start_sample

                    # print(  ts, jb_start_ms,jb_start_ms + jb_size_ms * 2, out_file_sample_num, out_file_sample_num/sample_rate_ms )
                    # Проверяем, попадает ли полученный нами пакет в нижнюю границу джиттербуфера
                    if out_file_sample_num < (jb_start_ms) * sample_rate_ms:
                        print("Error: RTP #", rtp_data.seq, 'timestamp lower than expected', ts, jb_start_ms,
                              jb_start_ms + jb_size_ms * 2, out_file_sample_num / sample_rate_ms)
                        rtp_stream[ssrc].mix_start_sample += len(rtp_data.data)
                        continue
                    # Проверяем, попадает ли полученный нами пакет в верхнюю границу джиттербуфера
                    if out_file_sample_num >= (jb_start_ms + jb_size_ms * 2) * sample_rate_ms - len(rtp_data.data):
                        # Если вдруг этот пакет переполняет джиттербуфер - делаем вид, что его не было.
                        rtp_stream[ssrc].mix_start_sample -= len(rtp_data.data)
                        print("Clock drift: RTP ", ssrc, "#", rtp_data.seq,
                              'timestamp higher than expected ', ts, jb_start_ms, jb_start_ms + jb_size_ms * 2,
                              out_file_sample_num / sample_rate_ms,
                              (jb_start_ms + jb_size_ms * 2) * sample_rate_ms - out_file_sample_num)
                        continue
                    # Фигачим семпл в джиттербуфер
                    rtp_stream[ssrc].jb[
                    out_file_sample_num - jb_start_ms * sample_rate_ms:out_file_sample_num - jb_start_ms * sample_rate_ms + len(
                        rtp_data.data)] = rtp_data.data

    file_rtp.close()
