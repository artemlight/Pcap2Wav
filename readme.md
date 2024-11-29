How to use:

```
git clone
docker build . -t pcap2wav
mkdir /output
docker run -ti --network host \
        -v /var/spool/voipmonitor:/var/spool/voipmonitor \
        -v /output:/output \
        pcap2wav python3 /app/get_pcap.py \
        --new-tcpdump-format \
        --mysql-password=changeit \
        --start=2024-11-25 \
        --end=2024-11-28 \
        --output-directory=/output \
        --caller-ids 1139 1102
```