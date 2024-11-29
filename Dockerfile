FROM ubuntu:20.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update
RUN apt-get install -y python3.9 python3.9-venv
RUN apt-get clean


WORKDIR /app
RUN python3.9 -m venv /app/.venv

ENV PATH="/app/.venv/bin:$PATH"
RUN python3 -m pip install --upgrade pip

COPY . /app
RUN python3 -m pip install -r /app/requirements.txt

# Set the default command to run the script
CMD ["python3", "/app/get_pcap.py"]