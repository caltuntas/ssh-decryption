FROM node:16-bullseye

RUN apt-get update && apt-get install -y tcpdump libpcap-dev vim

WORKDIR /usr/src/app

COPY package*.json ./

RUN npm install

COPY . .

RUN patch -p0 < dumpkeys.patch

ENTRYPOINT ["./start.sh"]
