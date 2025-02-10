const pcap = require("pcap");
const crypto = require("crypto");
const config = require("./config.json");

const packetParser = function(binary,initialPos){
  const packet = binary;
  let pos = initialPos || 0;
  const readString = function() {
    const len_start = pos;
    const len_end = len_start + 4;
    const len = packet.subarray(len_start,len_end).readInt32BE();
    const string_start = len_end;
    const string_end = string_start + len;
    const string = packet.subarray(string_start,string_end).toString();
    pos = string_end ;
    return string;
  }

  const readBoolean = function() {
    const res = packet[pos++];
    return res;
  }

  const readObject = function(o) {
    const obj = {};
    Object.keys(o).forEach(key => {
      if(o[key] === 'string') {
        const val = readString();
        obj[key] = val;
      }
      else if(o[key] === 'boolean') {
        const val = readBoolean();
        obj[key] = val;
      }
    });
    return obj;
  }

  return {
    readString,
    readBoolean,
    readObject
  };

};



const pcapFile = "./ssh.pcap";
const MESSAGE = {
    // Transport layer protocol -- generic (1-19)
    DISCONNECT: 1,
    IGNORE: 2,
    UNIMPLEMENTED: 3,
    DEBUG: 4,
    SERVICE_REQUEST: 5,
    SERVICE_ACCEPT: 6,

    // Transport layer protocol -- algorithm negotiation (20-29)
    KEXINIT: 20,
    NEWKEYS: 21,

    // Transport layer protocol -- key exchange method-specific (30-49)
    KEXDH_INIT: 30,
    KEXDH_REPLY: 31,

    KEXDH_GEX_GROUP: 31,
    KEXDH_GEX_INIT: 32,
    KEXDH_GEX_REPLY: 33,
    KEXDH_GEX_REQUEST: 34,

    KEXECDH_INIT: 30,
    KEXECDH_REPLY: 31,

    // User auth protocol -- generic (50-59)
    USERAUTH_REQUEST: 50,
    USERAUTH_FAILURE: 51,
    USERAUTH_SUCCESS: 52,
    USERAUTH_BANNER: 53,

    // User auth protocol -- user auth method-specific (60-79)
    USERAUTH_PASSWD_CHANGEREQ: 60,

    USERAUTH_PK_OK: 60,

    USERAUTH_INFO_REQUEST: 60,
    USERAUTH_INFO_RESPONSE: 61,

    // Connection protocol -- generic (80-89)
    GLOBAL_REQUEST: 80,
    REQUEST_SUCCESS: 81,
    REQUEST_FAILURE: 82,

    // Connection protocol -- channel-related (90-127)
    CHANNEL_OPEN: 90,
    CHANNEL_OPEN_CONFIRMATION: 91,
    CHANNEL_OPEN_FAILURE: 92,
    CHANNEL_WINDOW_ADJUST: 93,
    CHANNEL_DATA: 94,
    CHANNEL_EXTENDED_DATA: 95,
    CHANNEL_EOF: 96,
    CHANNEL_CLOSE: 97,
    CHANNEL_REQUEST: 98,
    CHANNEL_SUCCESS: 99,
    CHANNEL_FAILURE: 100

    // Reserved for client protocols (128-191)

    // Local extensions (192-155)
  };


const pcapSession = pcap.createOfflineSession(pcapFile, "tcp");

const ivCS = Buffer.from(config.outbound.cipherIV);
const keyCS = Buffer.from(config.outbound.cipherKey);
const ivSC = Buffer.from(config.inbound.decipherIV);
const keySC = Buffer.from(config.inbound.decipherKey);
const decipherCS = crypto.createDecipheriv("aes-128-ctr", keyCS, ivCS);
const decipherSC = crypto.createDecipheriv("aes-128-ctr", keySC, ivSC);
let newKeysSent = false;
let packet_number =0;
let clientAddress;
pcapSession.on("packet", (rawPacket) => {
  const packet = pcap.decode.packet(rawPacket);
  if (packet.payload.ethertype!==2048)
    return;
  console.log(packet.link_type);
  console.log('packet:', JSON.stringify(packet));
  if (packet_number == 0) {
    clientAddress = packet.payload.payload.saddr.toString();
    serverAddress = packet.payload.payload.daddr.toString();
  }
  packet_number++;
  const tcp = packet.payload.payload.payload;
  const direction = packet.payload.payload.saddr.toString() === clientAddress ? 'CS':'SC';

  if (tcp && tcp.data && (tcp.sport === 22 || tcp.dport === 22)) {
    const sshData = tcp.data ? tcp.data.toString("utf-8") : "";
    if (sshData.startsWith("SSH-")) {
      console.log("SSH Protocol Version Exchange:");
      console.log(sshData.trim());
    } else if (tcp.data) {
      let packet_len, msg_code;
      if (newKeysSent === false) {
        packet_len = tcp.data.subarray(0, 4).readInt32BE(0);
        padding_len = tcp.data[4];
        msg_code = tcp.data[5];
      } else {
        let decryptedPacket;
        let encryptedPacket = tcp.data.subarray(0,tcp.data.length-32);
        let mac = tcp.data.subarray(tcp.data.length-32);
        if(direction === 'CS') {
            decryptedPacket = decipherCS.update(encryptedPacket);
        } else if (direction === 'SC') {
            decryptedPacket = decipherSC.update(encryptedPacket);
        }
        console.log(`Entire Packet, ${direction} :`, tcp.data.toString("hex"));
        console.log(`Encrypted SSH Packet, ${direction} :`, encryptedPacket.toString("hex"));
        console.log(`MAC, ${direction} :`,mac.toString('hex'));
        packet_len = decryptedPacket.subarray(0, 4).readInt32BE(0);
        padding_len = decryptedPacket[4];
        msg_code = decryptedPacket[5];
        const msg_name = Object.keys(MESSAGE).find(key => MESSAGE[key] === msg_code);
        console.log("Decrypted Packet :", decryptedPacket.toString("hex"));
        console.log(`packet length=${packet_len}`);
        console.log(`message code=${msg_name}`);
        if (msg_code === MESSAGE.USERAUTH_REQUEST) {
          const parser = packetParser(decryptedPacket,6);
          const obj = parser.readObject({user:'string',service:'string',method:'string'});
          if (obj.method === "password") {
            const passObj = parser.readObject({isChange:'boolean',password:'string'});
            console.log('Username : ' + obj.user);
            console.log('Password : ' + passObj.password);
          }
        }
      }
      if (msg_code == MESSAGE.NEWKEYS) {
        newKeysSent = true;
      }
    }
  }
});

pcapSession.on("error", (err) => {
  console.error("Error:", err.message);
});

pcapSession.on("complete", () => {
  console.log("Finished reading pcap file.");
});
