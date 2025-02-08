const pcap = require("pcap");
const crypto = require("crypto");
const config = require("./config.json");

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
let serverAddress;
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
      let packet_len, padding_len, msg_code;
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
        const payload_len = packet_len - padding_len -1;
        const payload = decryptedPacket.subarray(5,payload_len+5).toString('hex');
        msg_code = decryptedPacket[5];
        const msg_name = Object.keys(MESSAGE).find(key => MESSAGE[key] === msg_code);
        console.log("Decrypted Packet :", decryptedPacket.toString("hex"));
        console.log(`packet length=${packet_len}`);
        console.log(`message code=${msg_name}`);
        if (msg_code === MESSAGE.USERAUTH_REQUEST) {
          const username_len_start = 6;
          const username_len_end = username_len_start + 4;
          const username_len = decryptedPacket.subarray(username_len_start,username_len_end).readInt32BE();
          const username_start = username_len_end;
          const username_end = username_start + username_len + 1;
          const username = decryptedPacket.subarray(username_start,username_end).toString();
          const service_name_len_start = username_end-1;
          const service_name_len_end = username_end + 4;
          const service_name_len = decryptedPacket.subarray(service_name_len_start, service_name_len_end).readInt32BE();
          const service_name_start = service_name_len_end -1;
          const service_name_end = service_name_start + service_name_len -1;
          const service_name = decryptedPacket.subarray(service_name_start, service_name_end + 1).toString();
          const method_len_start = service_name_end + 1;
          const method_len_end = method_len_start + 4;
          const method_len = decryptedPacket.subarray(method_len_start, method_len_end).readInt32BE();
          const method_start = method_len_end ;
          const method_end = method_start + method_len;
          const method = decryptedPacket.subarray(method_start, method_end).toString();
          if (method === "password") {
            const pass_len_start = method_end + 1;
            const pass_len_end = pass_len_start + 4;
            const pass_len = decryptedPacket.subarray(pass_len_start, pass_len_end).readInt32BE();
            const pass_start = pass_len_end;
            const pass_end = pass_start + pass_len;
            const pass = decryptedPacket.subarray(pass_start, pass_end).toString();
            console.log('Username : ' + username);
            console.log('Password : ' + pass);
          }
        }
      }
      if (msg_code == 21) {
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
