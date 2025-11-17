const pcap = require("pcap");
const crypto = require("crypto");

const key1 = Buffer.from(process.env.KEY1, "hex");
const key2 = Buffer.from(process.env.KEY2, "hex");
const iv1 = Buffer.from(process.env.IV1, "hex");
const iv2 = Buffer.from(process.env.IV2, "hex");
const decipherCache = new Map();
//https://www.rfc-editor.org/rfc/rfc4251.html#section-7
const MAX_MESSAGE_CODE = 255;
const MIN_MESSAGE_CODE = 0;
//https://datatracker.ietf.org/doc/html/rfc4253#section-6.1
const MAX_PACKET_LEN = 35000;

const sshSession = (function () {
  let sourcePort;
  let destinationPort;
  const init = function (tcp) {
    sourcePort = tcp.sport;
    destinationPort = tcp.dport;
    console.log("SSH Protocol Version Exchange:");
  };

  const hasPacket = function (tcp) {
    return (
      tcp.data &&
      sourcePort &&
      destinationPort &&
      (destinationPort == tcp.dport || destinationPort == tcp.sport) &&
      (sourcePort == tcp.sport || sourcePort == tcp.dport)
    );
  };

  return {
    init,
    hasPacket,
  };
})();

const packetParser = function (binary, initialPos) {
  const packet = binary;
  let pos = initialPos || 0;
  const readString = function () {
    const len_start = pos;
    const len_end = len_start + 4;
    const len = packet.subarray(len_start, len_end).readInt32BE();
    const string_start = len_end;
    const string_end = string_start + len;
    const string = packet.subarray(string_start, string_end).toString();
    pos = string_end;
    return string;
  };

  const readBoolean = function () {
    const res = packet[pos++];
    return res;
  };

  const readObject = function (o) {
    const obj = {};
    Object.keys(o).forEach((key) => {
      if (o[key] === "string") {
        const val = readString();
        obj[key] = val;
      } else if (o[key] === "boolean") {
        const val = readBoolean();
        obj[key] = val;
      }
    });
    return obj;
  };

  return {
    readString,
    readBoolean,
    readObject,
  };
};

const pcapFile = "./sshdump.pcap";
const EtherTypes = {
  IPv4: 2048,
};
const Directions = {
  ServerToClient: "SC",
  ClientToServer: "CS",
};
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
  CHANNEL_FAILURE: 100,
};

function countPackets(pcapFile) {
  return new Promise((resolve, reject) => {
    const pcapSession = pcap.createOfflineSession(pcapFile, "tcp");
    let packetCount = 0;
    pcapSession.on("packet", () => {
      packetCount++;
    });
    pcapSession.on("complete", () => {
      resolve(packetCount);
    });
    pcapSession.on("error", (err) => {
      reject(err);
    });
  });
}

function decrementIV(iv) {
  const hex = iv.toString("hex");
  const ivBigInt = BigInt("0x" + hex);
  const newIvBigInt = ivBigInt - 1n;
  return Buffer.from(newIvBigInt.toString(16), "hex");
}

function decryptPacket(decipher, buffer) {
  const MAC_LEN = 32;
  let decryptedPacket;
  let encryptedPacket;
  if (isETM) {
    encryptedPacket = buffer.subarray(4, buffer.length - MAC_LEN);
  } else {
    encryptedPacket = buffer.subarray(0, buffer.length - MAC_LEN);
  }
  decryptedPacket = decipher.update(encryptedPacket);
  if (isETM) {
    decryptedPacket = Buffer.concat([buffer.subarray(0, 4), decryptedPacket]);
  }
  packet_len = decryptedPacket.subarray(0, 4).readInt32BE(0);
  padding_len = decryptedPacket[4];
  msg_code = decryptedPacket[5];
  return {
    packet_len,
    padding_len,
    msg_code,
    payload: decryptedPacket,
  };
}

const isETM = false;
function createDecipher(buffer, direction) {
  verifyKeyAndIv = function (key, iv, buffer, packetCount) {
    for (let i = packetCount; i >= 0; i--) {
      const decipher = crypto.createDecipheriv("aes-128-ctr", key, iv);
      const packet = decryptPacket(decipher, buffer);
      if (
        packet.packet_len >= MAX_PACKET_LEN ||
        packet.packet_len <= 0 ||
        packet.msg_code > MAX_MESSAGE_CODE ||
        msg_code < 0
      ) {
        iv = decrementIV(iv);
      } else {
        return iv;
      }
    }
  };

  if (decipherCache.has(direction)) return decipherCache.get(direction);

  const options = [
    { key: key1, iv: iv1 },
    { key: key1, iv: iv2 },
    { key: key2, iv: iv1 },
    { key: key2, iv: iv2 },
  ];

  for (const o of options) {
    const result = verifyKeyAndIv(o.key, o.iv, buffer, 5000);
    if (result) {
      const decipher = crypto.createDecipheriv("aes-128-ctr", o.key, result);
      decipherCache.set(direction, decipher);
      return decipher;
    }
  }
}

function decryptSession(file, packetCount) {
  const pcapSession = pcap.createOfflineSession(file, "tcp");
  let newKeysSent = false;
  let packet_number = 0;
  let clientAddress;
  pcapSession.on("packet", (rawPacket) => {
    const packet = pcap.decode.packet(rawPacket);
    if (packet.payload.ethertype !== EtherTypes.IPv4) return;
    if (packet_number == 0) {
      clientAddress = packet.payload.payload.saddr.toString();
      serverAddress = packet.payload.payload.daddr.toString();
    }
    packet_number++;
    const tcp = packet.payload.payload.payload;
    const direction =
      packet.payload.payload.saddr.toString() === clientAddress
        ? Directions.ClientToServer
        : Directions.ServerToClient;

    if (tcp && tcp.data && (tcp.sport === 22 || tcp.dport === 22)) {
      const sshData = tcp.data ? tcp.data.toString("utf-8") : "";
      if (sshData.startsWith("SSH-")) {
        sshSession.init(tcp);
        console.log(sshData.trim());
      } else if (sshSession.hasPacket(tcp)) {
        let packet_len, msg_code;
        if (newKeysSent === false) {
          packet_len = tcp.data.subarray(0, 4).readInt32BE(0);
          padding_len = tcp.data[4];
          msg_code = tcp.data[5];
        } else {
          const decipher = createDecipher(tcp.data, direction, packetCount);
          const decryptedPacket = decryptPacket(decipher, tcp.data);
          console.log(`TCP Packet, ${direction} :`, tcp.data.toString("hex"));
          const msg_name = Object.keys(MESSAGE).find(
            (key) => MESSAGE[key] === decryptedPacket.msg_code
          );
          console.log(
            "Decrypted Packet :",
            decryptedPacket.payload.toString("hex")
          );
          console.log(`packet length=${decryptedPacket.packet_len}`);
          console.log(`message code=${msg_name}`);
          if (decryptedPacket.msg_code === MESSAGE.USERAUTH_REQUEST) {
            const parser = packetParser(decryptedPacket.payload, 6);
            const obj = parser.readObject({
              user: "string",
              service: "string",
              method: "string",
            });
            if (obj.method === "password") {
              const passObj = parser.readObject({
                isChange: "boolean",
                password: "string",
              });
              console.log("Username : " + obj.user);
              console.log("Password : " + passObj.password);
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
}

async function main() {
  const packetCount = await countPackets(pcapFile);
  decryptSession(pcapFile, packetCount);
}


main();
