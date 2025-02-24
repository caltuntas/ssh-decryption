const pcap = require("pcap");
const crypto = require("crypto");
const pcapFile = "./ssh3.pcap";

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
  
  const readMpint = function() {
    const len_start = pos;
    const len_end = len_start + 4;
    const len = packet.subarray(len_start,len_end).readInt32BE();
    const start = len_end;
    const end = start + len;
    const val = packet.subarray(start,end);
    pos = end ;
    return Buffer.from(val);
  }

  const readBoolean = function() {
    const res = packet[pos++];
    return res;
  }

  const readBuffer = function(len) {
    const buf = packet.subarray(pos,pos + len);
    return Buffer.from(buf);
  }

  const readUint32 = function() {
    const res = packet.subarray(pos,pos + 4).readUInt32BE();
    pos+=4;
    return res;
  }

  const readObject = function(o) {
    const obj = {};
    Object.keys(o).forEach(key => {
      const type = o[key];
      if(type === 'string') {
        const val = readString();
        obj[key] = val;
      }
      else if(type === 'mpint') {
        const val = readMpint();
        obj[key] = val;
      }
      else if(type === 'boolean') {
        const val = readBoolean();
        obj[key] = val;
      }
      else if(type.includes('buffer')) {
        const len = parseInt(type.substring(type.indexOf(':')+1));
        const val = readBuffer(len);
        obj[key] = val;
        pos+=len;
      } else if(type === 'uint32') {
        const val = readUint32();
        obj[key]= val;
      }
    });
    return obj;
  }

  return {
    readString,
    readBoolean,
    readObject,
    readBuffer,
    readUint32,
    readMpint,
  };

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
    CHANNEL_FAILURE: 100

    // Reserved for client protocols (128-191)

    // Local extensions (192-155)
  };


const pcapSession = pcap.createOfflineSession(pcapFile, "tcp");

let ivCS;
let keyCS;
let ivSC;
let keySC;
let decipherCS;
let decipherSC;
let newKeysSent = false;
let packet_number =0;
let clientAddress;
let clientDhPubKey;
let serverDhGexReply;
let clientKexInitPayload;
let serverKexInitPayload;
let clientIdentification;
let serverIdentification;
let sessionId;
pcapSession.on("packet", (rawPacket) => {
  const packet = pcap.decode.packet(rawPacket);
  if (packet.payload.ethertype!==2048)
    return;
  //console.log(packet.link_type);
  //console.log('packet:', JSON.stringify(packet));
  if (packet_number == 0) {
    clientAddress = packet.payload.payload.saddr.toString();
    serverAddress = packet.payload.payload.daddr.toString();
  }
  packet_number++;
  const tcp = packet.payload.payload.payload;
  const direction = packet.payload.payload.saddr.toString() === clientAddress ? 'CS':'SC';
  let clientKexInit;
  let serverKexInit;
  let clientDhGexRequest;

  if (tcp && tcp.data && (tcp.sport === 22 || tcp.dport === 22)) {
    const sshData = tcp.data ? tcp.data.toString("utf-8") : "";
    if (sshData.startsWith("SSH-")) {
      console.log("SSH Protocol Version Exchange:");
      console.log(sshData.trim());
      if (direction === 'CS') 
        clientIdentification = sshData.trim();
      else if (direction === 'SC') 
        serverIdentification = sshData.trim();
    } else if (tcp.data) {
      let packet_len, msg_code;
      if (newKeysSent === false) {
        packet_len = tcp.data.subarray(0, 4).readInt32BE(0);
        padding_len = tcp.data[4];
        msg_code = tcp.data[5];
        const msg_name = Object.keys(MESSAGE).find(key => MESSAGE[key] === msg_code);
        console.log(`message code=${msg_code},${msg_name}`);
        const payload = tcp.data.subarray(5,tcp.data.length-padding_len);
        const payloadWithoutMessageType = tcp.data.subarray(6);
        console.log("direction = " + direction);
        console.log(payload.toString("hex"));
        const parser = packetParser(payloadWithoutMessageType,0);
        if (msg_code === MESSAGE.KEXINIT) {
          const obj = parser.readObject({
            cookie: "buffer:16",
            kex_algorithms: "string",
            server_host_key_algorithms: "string",
            encryption_algorithms_client_to_server: "string",
            encryption_algorithms_server_to_client: "string",
            mac_algorithms_client_to_server: "string",
            mac_algorithms_server_to_client: "string",
            compression_algorithms_client_to_server: "string",
            compression_algorithms_server_to_client: "string",
            languages_client_to_server: "string",
            languages_server_to_client: "string",
            first_kex_packet_follows: "boolean",
            reserved: "buffer:4",
          });
          if (direction === 'CS') {
            clientKexInit = obj;
            clientKexInitPayload = Buffer.from(payload);
          }
          else if (direction === 'SC') {
            serverKexInit = obj;
            serverKexInitPayload = Buffer.from(payload);
          }

          console.log(obj);
        } else if (msg_code === MESSAGE.KEXDH_GEX_REQUEST) {
          console.log("direction = " + direction);
          const obj = parser.readObject({
            min: "uint32",
            n: "uint32",
            max: "uint32",
          });
          if(direction === 'CS')
            clientDhGexRequest = obj;
          console.log(obj);
        } else if (msg_code === MESSAGE.KEXDH_GEX_GROUP && 1===2) {
          const obj = parser.readObject({
            p: "mpint",
            g: "mpint",
          });
          console.log(obj);
        } else if (msg_code === MESSAGE.KEXDH_GEX_INIT || msg_code === MESSAGE.KEXDH_INIT) {
          const obj = parser.readObject({
            e: "mpint",
          });
          clientDhPubKey = obj.e;
          console.log(obj);
        } else if (msg_code === MESSAGE.KEXDH_GEX_REPLY || msg_code === MESSAGE.KEXDH_REPLY) {
          const obj = parser.readObject({
            host_key: "mpint",
            f: "mpint",
            signature: "mpint",
          });
          const hostKeyParser = packetParser(obj.host_key, 0);
          const hostKeyObj = hostKeyParser.readObject({
            type: "string",
            public_key: "mpint",
          });
          serverDhGexReply = obj;
          console.log(hostKeyObj);
        }
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
        const privKey = "497568fef6d00f4026642640302d4f20ddb4fa479d6a6761b10f097e3f9b876b7722092761bf3acaf00ca31152d9aac0a60a26a90edf9b5ccf180d6c5f75890b26415dcf1f34b777b63cb9a91db67fbb3989e9479d3d8b9059ad4071af4220be421d49656156a736f7022fc3b2baeab68295c7010844031af703f04e4f41f4dd";
        const clientPrivateKey = Buffer.from(privKey, "hex"); 

        const dh = crypto.createDiffieHellmanGroup('modp2');
        const dhKey = crypto.createDiffieHellman(dh.getPrime(),dh.getGenerator());
        dhKey.setPublicKey(clientDhPubKey);
        dhKey.setPrivateKey(clientPrivateKey);
        let secret = dhKey.computeSecret(serverDhGexReply.f);
        const hash = crypto.createHash("sha1");
        /*
        The hash H is computed as the HASH hash of the concatenation of the following:

      string    V_C, the client's identification string (CR and LF excluded)
      string    V_S, the server's identification string (CR and LF excluded)
      string    I_C, the payload of the client's SSH_MSG_KEXINIT
      string    I_S, the payload of the server's SSH_MSG_KEXINIT
      string    K_S, the host key
      mpint     e, exchange value sent by the client
      mpint     f, exchange value sent by the server
      mpint     K, the shared secret
        */
       console.log("V_C="+Buffer.from(clientIdentification).toString("hex"));
       console.log("V_S="+Buffer.from(serverIdentification).toString("hex"));
       console.log("I_C="+clientKexInitPayload.toString("hex"));
       console.log("I_S="+serverKexInitPayload.toString("hex"));
       console.log("K_S="+serverDhGexReply.host_key.toString("hex"));
       console.log("e="+clientDhPubKey.toString("hex"));
       console.log("f="+serverDhGexReply.f.toString("hex"));
       console.log("K="+secret.toString("hex"));
       hashString(hash,clientIdentification);
       hashString(hash,serverIdentification);
       hashString(hash,clientKexInitPayload);
       hashString(hash,serverKexInitPayload);
       hashString(hash,serverDhGexReply.host_key);
       hashString(hash,clientDhPubKey);
       hashString(hash,serverDhGexReply.f);
       hashString(hash,secret);
       sessionId = hash.digest();
       console.log("H="+sessionId.toString("hex"));
       /*
       Encryption keys MUST be computed as HASH, of a known value and K, as follows:
   o  Initial IV client to server: HASH(K || H || "A" || session_id)
      (Here K is encoded as mpint and "A" as byte and session_id as raw
      data.  "A" means the single character A, ASCII 65).
   o  Initial IV server to client: HASH(K || H || "B" || session_id)
   o  Encryption key client to server: HASH(K || H || "C" || session_id)
   o  Encryption key server to client: HASH(K || H || "D" || session_id)
   o  Integrity key client to server: HASH(K || H || "E" || session_id)
   o  Integrity key server to client: HASH(K || H || "F" || session_id)

       */
   {
    const newSecret = Buffer.allocUnsafe(4 + secret.length);
    writeUInt32BE(newSecret, secret.length, 0);
    newSecret.set(secret, 4);
    secret = newSecret;
  }
       ivCS = deriveKey(secret,sessionId,sessionId,"A","sha1");
       ivCS = ivCS.subarray(0,16);
       ivSC = deriveKey(secret,sessionId,sessionId,"B","sha1");
       ivSC = ivSC.subarray(0,16);
       keyCS = deriveKey(secret,sessionId,sessionId,"C","sha1");
       keyCS = keyCS.subarray(0,16);
       keySC = deriveKey(secret,sessionId,sessionId,"D","sha1");
       keySC = keySC.subarray(0,16);
      decipherCS = crypto.createDecipheriv("aes-128-ctr", keyCS, ivCS);
      decipherSC = crypto.createDecipheriv("aes-128-ctr", keySC, ivSC);
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

function deriveKey(K, H, sessionId, X, hashAlgo) {
  const hash = crypto.createHash(hashAlgo);
  hash.update(K);
  hash.update(H);
  hash.update(X);
  hash.update(sessionId);
  return hash.digest();
}


function writeUInt32BE(buf, value, offset) {
  buf[offset++] = (value >>> 24);
  buf[offset++] = (value >>> 16);
  buf[offset++] = (value >>> 8);
  buf[offset++] = value;
  return offset;
}

const hashString = (() => {
  const LEN = Buffer.allocUnsafe(4);
  return (hash, buf) => {
    writeUInt32BE(LEN, buf.length, 0);
    hash.update(LEN);
    hash.update(buf);
  };
})();