const crypto = require('crypto');

const prime = Buffer.from([179]);
const generator = Buffer.from([2]);

console.log('prime=' + prime.toString('hex'));
console.log('generator=' + generator.toString('hex'));

const clientDH = crypto.createDiffieHellman(prime, generator);
clientDH.generateKeys();
const clientPub = clientDH.getPublicKey();
console.log('client getPublicKey=' + clientPub.toString('hex'));
const clientPrv = clientDH.getPrivateKey();
console.log('client getPrivateKey=' + clientPrv.toString('hex'));

const serverDH = crypto.createDiffieHellman(prime, generator);
serverDH.generateKeys();
const serverPub = serverDH.getPublicKey();
console.log('server getPublicKey=' + serverPub.toString('hex'));
const serverPrv = serverDH.getPrivateKey();
console.log('server getPrivateKey=' + serverPrv.toString('hex'));

const serverSecret = serverDH.computeSecret(clientPub);
console.log('server Shared Secret=' + serverSecret.toString('hex'));
const clientSecret = clientDH.computeSecret(serverPub);
console.log('client Shared Secret=' + clientSecret.toString('hex'));
