const { Client } = require('ssh2');

const algorithms = {
	kex: [
	  //'ecdh-sha2-nistp256',
	  //'ecdh-sha2-nistp384',
	  //'ecdh-sha2-nistp521',
	  //'diffie-hellman-group-exchange-sha256',
	  //'diffie-hellman-group14-sha1',
	  //'diffie-hellman-group-exchange-sha1',
	  //'diffie-hellman-group16-sha512',
	  'diffie-hellman-group1-sha1',
	],
	cipher: [
	  'aes128-ctr',
	  //'aes192-ctr',
	  //'aes256-ctr',
	  //'aes128-gcm',
	  //'aes128-gcm@openssh.com',
	  //'aes256-gcm',
	  //'aes256-gcm@openssh.com',
	  //'aes256-cbc',
	  //'aes192-cbc',
	  //'aes128-cbc',
	  //'blowfish-cbc',
	  //'3des-cbc',
	  //'arcfour256',
	  //'arcfour128',
	  //'cast128-cbc',
	  //'arcfour',
	],
	hmac: [
	  'hmac-sha2-256',
	  //'hmac-sha2-512',
	  //'hmac-sha1',
	  //'hmac-md5',
	  //'hmac-sha2-256-96',
	  //'hmac-sha2-512-96',
	  //'hmac-ripemd160',
	  //'hmac-sha1-96',
	  //'hmac-md5-96',
	],
	//compress: ['none', 'zlib@openssh.com', 'zlib'],
	//serverHostKey: ['ssh-dss', 'ssh-rsa', 'rsa-sha2-256', 'rsa-sha2-512', 'ecdsa-sha2-nistp521', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp256', 'ssh-ed25519'],
  };

const options = {};
options.algorithms = algorithms;

const conn = new Client(options);
conn.on('ready', () => {
	conn.exec('cd /tmp\nls -lah\ndf -h\ndu -sh\nexit\n', { pty: false }, (err, stream) => {
		if (err) throw err;
		stream.on('close', (code, signal) => {
			console.log('Stream :: close :: code: ' + code + ', signal: ' + signal);
			conn.end();
		});
		stream.on('data', (data) => {
			console.log('STDOUT: ' + data);
		});
		stream.stderr.on('data', function err(data) {
			console.log('STDERR: ' + data);
		});
	})})
	.connect({
		host: process.env.TARGET_HOST,
		port: 22,
		username: process.env.TARGET_USERNAME,
		password: process.env.TARGET_PASSWORD,
		algorithms: algorithms,
		debug: function(msg) {
			console.log(msg);
		},
});
