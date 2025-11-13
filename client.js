const { Client } = require('ssh2');

const algorithms = {
	//kex: [
	//  'diffie-hellman-group16-sha512',
	//],
	cipher: [
	  'aes128-ctr',
	],
	//hmac: [
	//  'hmac-sha2-256',
	//],
  };

const options = {};
options.algorithms = algorithms;

const args = process.argv.slice(2);
if (args.length < 2) {
  console.log('Usage: node ssh-client.js <username>@<host> [password]');
  process.exit(1);
}

const [userHost, ...rest] = args;
const [username, host] = userHost.split('@');
const port = 22;

const conn = new Client(options);

let password = rest[0];

const config = {
  host,
  port,
  username,
  algorithms: algorithms,
  //debug: function(msg) {
  //	console.log(msg);
  //},
  readyTimeout: 20000
};

if (password) {
  config.password = password;
} 

conn.on('ready', () => {
  conn.shell({
    term: process.env.TERM || 'xterm',
    cols: process.stdout.columns,
    rows: process.stdout.rows
  }, (err, stream) => {
    if (err) {
      console.error('Failed to start shell:', err.message);
      process.exit(1);
    }

    if (process.stdin.isTTY) {
      process.stdin.setRawMode(true);
      process.stdin.resume();
    }

    process.stdin.pipe(stream);
    stream.pipe(process.stdout);
    stream.stderr.pipe(process.stderr);

    process.stdout.on('resize', () => {
      stream.setWindow(process.stdout.rows, process.stdout.columns);
    });

    stream.on('close', () => {
      if (process.stdin.isTTY) {
        process.stdin.setRawMode(false);
      }
      conn.end();
      process.exit(0);
    });
  });
}).on('error', (err) => {
  console.error('SSH Connection error:', err.message);
  process.exit(1);
}).connect(config);
