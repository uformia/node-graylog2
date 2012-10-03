var zlib   = require('zlib'),
    crypto = require('crypto'),
    dgram  = require('dgram');

var graylog = function graylog(config) {

    var key;

    this.config     = config;

    this.client     = dgram.createSocket("udp4");
    this.servers    = config.servers;
    this.hostname   = config.hostname || require('os').hostname();
    this.toConsole  = false;
    this.facility   = config.facility || 'Node.js';
    this.sequence   = 0;
};

graylog.prototype.level = {
    EMERG: 0,    // system is unusable
    ALERT: 1,    // action must be taken immediately
    CRIT: 2,     // critical conditions
    ERR: 3,      // error conditions
    ERROR: 3,    // because people WILL typo
    WARNING: 4,  // warning conditions
    NOTICE: 5,   // normal, but significant, condition
    INFO: 6,     // informational message
    DEBUG: 7     // debug level message
};

graylog.prototype.getServer = function () {
    return this.servers[this.sequence % this.servers.length];
};

graylog.prototype.emergency = function (msg) {
    msg.level = this.level.EMERG;
    return this._log(msg);
};

graylog.prototype.alert = function (msg) {
    msg.level = this.level.ALERT;
    return this._log(msg);
};

graylog.prototype.critical = function (msg) {
    msg.level = this.level.CRIT;
    return this._log(msg);
};

graylog.prototype.error = function (msg) {
    msg.level = this.level.ERROR;
    return this._log(msg);
};

graylog.prototype.warning = function (msg) {
    msg.level = this.level.WARNING;
    return this._log(msg);
};
graylog.prototype.warn = graylog.prototype.warning;

graylog.prototype.notice = function (msg) {
    msg.level = this.level.NOTICE;
    return this._log(msg);
};
graylog.prototype.log = graylog.prototype.notice;

graylog.prototype.info = function (msg) {
    msg.level = this.level.INFO;
    return this._log(msg);
};

graylog.prototype.debug = function (msg) {
    msg.level = this.level.DEBUG;
    return this._log(msg);
};

graylog.prototype._log = function log(msg) {

    msg.version    = '1.0';
    msg.timestamp  = new Date().getTime()/1000 >> 0;
    msg.host       = this.hostname;
    msg.facility   = this.facility;

    msg['_logSequence'] = this.sequence++;

    if(msg.stack && msg.message) {
        msg.short_message = msg.message;
        msg.full_message  = msg.stack;

        // parse the error stack
        fileinfo = msg.stack.split('\n')[0];
        fileinfo = fileinfo.substr(fileinfo.indexOf('('), fileinfo.indeOf(')'));
        fileinfo = fileinfo.split(':');

        msg.file = fileinfo[0];
        msg.line = fileinfo[1];
    }

    var message = new Buffer(JSON.stringify(msg));

    zlib.deflate(message, function (err, buffer) {
        if (err) {
            return;
        }

        var chunkCount = Math.ceil(buffer.length / 8192);

        // If it all fits, just send it
        if (chunkCount === 1) {
            this.send(buffer);
        }

        // Generate a random id in buffer format
        crypto.randomBytes(8, function(err, id) {

            var chunk = new Buffer(8204),
                start = 0,
                stop  = 0;

            // Set up magic number (0 and 1) and chunk total count (11)
            chunk[0] = 15;
            chunk[1] = 16;
            chunk[11] = chunkCount;

            // set message id (2,9)
            id.copy(chunk, 2, 0, 8);

            for(var i = 0; i < chunkCount; chunkCount++) {

                // Set chunk sequence number
                chunk[10] = i;

                // Select data from full buffer
                start = i * 8192;
                stop  =  Math.min((i+1) * 8192, buffer.length);
                buffer.copy(chunk, 12, start, stop);

                // Send a chunk of 8192 bytes or less
                this.send(chunk.slice(0, stop-start));
            }
        });
    });
}

graylog.prototype.send = function(chunk) {
    var server = this.getServer();
    this.client.send(chunk, 0, chunk.length, server.port, server.host, function (err, byteCount) {
        if (err) {
            console.log(err);
        }
    });
};

exports.graylog = graylog;
