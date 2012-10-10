var zlib   = require('zlib'),
    crypto = require('crypto'),
    async  = require('async'),
    dgram  = require('dgram');

var graylog = function graylog(config) {

    var key;

    this.config     = config;

    this.servers    = config.servers;
    this.hostname   = config.hostname || require('os').hostname();
    this.facility   = config.facility || 'Node.js';

    this._callCount  = 0;

    this._bufferSize = config.bufferSize || this.DEFAULT_BUFFERSIZE;
    this._dataSize   = this._bufferSize - 12;
};

graylog.prototype.DEFAULT_BUFFERSIZE = 8192;

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
    return this.servers[this._callCount++ % this.servers.length];
};

graylog.prototype.emergency = function (short_message, full_message, additionalFields, timestamp) {
    return this._log(short_message, full_message, additionalFields, timestamp, this.level.EMERGENCY);
};

graylog.prototype.alert = function (short_message, full_message, additionalFields, timestamp) {
    return this._log(short_message, full_message, additionalFields, timestamp, this.level.ALERT);
};

graylog.prototype.critical = function (short_message, full_message, additionalFields, timestamp) {
    return this._log(short_message, full_message, additionalFields, timestamp, this.level.CRIT);
};

graylog.prototype.error = function (short_message, full_message, additionalFields, timestamp) {
    return this._log(short_message, full_message, additionalFields, timestamp, this.level.ERROR);
};

graylog.prototype.warning = function (short_message, full_message, additionalFields, timestamp) {
    return this._log(short_message, full_message, additionalFields, timestamp, this.level.WARNING);
};
graylog.prototype.warn = graylog.prototype.warning;

graylog.prototype.notice = function (short_message, full_message, additionalFields, timestamp) {
    return this._log(short_message, full_message, additionalFields, timestamp, this.level.NOTICE);
};

graylog.prototype.info = function (short_message, full_message, additionalFields, timestamp) {
    return this._log(short_message, full_message, additionalFields, timestamp, this.level.INFO);
};
graylog.prototype.log = graylog.prototype.info;

graylog.prototype.debug = function (short_message, full_message, additionalFields, timestamp) {
    return this._log(short_message, full_message, additionalFields, timestamp, this.level.DEBUG);
};

graylog.prototype._log = function log(short_message, full_message, additionalFields, timestamp, level) {

    var payload,
        fileinfo,
        that    = this,
        field   = '',
        message = {
            version    : '1.0',
            timestamp  : (timestamp || new Date()).getTime() / 1000,
            host       : this.hostname,
            facility   : this.facility,
            level      : level
        };

    if (typeof(short_message) !== 'object') {
        // We normally set the data
        message.short_message   = short_message;
        message.full_message    = full_message || short_message;
    }
    else if (short_message.stack && short_message.message) {

        // Short message is an Error message, we process accordingly
        message.short_message = short_message.message;
        message.full_message  = short_message.stack;

        // extract error file and line
        fileinfo = message.stack.split('\n')[0];
        fileinfo = fileinfo.substr(fileinfo.indexOf('('), fileinfo.indeOf(')'));
        fileinfo = fileinfo.split(':');

        message.file = fileinfo[0];
        message.line = fileinfo[1];

        additionalFields = full_message || additionalFields;
    }
    else {
        message.full_message = message.short_message   = JSON.stringify(short_message);
    }

    // We insert additional fields
    for (field in additionalFields) {
        message['_' + field] = additionalFields[field];
    }

    // https://github.com/Graylog2/graylog2-docs/wiki/GELF
    if (message._id) {
        message.__id = message._id;
        delete message._id;
    }

    // Compression
    payload = new Buffer(JSON.stringify(message));

    zlib.deflate(payload, function (err, buffer) {
        if (err) {
            return;
        }

        var chunkCount = Math.ceil(buffer.length / that._bufferSize),
            server     = that.getServer(),
            client     = dgram.createSocket("udp4");

        if (chunkCount > 128) {
            return console.error('Cannot send messages bigger than 1022.5K, not sending');
        }

        // If it all fits, just send it
        if (chunkCount === 1) {
            return that.send(buffer, client, server, function () {
                client.close();
            });
        }

        // Generate a random id in buffer format
        crypto.randomBytes(8, function (err, id) {

            // To be tested: whats faster, sending as we go or prebuffering?
            var chunk    = new Buffer(that._bufferSize),
                start    = 0,
                stop     = 0,
                chunkSequenceNumber = 0;

            // Set up magic number (0 and 1) and chunk total count (11)
            chunk[0] = 30;
            chunk[1] = 15;
            chunk[11] = chunkCount;

            // set message id (2,9)
            id.copy(chunk, 2, 0, 8);

            async.whilst(
                function () { return chunkSequenceNumber < chunkCount; },
                function (cb) {
                    // Set chunk sequence number
                    chunk[10] = chunkSequenceNumber;

                    // Select data from full buffer
                    start = chunkSequenceNumber * that._dataSize;
                    stop  = Math.min((chunkSequenceNumber + 1) * that._dataSize, buffer.length);
                    buffer.copy(chunk, 12, start, stop);

                    chunkSequenceNumber++;

                    // Send a chunk of 8192 bytes or less
                    that.send(chunk.slice(0, stop - start + 12), client, server, cb);
                },
                function () { client.close(); }
            );
        });
    });
};

graylog.prototype.send = function (chunk, client, server, cb) {
    client.send(chunk, 0, chunk.length, server.port, server.host, function (err, byteCount) {
        if (err) {
            console.log(err);
        }

        cb();
    });
};

exports.graylog = graylog;
