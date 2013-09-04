var zlib   = require('zlib'),
    crypto = require('crypto'),
    dgram  = require('dgram');

var graylog = function graylog(config) {
    this.config       = config;

    this.servers      = config.servers;
    this.client       = null;
    this.hostname     = config.hostname || require('os').hostname();
    this.facility     = config.facility || 'Node.js';

    this._callCount   = 0;
    this._isDestroyed = false;

    this._bufferSize  = config.bufferSize || this.DEFAULT_BUFFERSIZE;
};

graylog.prototype.DEFAULT_BUFFERSIZE = 1400;  // a bit less than a typical MTU of 1500 to be on the safe side

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

graylog.prototype.getClient = function () {
    if (!this.client && !this._isDestroyed) {
        this.client = dgram.createSocket("udp4");
    }

    return this.client;
};

graylog.prototype.destroy = function () {
    if (this.client) {
        this.client.close();
		this.client = null;
		this._isDestroyed = true;
    }
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
        message.full_message = message.short_message = JSON.stringify(short_message);
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
            console.error('Error deflating message:', err);
            return;
        }

        // If it all fits, just send it
        if (buffer.length <= that._bufferSize) {
            return that.send(buffer, that.getServer());
        }

        // It didn't fit, so prepare for a chunked stream

        var bufferSize = that._bufferSize,
            dataSize   = bufferSize - 12,  // the data part of the buffer is the buffer size - header size
            chunkCount = Math.ceil(buffer.length / dataSize);

        if (chunkCount > 128) {
            return console.error('Cannot send messages bigger than', dataSize * 128, 'bytes, not sending');
        }

        // Generate a random id in buffer format
        crypto.randomBytes(8, function (err, id) {
            if (err) {
                return console.error('Error creating message ID:', err);
            }

            // To be tested: what's faster, sending as we go or prebuffering?
            var server = that.getServer(),
                chunk = new Buffer(bufferSize),
                chunkSequenceNumber = 0;

            // Prepare the header

            // Set up magic number (bytes 0 and 1)
            chunk[0] = 30;
            chunk[1] = 15;

            // Set the total number of chunks (byte 11)
            chunk[11] = chunkCount;

            // Set message id (bytes 2-9)
            id.copy(chunk, 2, 0, 8);

            function send(err) {
                if (err || chunkSequenceNumber >= chunkCount) {
                    // We have reached the end, or had an error
                    return;
                }

                // Set chunk sequence number (byte 10)
                chunk[10] = chunkSequenceNumber;

                // Copy data from full buffer into the chunk
                var start = chunkSequenceNumber * dataSize;
                var stop  = Math.min((chunkSequenceNumber + 1) * dataSize, buffer.length);

                buffer.copy(chunk, 12, start, stop);

                chunkSequenceNumber++;

                // Send the chunk
                that.send(chunk.slice(0, stop - start + 12), server, send);
            }

            send();
        });
    });
};

graylog.prototype.send = function (chunk, server, cb) {
    var client = this.getClient();

    if (!client) {
        if (cb) {
            cb('Socket was destroyed');
        }
        return;
    }

    client.send(chunk, 0, chunk.length, server.port, server.host, function (err/*, bytes */) {
        if (err) {
            console.error('Error sending buffer:', err);
        }

        if (cb) {
            cb(err);
        }
    });
};

exports.graylog = graylog;
