var bunyan = require('bunyan');

var log = bunyan.createLogger({
    name: 'oms-token-master',
    streams: [{
        type: 'rotating-file',
        level: 'info',
        path: './../log/oms-token-master.log',
        period: '1d',
        count: 7
    }],
    serializers: {
        err: bunyan.stdSerializers.err,
        req: bunyan.stdSerializers.req,
        res: bunyan.stdSerializers.res
    },
    src: true
});

module.exports = log;
