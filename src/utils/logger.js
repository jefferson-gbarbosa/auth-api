const winston = require('winston');
require('winston-daily-rotate-file');
const { combine, timestamp, json } = winston.format;

const fileRotateTransport = new winston.transports.DailyRotateFile({
    filename: 'combined-%DATE%.log',
    datePattern: 'YYYY-MM-DD',
    maxFiles: '14d',
});

const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || 'info',
    format: combine(timestamp({format: 'YYYY-MM-DD hh:mm:ss.SSS A'}), json()),
    transports: [fileRotateTransport],
});

module.exports = logger;