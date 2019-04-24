// Copyright (c) 2012-2014 Heapsource.com and Contributors - http://www.heapsource.com
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
var winston = require('winston');
var util = require('util');
var chalk = require('chalk');

//Allow this file to get an exclusive copy of underscore so it can change the template settings without affecting others
delete require.cache[require.resolve('lodash')];
var _ = require('lodash');
delete require.cache[require.resolve('lodash')];

/**
 * A default list of properties in the request object that are allowed to be logged.
 * These properties will be safely included in the meta of the log.
 * 'body' is not included in this list because it can contains passwords and stuff that are sensitive for logging.
 * TODO: Include 'body' and get the defaultRequestFilter to filter the inner properties like 'password' or 'password_confirmation', etc. Pull requests anyone?
 * @type {Array}
 */
var requestWhitelist = ['url', 'headers', 'method', 'httpVersion', 'originalUrl', 'query'];

/**
 * A default list of properties in the request body that are allowed to be logged.
 * This will normally be empty here, since it should be done at the route level.
 * @type {Array}
 */
var bodyWhitelist = [];

/**
 * A default list of properties in the request body that are not allowed to be logged.
 * @type {Array}
 */
var bodyBlacklist = [];

/**
 * A default list of properties in the response object that are allowed to be logged.
 * These properties will be safely included in the meta of the log.
 * @type {Array}
 */
var responseWhitelist = ['statusCode'];

/**
 * A list of request routes that will be skipped instead of being logged. This would be useful if routes for health checks or pings would otherwise pollute
 * your log files.
 * @type {Array}
 */
var ignoredRoutes = [];

/**
 * A default function to filter the properties of the req object.
 * @param req
 * @param propName
 * @return {*}
 */
var defaultRequestFilter = function (req, propName) {
    return _.result(req, propName);
};

/**
 * A default function to filter the properties of the res object.
 * @param res
 * @param propName
 * @return {*}
 */
var defaultResponseFilter = function (res, propName) {
    return _.result(res, propName);
};

/**
 * A default function to decide whether skip logging of particular request. Doesn't skip anything (i.e. log all requests).
 * @return always false
 */
var defaultSkip = function() {
  return false;
};

/**
 * accressToken Request 
 */
var accressTokenReq = '';
function filterObject(originalObj, whiteList, initialFilter) {
    var obj = {};
    var fieldsSet = false;

    [].concat(whiteList).forEach(function (propName) {
        var value = initialFilter(originalObj, propName);

        if(typeof (value) !== 'undefined') {
            _.set(obj, propName, value);
            fieldsSet = true;
        };
    });

    return fieldsSet ? obj : undefined;
}

//
// ### function errorLogger(options)
// #### @options {Object} options to initialize the middleware.
//


function errorLogger(options) {

    ensureValidOptions(options);

    options.requestFilter = options.requestFilter || defaultRequestFilter;
    options.responseFilter = options.responseFilter || defaultResponseFilter;
    options.winstonInstance = options.winstonInstance || (new winston.Logger ({ transports: options.transports }));

    return function (err, req, res, next) {

        // Let winston gather all the error data.
        var exceptionMeta = winston.exception.getAllInfo(err);
        exceptionMeta.req = filterObject(req, requestWhitelist, options.requestFilter);
        var end = res.end;
        res.end = function(chunk, encoding) {
            res.end = end;
            res.end(chunk, encoding);

            exceptionMeta.res = filterObject(res, responseWhitelist, options.responseFilter);
            // This is fire and forget, we don't want logging to hold up the request so don't wait for the callback
            options.winstonInstance.log('error', 'middlewareError', exceptionMeta);
        }

        next(err);
    };
}

//
// ### function logger(options)
// #### @options {Object} options to initialize the middleware.
//


function logger(options) {

    ensureValidOptions(options);
    ensureValidLoggerOptions(options);

    options.requestFilter = options.requestFilter || defaultRequestFilter;
    options.responseFilter = options.responseFilter || defaultResponseFilter;
    options.winstonInstance = options.winstonInstance || (new winston.Logger ({ transports: options.transports }));
    options.level = options.level || "info";
    options.statusLevels = options.statusLevels || false;
    options.msg = options.msg || "HTTP {{req.method}} {{req.url}}";
    options.colorStatus = options.colorStatus || false;
    options.expressFormat = options.expressFormat || false;
    options.ignoreRoute = options.ignoreRoute || function () { return false; };
    options.skip = options.skip || defaultSkip;
    // new options
    options.customLogger = options.customLogger || null;
    options.filterOutList = options.filterOutList || []; // example: ['dropdown', 'loggedin', 'query-table', 'query-last-package-number', '.png', '.woff', '.ttf', 'jquery.nanoscroller', 'favicon.ico'];
    options.noExportData = options.noExportData;
    options.noHeader = options.noHeader;
    options.noBody = options.noBody || false;
 
    var _logger;
    if (options.customLogger !== null) {
        _logger = options.customLogger;
    } else {
        _logger = options.winstonInstance;
    }

    // Using mustache style templating
    var template = _.template(options.msg, null, {
      interpolate: /\{\{(.+?)\}\}/g
    });

    return function (req, res, next) {
        var currentUrl = req.originalUrl || req.url;
        if (currentUrl && _.contains(ignoredRoutes, currentUrl)) return next();

        req._startTime = (new Date);

        req._routeWhitelists = {
            req: [],
            res: [],
            body: []
        };

        req._routeBlacklists = {
            body: []
        };

        // try to log request first
        if (options.expressFormat) {
            var msg = chalk.grey(req.method + " " + req.url || req.url)
                + " " + chalk[statusColor](res.statusCode)
                + " " + chalk.grey(res.responseTime + "ms");
        } else {
            var msg = template({ req: req, res: res });
        }
        if (!options.skip(req, res) && !options.ignoreRoute(req, res) && req.method !== 'OPTIONS') {

            // filter out messages from array
            var canWriteLogReq = true;
            var arr = options.filterOutList;
            for(var i = 0; i != arr.length; i++) {
                var arrItem = arr[i];
                if(msg.includes(arrItem)) {
                    canWriteLog = false; // log will not write if found an item in filter out array
                }
            }
            
            if (canWriteLogReq) {
                //var reqMsg = msg + "Request from FE - header: " + JSON.stringify(req.headers) + " body: " + JSON.stringify(req.body);
                var reqMsg = msg + "";
                
                if (!options.noHeader) {
                    reqMsg += " |ACCESSTOKEN=" + JSON.stringify(req.headers.authorization);
					accressTokenReq = req.headers.authorization
                }

                if (!options.noBody) {
                    reqMsg += " |BODY=" + JSON.stringify(req.body);
                }

                _logger.info(reqMsg);
                // options.winstonInstance.log(options.level, reqMsg);
            }

        }


        // Manage to get information from the response too, just like Connect.logger does:
        var end = res.end;
        res.end = function(chunk, encoding) {
            res.responseTime = (new Date) - req._startTime;

            res.end = end;
            res.end(chunk, encoding);

            req.url = req.originalUrl || req.url;

            if (options.statusLevels) {
              if (res.statusCode >= 100) { options.level = "info"; }
              if (res.statusCode >= 400) { options.level = "warn"; }
              if (res.statusCode >= 500) { options.level = "error"; }
            };

            if (options.colorStatus || options.expressFormat) {
              // Palette from https://github.com/expressjs/morgan/blob/master/index.js#L205
              var statusColor = 'green';
              if (res.statusCode >= 500) statusColor = 'red';
              else if (res.statusCode >= 400) statusColor = 'yellow';
              else if (res.statusCode >= 300) statusColor = 'cyan';
              var coloredStatusCode = chalk[statusColor](res.statusCode);
            }

            var meta = {};

            if(options.meta !== false) {
              var bodyWhitelist, blacklist;

              requestWhitelist = requestWhitelist.concat(req._routeWhitelists.req || []);
              responseWhitelist = responseWhitelist.concat(req._routeWhitelists.res || []);

              meta.req = filterObject(req, requestWhitelist, options.requestFilter);
              meta.res = filterObject(res, responseWhitelist, options.responseFilter);

              if (_.contains(responseWhitelist, 'body')) {
                if (chunk) {
                  var isJson = (res._headers && res._headers['content-type']
                    && res._headers['content-type'].indexOf('json') >= 0);

                  meta.res.body =  isJson ? JSON.parse(chunk) : chunk.toString();
                  res.body = meta.res.body;
                }
              }

              bodyWhitelist = req._routeWhitelists.body || [];
              blacklist = _.union(bodyBlacklist, (req._routeBlacklists.body || []));

              var filteredBody = null;

              if ( req.body !== undefined ) {
                  if (blacklist.length > 0 && bodyWhitelist.length === 0) {
                    var whitelist = _.difference(_.keys(req.body), blacklist);
                    filteredBody = filterObject(req.body, whitelist, options.requestFilter);
                  } else {
                    filteredBody = filterObject(req.body, bodyWhitelist, options.requestFilter);
                  }
              }

              if (filteredBody) meta.req.body = filteredBody;

              meta.responseTime = res.responseTime;
            }

            // This is fire and forget, we don't want logging to hold up the request so don't wait for the callback
            if (!options.skip(req, res) && !options.ignoreRoute(req, res) && req.method !== 'OPTIONS') {
                if(options.noExportData && msg.includes('/export')) {
                    delete res.body['resultData'];
                }

                var canWriteLogRes = true;
                for (var i = 0; i != arr.length; i++) {
                    var arrItem = arr[i];
                    if (msg.includes(arrItem)) {
                        canWriteLogRes = false; // log will not write if found an item in filter out array
                    }
                }

                if (canWriteLogRes) {
                    //var resMsg = msg + "Response to FE - header: " + JSON.stringify(res.header()._headers) + " body: " + JSON.stringify(res.body) + ", statusCode: " + res.statusCode + ", responseTime: " + res.responseTime + "ms";
                    var resMsg = msg + "";

                    if (!options.noHeader) {
                        resMsg += " |ACCESSTOKEN=" + accressTokenReq;
                    }

                    if (!options.noBody) {
                        resMsg += " |BODY=" + JSON.stringify(res.body);
                    }
					
					var des = '';
					if(res && (res.statusCode === 200 || res.statusCode === '200')){
						des = 'OK';
					}else if(res && (res.statusCode === 201 || res.statusCode === '201')){
						des = 'Created';
					}else if(res && (res.statusCode === 202 || res.statusCode === '202')){
						des = 'Accepted';
					}else if(res && (res.statusCode === 203 || res.statusCode === '203')){
						des = 'Non-Authoritative Information';
					}else if(res && (res.statusCode === 204 || res.statusCode === '204')){
						des = 'No Content';
					}else if(res && (res.statusCode === 205 || res.statusCode === '205')){
						des = 'Reset Content';
					}else if(res && (res.statusCode === 206 || res.statusCode === '206')){
						des = 'Partial Content';
					}else if(res && (res.statusCode === 207 || res.statusCode === '207')){
						des = 'Multi-Status';
					}else if(res && (res.statusCode === 208 || res.statusCode === '208')){
						des = 'Already Reported';
					}else if(res && (res.statusCode === 304 || res.statusCode === '304')){
						des = 'Not Modified';
					}else if(res && (res.statusCode === 305 || res.statusCode === '305')){
						des = 'Use Proxy';
					}else if(res && (res.statusCode === 306 || res.statusCode === '306')){
						des = 'Switch Proxy';
					}else if(res && (res.statusCode === 307 || res.statusCode === '307')){
						des = 'Temporary Redirect';
					}else if(res && (res.statusCode === 308 || res.statusCode === '308')){
						des = 'Permanent Redirect';
					}else if(res && (res.statusCode === 400 || res.statusCode === '400')){
						des = 'Bad Request';
					}else if(res && (res.statusCode === 401 || res.statusCode === '401')){
						des = 'Unauthorized';
					}else if(res && (res.statusCode === 402 || res.statusCode === '402')){
						des = 'Payment Required';
					}else if(res && (res.statusCode === 403 || res.statusCode === '403')){
						des = 'Forbidden';
					}else if(res && (res.statusCode === 404 || res.statusCode === '404')){
						des = 'Not Found';
					}else if(res && (res.statusCode === 405 || res.statusCode === '405')){
						des = 'Method Not Allowed';
					}else if(res && (res.statusCode === 406 || res.statusCode === '406')){
						des = 'Not Acceptable';
					}else if(res && (res.statusCode === 407 || res.statusCode === '407')){
						des = 'Proxy Authentication Required';
					}else if(res && (res.statusCode === 408 || res.statusCode === '408')){
						des = 'Request Timeout';
					}else if(res && (res.statusCode === 500 || res.statusCode === '500')){
						des = 'Internal Server Error';
					}else if(res && (res.statusCode === 501 || res.statusCode === '501')){
						des = 'Not Implemented';
					}else if(res && (res.statusCode === 502 || res.statusCode === '502')){
						des = 'Bad Gateway';
					}else if(res && (res.statusCode === 503 || res.statusCode === '503')){
						des = 'Service Unavailable';
					}else if(res && (res.statusCode === 504 || res.statusCode === '504')){
						des = 'Gateway Timeout';
					}else if(res && (res.statusCode === 505 || res.statusCode === '505')){
						des = 'HTTP Version Not Supported';
					}else if(res && (res.statusCode === 506 || res.statusCode === '506')){
						des = 'Variant Also Negotiates';
					}else if(res && (res.statusCode === 507 || res.statusCode === '507')){
						des = 'Insufficient Storage';
					}else if(res && (res.statusCode === 508 || res.statusCode === '508')){
						des = 'Loop Detected';
					}else if(res && (res.statusCode === 510 || res.statusCode === '510')){
						des = 'Not Extended';
					}else if(res && (res.statusCode === 511 || res.statusCode === '511')){
						des = 'Network Authentication Required';
					}else if(res && (res.statusCode === 544 || res.statusCode === '544')){
						des = 'Network Authentication Required';
					}else if(res && (res.statusCode === 444 || res.statusCode === '444')){
						des = 'No Response';
					}else if(res && (res.statusCode === 494 || res.statusCode === '494')){
						des = 'Request header too large';
					}else if(res && (res.statusCode === 495 || res.statusCode === '495')){
						des = 'SSL Certificate Error';
					}else if(res && (res.statusCode === 496 || res.statusCode === '496')){
						des = 'SSL Certificate Required';
					}else if(res && (res.statusCode === 497 || res.statusCode === '497')){
						des = 'HTTP Request Sent to HTTPS Port';
					}else if(res && (res.statusCode === 499 || res.statusCode === '499')){
						des = 'Client Closed Request';
					}else if(res && (res.statusCode === 520 || res.statusCode === '520')){
						des = 'Unknown Error';
					}else if(res && (res.statusCode === 521 || res.statusCode === '521')){
						des = 'Web Server Is Down';
					}else if(res && (res.statusCode === 522 || res.statusCode === '522')){
						des = 'Connection Timed Out';
					}else if(res && (res.statusCode === 523 || res.statusCode === '523')){
						des = 'Origin Is Unreachable';
					}else if(res && (res.statusCode === 524 || res.statusCode === '524')){
						des = 'A Timeout Occurred';
					}else if(res && (res.statusCode === 525 || res.statusCode === '525')){
						des = 'SSL Handshake Failed';
					}else if(res && (res.statusCode === 526 || res.statusCode === '526')){
						des = 'Invalid SSL Certificate';
					}else if(res && (res.statusCode === 527 || res.statusCode === '527')){
						des = 'Railgun Error';
					}else if(res && (res.statusCode === 530 || res.statusCode === '530')){
						des = 'Origin DNS Error';
					}

                    resMsg += " |STATUS=" + res.statusCode + " |DESC=" + des + " |RESPONSETIME:" + res.responseTime + "ms";

                    _logger.info(resMsg);
                // options.winstonInstance.log(options.level, msg, meta);
                }

            }
        };

        next();
    };
}

function ensureValidOptions(options) {
    if(!options) throw new Error("options are required by express-winston middleware");
    if(!((options.transports && (options.transports.length > 0)) || options.winstonInstance))
        throw new Error("transports or a winstonInstance are required by express-winston middleware");
}

function ensureValidLoggerOptions(options) {
    if (options.ignoreRoute && !_.isFunction(options.ignoreRoute)) {
        throw new Error("`ignoreRoute` express-winston option should be a function");
    }
}

module.exports.errorLogger = errorLogger;
module.exports.logger = logger;
module.exports.requestWhitelist = requestWhitelist;
module.exports.bodyWhitelist = bodyWhitelist;
module.exports.bodyBlacklist = bodyBlacklist;
module.exports.responseWhitelist = responseWhitelist;
module.exports.defaultRequestFilter = defaultRequestFilter;
module.exports.defaultResponseFilter = defaultResponseFilter;
module.exports.defaultSkip = defaultSkip;
module.exports.ignoredRoutes = ignoredRoutes;

