# NEW Options

```
// app.js

// setup log4js
var log4js = require('log4js');
log4js.configure('./app/config/log4js_config.json');
var log4jsLogger = log4js.getLogger('bluefin-ltc');

app.use(expressWinston.logger({
    transports: [fileTransport],
    meta: true, // optional: control whether you want to log the meta data about the request (default to true)
    msg: "phoenix-partner - :: ## {{req.session.userName}} - {{req.session.id}} - {{req.id}} ## HTTP {{req.method}} {{req.url}} ", //request-body:{{JSON.stringify(req.body)}}", // -- response-body:{{JSON.stringify(res.body)}}", // optional: customize the default logging message. E.g. "{{res.statusCode}} {{req.method}} {{res.responseTime}}ms {{req.url}}"
    expressFormat: false, // Use the default Express/morgan request formatting, with the same colors. Enabling this will override any msg and colorStatus if true. Will only output colors on transports with colorize set to true
    colorStatus: true, // Color the status code, using the Express/morgan color palette (default green, 3XX cyan, 4XX yellow, 5XX red). Will not be recognized if expressFormat is true
    ignoreRoute: function (req, res) {
        return false;
    }, // optional: allows to skip some log messages based on request and/or response
    // NEW OPTIONS
    customLogger: log4jsLogger, // use log4jsLogger in expressWinston
    filterOutList: ['dropdown', 'loggedin', 'query-table', 'query-last-package-number', '.png', '.woff', '.ttf', 'jquery.nanoscroller', 'favicon.ico'], // not log any messages that have one of these words
    noExportData: true, // remove resultData in case message has '/export'
    noHeader: true, // not log headers if true
    noBody: false // not log body if true
}));
```


# winston-express-middleware
[![Build Status](https://secure.travis-ci.org/hharnisc/winston-express-middleware.png)](http://travis-ci.org/hharnisc/winston-express-middleware)

> [winston](https://github.com/flatiron/winston) middleware for express.js

*Note: This is a fork of [express-winston](https://github.com/bithavoc/express-winston) with updates to the whitelisting system, using the latest winston, and bugfixes*

## Installation

    npm install winston-express-middleware

## Usage

winston-express-middleware provides middleware for request and error logging of your express.js application.  It uses 'whitelists' to select properties from the request and response objects.

To make use of winston-express-middleware, you need to add the following to your application:

In `package.json`:

```
{
  "dependencies": {
    "...": "...",
    "winston": "1.0.x",
    "winston-express-middleware": "0.1.x",
    "...": "..."
  }
}
```

In `server.js` (or wherever you need it):

```
var winston = require('winston'),
    expressWinston = require('winston-express-middleware');
```

### Error Logging

Use `expressWinston.errorLogger(options)` to create a middleware that log the errors of the pipeline.

``` js
    var router = require('./my-express-router');

    app.use(router); // notice how the router goes first.
    app.use(expressWinston.errorLogger({
      transports: [
        new winston.transports.Console({
          json: true,
          colorize: true
        })
      ]
    }));
```

The logger needs to be added AFTER the express router(`app.router)`) and BEFORE any of your custom error handlers(`express.handler`). Since winston-express-middleware will just log the errors and not __handle__ them, you can still use your custom error handler like `express.handler`, just be sure to put the logger before any of your handlers.

### Options

``` js
    transports: [<WinstonTransport>], // list of all winston transports instances to use.
    winstonInstance: <WinstonLogger>, // a winston logger instance. If this is provided the transports option is ignored
    level: String, // log level to use, the default is "info".
    statusLevels: Boolean // different HTTP status codes caused log messages to be logged at different levels (info/warn/error), the default is false
    skip: function(req, res) // function to determine if logging is skipped, defaults to false
```

To use winston's existing transports, set `transports` to the values (as in key-value) of the `winston.default.transports` object. This may be done, for example, by using underscorejs: `transports: _.values(winston.default.transports)`.

Alternatively, if you're using a winston logger instance elsewhere and have already set up levels and transports, pass the instance into expressWinston with the `winstonInstance` option. The `transports` option is then ignored.

### Request Logging

Use `expressWinston.logger(options)` to create a middleware to log your HTTP requests.

``` js
    var router = require('./my-express-router');

    app.use(expressWinston.logger({
      transports: [
        new winston.transports.Console({
          json: true,
          colorize: true
        })
      ],
      meta: true, // optional: control whether you want to log the meta data about the request (default to true)
      msg: "HTTP {{req.method}} {{req.url}}", // optional: customize the default logging message. E.g. "{{res.statusCode}} {{req.method}} {{res.responseTime}}ms {{req.url}}"
      expressFormat: true, // Use the default Express/morgan request formatting, with the same colors. Enabling this will override any msg and colorStatus if true. Will only output colors on transports with colorize set to true
      colorStatus: true, // Color the status code, using the Express/morgan color palette (default green, 3XX cyan, 4XX yellow, 5XX red). Will not be recognized if expressFormat is true
      ignoreRoute: function (req, res) { return false; } // optional: allows to skip some log messages based on request and/or response
    }));

    app.use(router); // notice how the router goes after the logger.
```

## Examples

``` js
    var express = require('express');
    var expressWinston = require('winston-express-middleware');
    var winston = require('winston'); // for transports.Console
    var app = module.exports = express();

    app.use(express.bodyParser());
    app.use(express.methodOverride());

    // Let's make our express `Router` first.
    var router = express.Router();
    router.get('/error', function(req, res, next) {
      // here we cause an error in the pipeline so we see winston-express-middleware in action.
      return next(new Error("This is an error and it should be logged to the console"));
    });

    app.get('/', function(req, res, next) {
      res.write('This is a normal request, it should be logged to the console too');
      res.end();
    });

    // winston-express-middleware logger makes sense BEFORE the router.
    app.use(expressWinston.logger({
      transports: [
        new winston.transports.Console({
          json: true,
          colorize: true
        })
      ]
    }));

    // Now we can tell the app to use our routing code:
    app.use(router);

    // winston-express-middleware errorLogger makes sense AFTER the router.
    app.use(expressWinston.errorLogger({
      transports: [
        new winston.transports.Console({
          json: true,
          colorize: true
        })
      ]
    }));

    // Optionally you can include your custom error handler after the logging.
    app.use(express.errorLogger({
      dumpExceptions: true,
      showStack: true
    }));

    app.listen(3000, function(){
      console.log("winston-express-middleware demo listening on port %d in %s mode", this.address().port, app.settings.env);
    });
```

Browse `/` to see a regular HTTP logging like this:

    {
      "req": {
        "httpVersion": "1.1",
        "headers": {
          "host": "localhost:3000",
          "connection": "keep-alive",
          "accept": "*/*",
          "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_4) AppleWebKit/536.11 (KHTML, like Gecko) Chrome/20.0.1132.57 Safari/536.11",
          "accept-encoding": "gzip,deflate,sdch",
          "accept-language": "en-US,en;q=0.8,es-419;q=0.6,es;q=0.4",
          "accept-charset": "ISO-8859-1,utf-8;q=0.7,*;q=0.3",
          "cookie": "connect.sid=nGspCCSzH1qxwNTWYAoexI23.seE%2B6Whmcwd"
        },
        "url": "/",
        "method": "GET",
        "originalUrl": "/",
        "query": {}
      },
      "res": {
        "statusCode": 200
      },
      "responseTime" : 12,
      "level": "info",
      "message": "HTTP GET /favicon.ico"
    }

Browse `/error` will show you how winston-express-middleware handles and logs the errors in the express pipeline like this:

    {
      "date": "Thu Jul 19 2012 23:39:44 GMT-0500 (COT)",
      "process": {
        "pid": 35719,
        "uid": 501,
        "gid": 20,
        "cwd": "/Users/thepumpkin/Projects/testExpressWinston",
        "execPath": "/usr/local/bin/node",
        "version": "v0.6.18",
        "argv": [
          "node",
          "/Users/thepumpkin/Projects/testExpressWinston/app.js"
        ],
        "memoryUsage": {
          "rss": 14749696,
          "heapTotal": 7033664,
          "heapUsed": 5213280
        }
      },
      "os": {
        "loadavg": [
          1.95068359375,
          1.5166015625,
          1.38671875
        ],
        "uptime": 498086
      },
      "trace": [
        ...,
        {
          "column": 3,
          "file": "Object].log (/Users/thepumpkin/Projects/testExpressWinston/node_modules/winston/lib/winston/transports/console.js",
          "function": "[object",
          "line": 87,
          "method": null,
          "native": false
        }
      ],
      "stack": [
        "Error: This is an error and it should be logged to the console",
        "    at /Users/thepumpkin/Projects/testExpressWinston/app.js:39:15",
        "    at callbacks (/Users/thepumpkin/Projects/testExpressWinston/node_modules/express/lib/router/index.js:272:11)",
        "    at param (/Users/thepumpkin/Projects/testExpressWinston/node_modules/express/lib/router/index.js:246:11)",
        "    at pass (/Users/thepumpkin/Projects/testExpressWinston/node_modules/express/lib/router/index.js:253:5)",
        "    at Router._dispatch (/Users/thepumpkin/Projects/testExpressWinston/node_modules/express/lib/router/index.js:280:4)",
        "    at Object.handle (/Users/thepumpkin/Projects/testExpressWinston/node_modules/express/lib/router/index.js:45:10)",
        "    at next (/Users/thepumpkin/Projects/testExpressWinston/node_modules/express/node_modules/connect/lib/http.js:204:15)",
        "    at done (/Users/thepumpkin/Dropbox/Projects/winston-express-middleware/index.js:91:14)",
        "    at /Users/thepumpkin/Dropbox/Projects/winston-express-middleware/node_modules/async/lib/async.js:94:25",
        "    at [object Object].log (/Users/thepumpkin/Projects/testExpressWinston/node_modules/winston/lib/winston/transports/console.js:87:3)"
      ],
      "req": {
        "httpVersion": "1.1",
        "headers": {
          "host": "localhost:3000",
          "connection": "keep-alive",
          "cache-control": "max-age=0",
          "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_4) AppleWebKit/536.11 (KHTML, like Gecko) Chrome/20.0.1132.57 Safari/536.11",
          "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
          "accept-encoding": "gzip,deflate,sdch",
          "accept-language": "en-US,en;q=0.8,es-419;q=0.6,es;q=0.4",
          "accept-charset": "ISO-8859-1,utf-8;q=0.7,*;q=0.3",
          "cookie": "connect.sid=nGspCCSzH1qxwNTWYAoexI23.seE%2B6WhmcwdzFEjqhMDuIIl3mAUY7dT4vn%2BkWvRPhZc"
        },
        "url": "/error",
        "method": "GET",
        "originalUrl": "/error",
        "query": {}
      },
      "level": "error",
      "message": "middlewareError"
    }

## Global Whitelists and Blacklists

Express-winston exposes three whitelists that control which properties of the `request`, `body`, and `response` are logged:

* `requestWhitelist`
* `bodyWhitelist`, `bodyBlacklist`
* `responseWhitelist`

For example, `requestWhitelist` defaults to:

    ['url', 'headers', 'method', 'httpVersion', 'originalUrl', 'query'];

Only those properties of the request object will be logged. Set or modify the whitelist as necessary.

For example, to include the session property (the session data), add the following during logger setup:

    expressWinston.requestWhitelist.push('session');

The blacklisting excludes certain properties and keeps all others. If both `bodyWhitelist` and `bodyBlacklist` are set
the properties excluded by the blacklist are not included even if they are listed in the whitelist!

Example:

    expressWinston.bodyBlacklist.push('secretid', 'secretproperty');

Note that you can log the whole request and/or response body:

    expressWinston.requestWhitelist.push('body');
    expressWinston.responseWhitelist.push('body');

If you need more fine grained control you can also specify sub-keys of request and response objects. Let's say you want to log the remoteAddress of the request without the entire connection object:

Example:
    expressWinston.requestWhitelist.push("connection.remoteAddress");


## Route-Specific Whitelists and Blacklists

You can add whitelist elements in a route.  winston-express-middleware adds a `_routeWhitelists` object to the `req`uest, containing `.body`, `.req` and .res` properties, to which you can set an array of 'whitelist' parameters to include in the log, specific to the route in question:

``` js
    router.post('/user/register', function(req, res, next) {
      req._routeWhitelists.body = ['username', 'email', 'age']; // But not 'password' or 'confirm-password' or 'top-secret'
      req._routeWhitelists.res = ['_headers'];
    });
```

Post to `/user/register` would give you something like the following:

    {
      "req": {
        "httpVersion": "1.1",
        "headers": {
          "host": "localhost:3000",
          "connection": "keep-alive",
          "accept": "*/*",
          "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_4) AppleWebKit/536.11 (KHTML, like Gecko) Chrome/20.0.1132.57 Safari/536.11",
          "accept-encoding": "gzip,deflate,sdch",
          "accept-language": "en-US,en;q=0.8,es-419;q=0.6,es;q=0.4",
          "accept-charset": "ISO-8859-1,utf-8;q=0.7,*;q=0.3",
          "cookie": "connect.sid=nGspCCSzH1qxwNTWYAoexI23.seE%2B6Whmcwd"
        },
        "url": "/",
        "method": "GET",
        "originalUrl": "/",
        "query": {},
        "body": {
          "username": "foo",
          "email": "foo@bar.com",
          "age": "72"
        }
      },
      "res": {
        "statusCode": 200
      },
      "responseTime" : 12,
      "level": "info",
      "message": "HTTP GET /favicon.ico"
    }

Blacklisting supports only the `body` property.


``` js
    router.post('/user/register', function(req, res, next) {
      req._routeWhitelists.body = ['username', 'email', 'age']; // But not 'password' or 'confirm-password' or 'top-secret'
      req._routeBlacklists.body = ['username', 'password', 'confirm-password', 'top-secret'];
      req._routeWhitelists.res = ['_headers'];
    });
```

If both `req._bodyWhitelist.body` and `req._bodyBlacklist.body` are set the result will be the white listed properties
excluding any black listed ones. In the above example, only 'email' and 'age' would be included.


## Tests

Run the basic Mocha tests:

    npm test

Run the Travis-CI tests (which will fail with < 100% coverage):

    npm test-travis

Generate the `coverage.html` coverage report:

    npm test-coverage

## Issues and Collaboration

If you ran into any problems, please use the project [Issues section](https://github.com/bithavoc/winston-express-middleware/issues) to search or post any bug.

## Contributors

* [Johan Hernandez](https://github.com/bithavoc) (https://github.com/bithavoc)
* [Lars Jacob](https://github.com/jaclar) (https://github.com/jaclar)
* [Jonathan Lomas](https://github.com/floatingLomas) (https://github.com/floatingLomas)

Also see AUTHORS file, add yourself if you are missing.
