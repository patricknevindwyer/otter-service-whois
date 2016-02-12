var express = require('express');
var router = express.Router();
var request = require('request');
var async = require("async");
var _ = require("underscore");
var whois = require("whois-ux");
var uuid = require("node-uuid");

var RESOLVE_INTERVAL = 1000;
var WEBHOOK_REMOTE_WHOIS = "http://localhost:8000/webhook/whois/";

// Register our service with the primary service dispatch
var DISPATCH_URI = "http://localhost:20000";
var SERVICE_UUID = "";

request.put(
    {
        uri: DISPATCH_URI + "/register", 
        body: {
            service: "service-whois",
            endpoint: "" + process.env.PORT,
            tags: ["dns", "ip"] 
        },
        json: true
    },
    function (err, data) {
        
        if (data.statusCode == 200) {
            SERVICE_UUID = data.body.uuid;
            console.log("Registered as [%s]", SERVICE_UUID);
            setInterval(serviceHeartbeat, 60000);
        }
        else {
            console.log("register error: %s", err);
            console.log("register data: %s", JSON.stringify(data));            
        }
    }
)

// Send a heartbeat message to the dispatch service
function serviceHeartbeat() {
    request.patch(DISPATCH_URI + "/service/uuid/" + SERVICE_UUID + "/heartbeat",
    function (err, data) {
        if (err) {
            console.log("Heartbeat error: %s", err);
            console.log(data);
        }
        else {
            console.log("dispatch heartbeat");
        }
    });
}

['SIGHUP', 'SIGINT', 'SIGQUIT', 'SIGILL', 'SIGTRAP', 'SIGABRT',
         'SIGBUS', 'SIGFPE', 'SIGUSR1', 'SIGSEGV', 'SIGUSR2', 'SIGTERM'
        ].forEach(function(element, index, array) {
            process.on(element, deregister);
        });

function deregister() {
    console.log("Caught exit");
    if (SERVICE_UUID !== "") {
        console.log("Service UUID exists, deregistering")
        request.del(DISPATCH_URI + "/service/uuid/" + SERVICE_UUID + "/",
        function (err, data) {
            if (err) {
                console.log("Deregistration error: %s", err );
                console.log(data);
            }
            else {
                console.log("Deregistered from service dispatch");
            }
            process.exit(1);
        });
    }
    else {
        process.exit(1);
    }
}

/*
    This module conforms to a standard Webhook based round trip.
    
    1. POST /resolve  (JSON body) - data to resolve
    2. enqueue data for resolve
    3. interval check for resolve data in queue
    4. Resolve top item from queue
    5. Store resolved data
    6. Tickle remote webhook for "completed" state
      6a. GET <remote>:/<webhook>/<item_id>/resolved
    7. GET /resolved/<item_id>
    8. DELETE /resolved/<item_id>

*/

var RESOLVE_QUEUE = [];
var RESOLVED_DATA = {};

function resolveData(queuedItem, next) {
    
    var isHostLookup = false;
    var query = "";
    var whoisQuery = "";
    
    if (_.has(queuedItem, "fqdn")) {
        isHostLookup = true;
        query = queuedItem.fqdn;
        whoisQuery = "'domain " + query + "'";
    }
    else {
        query = queuedItem.ip;
        whoisQuery = query;
    }
    console.log("Resolving [%s]\n\t%s", queuedItem.uuid, query);
    
    whois.whois(
        // hostname to lookup
        whoisQuery,
        
        // lookup callback
        function (err, whoisData) {
            console.log("Whois resolution complete");
            console.log(whoisData);
            
            if (err) {
                console.log(err);
                
            }            
            var results = {
                uuid: queuedItem.uuid,
                query: query,
                isHostLookup: isHostLookup,
                result: whoisData
            };
            
            // create a new lookup UUID so we don't stomp records and
            // results (multiple IP queries will be generated from each
            // host lookup)
            var whoisUUID = uuid.v4();
            
            RESOLVED_DATA[whoisUUID] = results;
            
            tickleWebhook(whoisUUID + "/ready", next);
            
        }
    )
        

}

function tickleWebhook(path, next) {
    request(WEBHOOK_REMOTE_WHOIS + path, function (error, response, body) {
        if (!error && response.statusCode == 200) {
            next();
        }
        else {
            console.log("Error calling remote webook at [%s]\n\tcode: %d\n\terror: %s", WEBHOOK_REMOTE_WHOIS + path, response.statusCode, error);
            next();
        }
    })   
}

/*
    Generic queue check and drain that kicks off at most
    every RESOLVE_INTERVAL milliseconds. 
*/
function checkResolveQueue() {
    
    if (RESOLVE_QUEUE.length > 0) {
        var resolveItem = RESOLVE_QUEUE.shift();
        resolveData(resolveItem, 
            function () {
                setTimeout(checkResolveQueue, RESOLVE_INTERVAL);
            }
        );
    }
    else {
        setTimeout(checkResolveQueue, RESOLVE_INTERVAL);
    }
}
checkResolveQueue();

/*
    Expecting a JSON body of the form:
    {
        "uuid": <uuid>,
        "uri": <full uri>
    }
    
    or
    
    {
        "uuid": <uuid>,
        "ip": <ip address>
    }
    
    The route that is called via Webhook will change based on the incoming 
    resolve features.
*/
router.post("/resolve", function (req, res, next) {
    
    RESOLVE_QUEUE.push(req.body);
    res.json({error: false, msg: "ok"});
    
});

router.get(/^\/resolved\/([a-zA-Z0-9\-]+)\/?$/, function (req, res, next) {
    var resolveUuid = req.params[0];
    console.log("Results being retrieved for [%s]", resolveUuid);
    if (RESOLVED_DATA[resolveUuid] !== undefined) {
        res.json({error: false, result: RESOLVED_DATA[resolveUuid]});
    }
    else {
        console.log("Invalid UUID specified");
        res.json({error: true, msg: "No such resolved UUID"});
    }
});

router.delete(/^\/resolved\/([a-zA-Z0-9\-]+)\/?$/, function (req, res, next) {
    var resolveUuid = req.params[0];
    console.log("Deleting results for [%s]", resolveUuid);
    delete RESOLVED_DATA[resolveUuid];
    res.json({error: false, msg: "ok"});
});




module.exports = router;
