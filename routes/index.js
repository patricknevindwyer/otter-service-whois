var express = require('express');
var router = express.Router();
var _ = require("underscore");
var whois = require("whois-ux");
var uuid = require("node-uuid");

var dispatch = require("dispatch-client");
var webhookService = require("webhook-service");

var WEBHOOK_REMOTE_WHOIS = "http://localhost:8000/webhook/whois/";

// Register ourselves with the dispatch server to find and share URIs for services
var dispatcher = new dispatch.Client("http://localhost:20000");
dispatcher.register("service-whois", ["dns", "ip"]);

// Setup the new webhook service responder
var webhookedService = new webhookService.Service(WEBHOOK_REMOTE_WHOIS);
webhookedService.useRouter(router);
webhookedService.callResolver(resolveData);
webhookedService.start();

// Run the WHOIS resolution
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
            
            webhookedService.saveResolved(whoisUUID, results);
            //RESOLVED_DATA[whoisUUID] = results;
            
            webhookedService.tickleWebhook(whoisUUID, next);
            
        }
    )
}


module.exports = router;
