var https = require('https');
var fs  = require('fs');


const NodeCache = require( "node-cache" );
const icaRiskCache = new NodeCache( { stdTTL: 0, checkperiod: 0 } );
const cloudsocRiskCache = new NodeCache( { stdTTL: 0, checkperiod: 0 } );
const vipRiskCache = new NodeCache( { stdTTL: 0, checkperiod: 0 } );

var gDeviceTag = "not found";
var gDeviceRegistered = false; 

function vipConfirmRisk(req,res,pushRequest,eventId){

//  console.log("CONFIRM RISK ", pushRequest['S:Envelope']['S:Body'].AuthenticateUserWithPushResponse );

  var userId = req.body.username;
  var devFP = req.body.deviceFingerprint;
  var requestId = "mn0123";


  console.log ("Confirm Risk ID = ", eventId);

  var reqBody = 
    '<soapenv:Envelope ' +
            'xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" ' + 
            'xmlns:vip="https://schemas.symantec.com/vip/2011/04/vipuserservices"> ' +
            '<soapenv:Header/>'+
            '<soapenv:Body>'+
              '<vip:ConfirmRiskRequest>'+
                 '<vip:requestId>'+ requestId +'</vip:requestId>'+
                 '<vip:UserId>'+ userId +'</vip:UserId>'+
                 '<vip:EventId>'+ eventId +'</vip:EventId>'+      
//                 '<vip:IAAuthData>'+ devFP +'</vip:IAAuthData>'+      
              '</vip:ConfirmRiskRequest>'+
            '</soapenv:Body>' +
        '</soapenv:Envelope>';

//  console.log ("Confirm Risk Req Body = ", reqBody);


 var options = {
    hostname: 'userservices-auth.vip.symantec.com',
    port: 443,
    path: '/vipuserservices/AuthenticationService_1_10',
    method: 'POST',
    headers: {
         'Content-Type': 'text/xml',
         'Content-Length': reqBody.length
    },
    key: fs.readFileSync('./cert/vip-key.pem'),   //path to private key
    cert: fs.readFileSync('./cert/vip.crt') //path to pem
    //  passphrase: 'password'
  };



  var xmlParser = require('xml2json');

  /*
  */
  var conn = https.request(options, (resp) => {
    console.log('Response from CONFIRM RISK - statusCode:', resp.statusCode);
//    console.log('headers:', resp.headers);

    const xmlString = [];

    resp.on('data', (d) => {
        xmlString.push(d);
      });
    resp.on('end', function() {
        const json = JSON.parse(xmlParser.toJson(Buffer.concat(xmlString)));
//        console.log("Response from POLL PUSH - body: ", json['S:Envelope']['S:Body']);

        if (json['S:Envelope']['S:Body'].ConfirmRiskResponse.status == '0000') {
           console.log("Response from Confirm Risk: SUCCESS");
        } else {
           // Error ; redirect browser to error page
           console.log("Response from Confirm Risk: ",json['S:Envelope']['S:Body'].ConfirmRiskResponse.status, " --- ", json['S:Envelope']['S:Body'].ConfirmRiskResponse.statusMessage);
        }
    });
  });

  conn.on('error', (e) => {
      console.error(e);
  });

    // POST the request body to VIP-AI
  conn.write(reqBody);
  conn.end();


  return true;
}





function vipDenyRisk(req,res,pushRequest,eventId){

//  console.log("CONFIRM RISK ", pushRequest['S:Envelope']['S:Body'].AuthenticateUserWithPushResponse );

  var userId = req.body.username;
  var devFP = req.body.deviceFingerprint;
  var requestId = "mn0123";


  console.log ("Deny Risk ID = ", eventId);

  var reqBody = 
    '<soapenv:Envelope ' +
            'xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" ' + 
            'xmlns:vip="https://schemas.symantec.com/vip/2011/04/vipuserservices"> ' +
            '<soapenv:Header/>'+
            '<soapenv:Body>'+
              '<vip:DenyRiskRequest>'+
                 '<vip:requestId>'+ requestId +'</vip:requestId>'+
                 '<vip:UserId>'+ userId +'</vip:UserId>'+
                 '<vip:EventId>'+ eventId +'</vip:EventId>'+      
//                 '<vip:IAAuthData>'+ devFP +'</vip:IAAuthData>'+      
              '</vip:DenyRiskRequest>'+
            '</soapenv:Body>' +
        '</soapenv:Envelope>';

//  console.log ("Confirm Risk Req Body = ", reqBody);


 var options = {
    hostname: 'userservices-auth.vip.symantec.com',
    port: 443,
    path: '/vipuserservices/AuthenticationService_1_10',
    method: 'POST',
    headers: {
         'Content-Type': 'text/xml',
         'Content-Length': reqBody.length
    },
    key: fs.readFileSync('./cert/vip-key.pem'),   //path to private key
    cert: fs.readFileSync('./cert/vip.crt') //path to pem
    //  passphrase: 'password'
  };



  var xmlParser = require('xml2json');

  /*
  */
  var conn = https.request(options, (resp) => {
    console.log('Response from DENY RISK - statusCode:', resp.statusCode);
//    console.log('headers:', resp.headers);

    const xmlString = [];

    resp.on('data', (d) => {
        xmlString.push(d);
      });
    resp.on('end', function() {
        const json = JSON.parse(xmlParser.toJson(Buffer.concat(xmlString)));
//        console.log("Response from POLL PUSH - body: ", json['S:Envelope']['S:Body']);

        if (json['S:Envelope']['S:Body'].DenyRiskResponse.status == '0000') {
           console.log("Response from Deny Risk: SUCCESS");
        } else {
           // Error ; redirect browser to error page
           console.log("Response from Deny Risk: ",json['S:Envelope']['S:Body'].DenyRiskResponse.status, " --- ", json['S:Envelope']['S:Body'].DenyRiskResponse.statusMessage);
        }
    });
  });

  conn.on('error', (e) => {
      console.error(e);
  });

    // POST the request body to VIP-AI
  conn.write(reqBody);
  conn.end();


  return true;


}


function pollPushStatus(req,res,pushRequest,eventId) {

  var requestId = pushRequest['S:Envelope']['S:Body'].AuthenticateUserWithPushResponse.transactionId;

  console.log ("Poll Transaction ID = ", requestId);


  var reqBody = 
    '<soapenv:Envelope ' +
            'xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" ' + 
            'xmlns:vip="https://schemas.symantec.com/vip/2011/04/vipuserservices"> ' +
            '<soapenv:Header/>'+
            '<soapenv:Body>'+
              '<vip:PollPushStatusRequest>' +
                '<vip:requestId>mn0123</vip:requestId>' +
                '<vip:transactionId>'+ requestId +'</vip:transactionId>' +
              '</vip:PollPushStatusRequest>' +
            '</soapenv:Body>' +
        '</soapenv:Envelope>';

  var options = {
    hostname: 'userservices-auth.vip.symantec.com',
    port: 443,
    path: '/vipuserservices/QueryService_1_10',
    method: 'POST',
    headers: {
         'Content-Type': 'text/xml',
         'Content-Length': reqBody.length
    },
    key: fs.readFileSync('./cert/vip-key.pem'),   //path to private key
    cert: fs.readFileSync('./cert/vip.crt') //path to pem
    //  passphrase: 'password'
  };

//  console.log('VIP PUSH POLL - Request: \n', reqBody);


  var xmlParser = require('xml2json');

  /*
  */
  var conn = https.request(options, (resp) => {
    console.log('Response from PUSH POLL - statusCode:', resp.statusCode);
//    console.log('headers:', resp.headers);

    const xmlString = [];

    resp.on('data', (d) => {
        xmlString.push(d);

      });
    resp.on('end', function() {

        const json = JSON.parse(xmlParser.toJson(Buffer.concat(xmlString)));
//        console.log("Response from POLL PUSH - body: ", json['S:Envelope']['S:Body']);

        if (json['S:Envelope']['S:Body'].PollPushStatusResponse.transactionStatus.status == '7001') {
           // In progress ; try again in 1 second
           setTimeout(pollPushStatus,1000,req,res,pushRequest,eventId);
        } else if (json['S:Envelope']['S:Body'].PollPushStatusResponse.transactionStatus.status == '7000') {
           // Success ; redirect browser back to success page
           vipDenyRisk(req,res,pushRequest,eventId);           // call denyRisk
           res.redirect(301, '/risk/risk?userId='+req.body.username+'&eventId='+eventId);
//           res.write("No Risk - good to go");
           res.end();
        } else if (json['S:Envelope']['S:Body'].PollPushStatusResponse.transactionStatus.status == '7002') {
           // Failed ; redirect browser back to Try-Again Page
           vipConfirmRisk(req,res,pushRequest,eventId);      // call confirmRisk
           res.redirect(301, '/demo/voonair-denied.html');
//           res.write("Denied - Try Again");
//           res.end();
        } else {
           // Error ; redirect browser to error page
           console.log(json['S:Envelope']['S:Body']);
           res.write("This looks Risky");
           res.end();
        }
    });
  });

  conn.on('error', (e) => {
      console.error(e);
  });

    // POST the request body to VIP-AI
  conn.write(reqBody);
  conn.end();


  return true;
}





function challengeUser (req,res,eventId) {

  var userId = req.body.username;

  var reqBody = 
    '<soapenv:Envelope ' +
            'xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" ' + 
            'xmlns:vip="https://schemas.symantec.com/vip/2011/04/vipuserservices"> ' +
            '<soapenv:Header/>'+
            '<soapenv:Body>'+
              '<vip:AuthenticateUserWithPushRequest>' +
                '<vip:requestId>mn0123</vip:requestId>' +
                '<vip:userId>'+ userId +'</vip:userId>' +
                '<vip:pushAuthData>' +
                  '<vip:displayParameters>' +
                    '<vip:Key>Message</vip:Key>' +
                    '<vip:Value>Push Me</vip:Value>' +
                  '</vip:displayParameters>' +
                '</vip:pushAuthData>' +
              '</vip:AuthenticateUserWithPushRequest>' +
            '</soapenv:Body>' +
        '</soapenv:Envelope>';


  var options = {
    hostname: 'userservices-auth.vip.symantec.com',
    port: 443,
    path: '/vipuserservices/AuthenticationService_1_10',
    method: 'POST',
    headers: {
         'Content-Type': 'text/xml',
         'Content-Length': reqBody.length
    },
    key: fs.readFileSync('./cert/vip-key.pem'),   //path to private key
    cert: fs.readFileSync('./cert/vip.crt') //path to pem
    //  passphrase: 'password'
  };

  console.log('VIP Push Notification - Request:');


  var xmlParser = require('xml2json');

  /*
  */
  var conn = https.request(options, (resp) => {
    console.log('Response from VIP PUSH - statusCode:', resp.statusCode);
//    console.log('headers:', resp.headers);

    const xmlString = [];

    resp.on('data', (d) => {
        xmlString.push(d);
      });
    resp.on('end', function() {
        const json = JSON.parse(xmlParser.toJson(Buffer.concat(xmlString)));
//        console.log("Response from VIP PUSH - body: ", json['S:Envelope']['S:Body'].AuthenticateUserWithPushResponse);
        pollPushStatus(req,res,json,eventId);
    });
  });

  conn.on('error', (e) => {
      console.error(e);
  });

    // POST the request body to VIP-AI
  conn.write(reqBody);
  conn.end();




  return true;
}


function riskyAccess (req,res,userContext) {

  const json = JSON.parse(userContext);

  var attrFound = false;
  var isRisky = true;
  var evntId = "not-found";
  gDeviceTag = "Not Found";
  gDeviceRegistered = false; 

  gDeviceTag = "Not Found";

  attrFound = 'S:Envelope' in json;
  if (attrFound) attrFound = 'S:Body' in json["S:Envelope"] ;
  if (attrFound) attrFound = 'EvaluateRiskResponse' in json["S:Envelope"]["S:Body"] ;
  if (attrFound) attrFound = 'Risky' in json["S:Envelope"]["S:Body"].EvaluateRiskResponse ;
  if (attrFound) attrFound = 'KeyValuePairs' in json["S:Envelope"]["S:Body"].EvaluateRiskResponse ;


  evntId = json["S:Envelope"]["S:Body"].EvaluateRiskResponse.EventId;

  if (attrFound) {

     for(var i = 0; i < json["S:Envelope"]["S:Body"].EvaluateRiskResponse.KeyValuePairs.length; i++)
     {
       if(json["S:Envelope"]["S:Body"].EvaluateRiskResponse.KeyValuePairs[i].Key == 'device.tag')
       {
         gDeviceTag = json["S:Envelope"]["S:Body"].EvaluateRiskResponse.KeyValuePairs[i].Value;
//         console.log("FOUND DEVICE TAG : ",gDeviceTag);
       } 
       if(json["S:Envelope"]["S:Body"].EvaluateRiskResponse.KeyValuePairs[i].Key == 'device.registered')
       {
         gDeviceRegistered = (json["S:Envelope"]["S:Body"].EvaluateRiskResponse.KeyValuePairs[i].Value == 'true');
//         console.log("FOUND DEVICE REGO : ",gDeviceRegistered);
       }
     }
  }

  //console.log("DEBUG --- ",json["S:Envelope"]["S:Body"].EvaluateRiskResponse)

  if (attrFound) {
    var status = json["S:Envelope"]["S:Body"].EvaluateRiskResponse.status;

    if (status == "0000") {
      // Success. Login is not risky. Ok to login
      console.log("Success", json["S:Envelope"]["S:Body"].EvaluateRiskResponse.status);
      vipRiskCache.set(req.body.username,(json["S:Envelope"]["S:Body"].EvaluateRiskResponse));

      isRisky = false;
    }
    else if (status == "6009") {
      console.log("Risky", json["S:Envelope"]["S:Body"].EvaluateRiskResponse.status);
      console.log("Response", json["S:Envelope"]["S:Body"].EvaluateRiskResponse);
      vipRiskCache.set(req.body.username,(json["S:Envelope"]["S:Body"].EvaluateRiskResponse));
      
      // Authentication failed. Login is risky
     // Should challenge the user before allowing login
    } else {
      console.log("Error", json["S:Envelope"]["S:Body"].EvaluateRiskResponse.status);
      // error condition (e.g. invalid input, not authorized to perform 
      // this operation, IA service not available, etc)
      // Recommend to challenge user
    }

    if (isRisky) {
  
      var challengePassed = challengeUser(req,res,json["S:Envelope"]["S:Body"].EvaluateRiskResponse.EventId);

      // evaluateRisk returns successfully and evaluated to be risky
      if (challengePassed) {
           // call denyRisk
      } else {
        // call confirmRisk
      }
    } else {
       res.redirect(301, '/risk/risk?userId='+req.body.username+'&eventId='+evntId);
    }
  }

  return isRisky;
}


function vipUserRisk (req,res) {

  console.log("USERNAME",req.body.username);
  console.log("PASSWORD",req.body.password);
  console.log("DFP",req.body.deviceFingerprint);


	var reqId = 'mni00100017'; // lower case and digits only
	var reqUser = req.body.username;
	var reqIp = '35.197.173.108';
	var reqUA = 'Mozilla';
	var reqAuthData = req.body.deviceFingerprint;

	var reqBody = 
		'<soapenv:Envelope ' +
            'xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" ' + 
            'xmlns:vip="https://schemas.symantec.com/vip/2011/04/vipuserservices"> ' +
            '<soapenv:Header/>'+
            '<soapenv:Body>'+
                '<vip:EvaluateRiskRequest>' +
                    '<vip:requestId>' + reqId + '</vip:requestId>' +
                    '<vip:UserId>' + reqUser + '</vip:UserId>' +
                    '<vip:Ip>' + reqIp + '</vip:Ip>' +
                    '<vip:UserAgent>' + reqUA + '</vip:UserAgent>' +
                    '<vip:IAAuthData>' + reqAuthData + '</vip:IAAuthData>' +
                    '<vip:ResponseControl>' +
                        '<vip:IncludeRequestContext>true</vip:IncludeRequestContext>' +
                    '</vip:ResponseControl>' +
                '</vip:EvaluateRiskRequest>' +
            '</soapenv:Body>' +
        '</soapenv:Envelope>';


	var options = {
	  hostname: 'userservices-auth.vip.symantec.com',
	  port: 443,
	  path: '/vipuserservices/AuthenticationService_1_10',
	  method: 'POST',
	  headers: {
	       'Content-Type': 'text/xml',
	       'Content-Length': reqBody.length
	  },
	  key: fs.readFileSync('./cert/vip-key.pem'),   //path to private key
	  cert: fs.readFileSync('./cert/vip.crt') //path to pem
	  //  passphrase: 'password'
	};

  console.log('VIP Intelligent Authentication - Request:');


	var xmlParser = require('xml2json');

	/*
	*/
	var conn = https.request(options, (resp) => {
	  console.log('Response from VIP IA - statusCode:', resp.statusCode);
//	  console.log('headers:', resp.headers);

	  const xmlString = [];

	  resp.on('data', (d) => {
      	xmlString.push(d);
      });
    resp.on('end', function() {
        riskyAccess(req,res,xmlParser.toJson(Buffer.concat(xmlString)));
/*
        {
           res.write("This looks Risky");
        } else {
           res.write("No Risk - good to go");
        }

//      	res.write(xmlParser.toJson(Buffer.concat(xmlString)));
      	res.end();
*/
	  });
  });

  conn.on('error', (e) => {
    	console.error(e);
  });

  	// POST the request body to VIP-AI
  conn.write(reqBody);
  conn.end();
}


function lookupUserRisk(req){

}






/*
  Set up server and services
*/

const express = require('express')
const app = express()

const bodyParser = require('body-parser');
const url = require('url');
const querystring = require('querystring');

const port = 3000
const host = "risk.iamdemo.broadcom.com";
var path = require('path');


// Parse URL-encoded bodies (as sent by HTML forms)
app.use(express.urlencoded());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

app.get('/', (req, res) => {
  res.send('Hello World!')
})

app.get('/risk/risk', (req, res) => {

  var eventId = req.query.eventId;
  let userId = req.query.userId;

  const json = { "userId": "undefined", "risks" : [{"riskSource": "VIP-IA", "risk":{}},{"riskSource": "CloudSOC", "risk":{}},{"riskSource": "RiskFabric", "risk":{}}] } ;
  
    if (userId == undefined) {
      json.userId = "undefined"; 
    } else {
      json.userId = userId;
  
      var risk = icaRiskCache.get(userId);
      if ( risk != undefined ){
//         console.log("Getting ICA Risk",risk);
         json.risks[2].riskSource = "RiskFabric";
         json.risks[2].risk = risk;
      } ;
      risk = cloudsocRiskCache.get(userId);
      if ( risk != undefined ){
//         console.log("Getting Cloudsoc Risk",risk);
         json.risks[1].riskSource = "CloudSOC";
         json.risks[1].risk = risk;
      } ;
      risk = vipRiskCache.get(userId);
      if ( risk != undefined ){
//         console.log("Getting VIP Risk",risk);
         json.risks[0].riskSource = "VIP-IA";
         json.risks[0].risk = risk;
      } ;

  }


  var html = '<html><head><title>Voonair Airlines</title></head><body>';


  html += '<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.4.0/css/bootstrap.min.css"><link href="https://fonts.googleapis.com/css?family=Montserrat" rel="stylesheet"><script src="https://ajax.googleapis.com/ajax/libs/jquery/3.4.1/jquery.min.js"></script><script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.4.0/js/bootstrap.min.js"></script>';


  html += "<style> .tabcontent { display: none; padding: 6px 12px; border: 1px solid #ccc; border-top: none; } </style>";


  html += '<style> body { font: 20px Montserrat, sans-serif;    line-height: 1.8;    color: #f5f6f7;  }  p {font-size: 16px;}  .margin {margin-bottom: 45px;}  .bg-1 {     background-color: #1abc9c; /* Green */    color: #ffffff;  }  .bg-2 {     background-color: #474e5d; /* Dark Blue */    color: #ffffff;  }  .bg-3 {     background-color: #ffffff; /* White */    color: #555555;  }  .bg-4 {     background-color: #2f2f2f; /* Black Gray */    color: #fff;  }  .container-fluid {    padding-top: 70px;    padding-bottom: 70px;  }  .navbar {    padding-top: 15px;    padding-bottom: 15px;    border: 0;    border-radius: 0;    margin-bottom: 0;    font-size: 12px;    letter-spacing: 5px;  }  .navbar-nav  li a:hover {    color: #1abc9c !important;  }  </style>';


  html += '<nav class="navbar navbar-default"> <div class="container">    <div class="navbar-header">      <button type="button" class="navbar-toggle" data-toggle="collapse" data-target="#myNavbar">        <span class="icon-bar"></span>        <span class="icon-bar"></span>        <span class="icon-bar"></span>                              </button>      <a class="navbar-brand" href="#">Voonair Airlines</a>    </div>    <div class="collapse navbar-collapse" id="myNavbar">      <ul class="nav navbar-nav navbar-right">        <li><a href="#">Search</a></li>        <li><a href="#">Buy</a></li>        <li><a href="/voonair/jsps/logout.jsp">Logout</a></li>      </ul>    </div>  </div></nav>';

  html += '<div class="container bg-1 text-center">  <h3 class="margin">Travel eazy, safe, with ....</h3>  <img src="http://siteminder.l7demo.com:7000/voonair/img/voonair_logo.png" class="img-responsive  margin" style="display:inline" alt="Bird" width="350" height="350"></div><div class="container bg-1 text-center">  <h3 class="margin">Risk Profile Information for '+ req.query.userId +'</h3></div>';

  html += '<div class="container bg-2 text-center"> <br/>  <p>';
  //
  // Store the deviceTag in the browser 
  //
  if (!gDeviceRegistered) {
     html+= " <div class='tab'> ";
     html += '<form action="/risk/registerfingerprinthandler?eventId=' + eventId +'&userId='+userId+'" method="post">';
     html += '<input type="hidden" name="fingerprint">';
     html += '<script type="text/javascript" src="https://userservices.vip.symantec.com/vipuserservices/static/v_1_0/scripts/iadfp.js"></script>';
     html += '<table cellspacing="5">';
       html += '<tr><td>Remember this device next time you log in?</td>';
       html += '<td id="updateButton" class="list-group-item list-group-item-success" align="right"><input type="submit" onclick="updateFingerprint()" name="ok" value="Yes"></td></tr>';
     html += '</table>';
     html += '</form>';
     html+= " </div> ";
  };


  var userLinks = ["https://iarules.symcdemo.com/ajaxswing/apps/iaruleengine","https://app.elastica.net/static/ng/appThreats/index.html#/?severities=high&deeplink=users","http://riskfabric.iamdemo.broadcom.com/#/entities/persons/2143/detail"];

  html+= " <div class='tab'> ";
  html+= " <table><tr> ";
  html+= ' <td><button class="list-group-item list-group-item-success" onclick="changeRisk(event, \'VIP-IA\')" id="defaultOpen">VIP-IA</button></td> ';
  html+= ' <td><button class="list-group-item list-group-item-success" onclick="changeRisk(event, \'CloudSOC\')">CloudSOC</button></td> ';
  html+= ' <td><button class="list-group-item list-group-item-success" onclick="changeRisk(event, \'RiskFabric\')">RiskFabric</button></td> ';
  html+= " </tr></table></div> ";


  for (var i=0; i<json.risks.length; i++){
      html += "<div id="+ JSON.stringify(json.risks[i].riskSource,null,"\t")  +" class='tabcontent'>";
      html += '<ul class="list-group">';
      html += '<li class="list-group-item list-group-item-success" style="width:20%"> <a target="_blank" href='+ userLinks[i] +'>'+ (JSON.stringify(json.risks[i].riskSource,null,"\t")) +'</a></li>';
      html += '<li class="list-group-item list-group-item-success" style="text-align:left" ><pre>'+ (JSON.stringify(json.risks[i].risk,null,"\t")) +'</pre></li>';
      html += '</ul>  </p>  <br/>  <!-- <a href="#" class="btn btn-default btn-lg">    <span class="glyphicon glyphicon-search"></span> more about us?  </a> -->';
      html += "</div>";
  }

  html += "</div>";
  html += '<footer class="container bg-4 text-center">  <p><a href="#">Voonair Airlines</a></p> </footer>';

html += '<script>';
html += 'function updateFingerprint() {';
html += 'IaDfp.writeTag("' + gDeviceTag + '",true);';
html += 'document.all["fingerprint"].value = IaDfp.readFingerprint();';
html += 'document.getElementById("updateButton").style.backgroundColor="green"; ';
html += '}';
html += '</script>';

html += "<script>"
html += "function changeRisk(evt, riskSource) { ";
html += "     var i, tabcontent, tablinks; ";

html += "     tabcontent = document.getElementsByClassName('tabcontent'); ";
html += "     for (i = 0; i < tabcontent.length; i++) { ";
html += "       console.log('TABCONTENT = ',tabcontent[i]);";
html += "       tabcontent[i].style.display = 'none'; ";
html += "     } ";

html += "     tablinks = document.getElementsByClassName('tablinks'); ";
html += "     for (i = 0; i < tablinks.length; i++) { ";
html += "       tablinks[i].className = tablinks[i].className.replace(' active', ''); ";
html += "     } ";
 
html += "     console.log('RISKSOURCE = ',riskSource);";
html += "     document.getElementById(riskSource).style.display = 'block'; ";
html += "     evt.currentTarget.className += ' active'; ";
html += "  }";
html += "</script>"


html += "<script>"
html += "document.getElementById('defaultOpen').click();";
html += "</script>"


  html += "</body></html>";



  res.send(html);

//  res.send(json);
})



function vipUpdateFingerprint(req,res){

//  console.log("CONFIRM RISK ", pushRequest['S:Envelope']['S:Body'].AuthenticateUserWithPushResponse );

  var userId = req.query.userId;
  var devFP = req.body.fingerprint;
  var requestId = "mn0123";
  var eventId = req.query.eventId;


  console.log ("Update FingerPrint = ", devFP);

  var reqBody = 
    '<soapenv:Envelope ' +
            'xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" ' + 
            'xmlns:vip="https://schemas.symantec.com/vip/2011/04/vipuserservices"> ' +
            '<soapenv:Header/>'+
            '<soapenv:Body>'+
              '<vip:DenyRiskRequest>'+
                 '<vip:requestId>'+ requestId +'</vip:requestId>'+
                 '<vip:UserId>'+ userId +'</vip:UserId>'+
                 '<vip:EventId>'+ eventId +'</vip:EventId>'+      
                 '<vip:IAAuthData>'+ devFP +'</vip:IAAuthData>'+      
                 '<vip:RememberDevice>true</vip:RememberDevice>'+
              '</vip:DenyRiskRequest>'+
            '</soapenv:Body>' +
        '</soapenv:Envelope>';

//  console.log ("Confirm Risk Req Body = ", reqBody);


 var options = {
    hostname: 'userservices-auth.vip.symantec.com',
    port: 443,
    path: '/vipuserservices/AuthenticationService_1_10',
    method: 'POST',
    headers: {
         'Content-Type': 'text/xml',
         'Content-Length': reqBody.length
    },
    key: fs.readFileSync('./cert/vip-key.pem'),   //path to private key
    cert: fs.readFileSync('./cert/vip.crt') //path to pem
    //  passphrase: 'password'
  };



  var xmlParser = require('xml2json');

  /*
  */
  var conn = https.request(options, (resp) => {
    console.log('Response from DENY RISK - statusCode:', resp.statusCode);
//    console.log('headers:', resp.headers);

    const xmlString = [];

    resp.on('data', (d) => {
        xmlString.push(d);
      });
    resp.on('end', function() {
        const json = JSON.parse(xmlParser.toJson(Buffer.concat(xmlString)));
//        console.log("Response from POLL PUSH - body: ", json['S:Envelope']['S:Body']);

        if (json['S:Envelope']['S:Body'].DenyRiskResponse.status == '0000') {
           console.log("Response from Deny Risk: SUCCESS");
        } else {
           // Error ; redirect browser to error page
           console.log("Response from Deny Risk: ",json['S:Envelope']['S:Body'].DenyRiskResponse.status, " --- ", json['S:Envelope']['S:Body'].DenyRiskResponse.statusMessage);
        }
    });
  });

  conn.on('error', (e) => {
      console.error(e);
  });

    // POST the request body to VIP-AI
  conn.write(reqBody);
  conn.end();


  return true;


}


app.get('/risk/vip', (req, res) => {
  vipUserRisk(req,res);
//  res.send('ICA Demo Stub!')
})

app.post('/risk/login', (req, res) => {
  vipUserRisk(req,res);
//  res.send("Logging in");
 //  res.send('ICA Demo Stub!')
})

app.post('/risk/registerfingerprinthandler', (req, res) => {
  vipUpdateFingerprint(req,res);
})

app.get('/demo/voonair-denied.html', function(req, res) {
    res.sendFile(path.join(__dirname + '/voonair-denied.html'));
});


app.get('/demo/voonair.html', function(req, res) {
    res.sendFile(path.join(__dirname + '/voonair.html'));
});

app.get('/demo/voonair-login.html', function(req, res) {
    res.sendFile(path.join(__dirname + '/voonair-login.html'));
});



app.get('/risk/fabric', (req, res) => {
   mykeys = icaRiskCache.keys();
   console.log( mykeys );
   icaRiskFabric();
   res.send('ICA RiskFabric Cache Updates')
})


app.get('/risk/threatDetect', (req, res) => {

   mykeys = cloudsocRiskCache.keys();
   console.log( mykeys );
   cloudsocThreatDetect();
   res.send('CloudSoc Threat-Detect Cache Updates')
})


app.listen(port,host, () => {
  console.log(`Example app listening at ${host}:${port}`)
})


icaRiskFabric();
setInterval(icaRiskFabric, 600000); // every 10 minutes

cloudsocThreatDetect();
setInterval(cloudsocThreatDetect, 600000); // every 10 minutes






function storeCloudSoc (data) {
//   console.log(data);
   console.log("PROCESSING CloudSoc DATA");

   const json = JSON.parse(data);

   if (json != undefined){
      for(var i=0; i<json.logs.length; i++)
      {
        var userId = (json.logs[i]).user;
//        console.log(" - USER - ", userId," - SCORE - ", (json.logs[i]).threat_score);
        cloudsocRiskCache.set(userId,(json.logs[i]));
      }
   }
}



function storeICA (data) {
//   console.log(data);
   console.log("PROCESSING ICA DATA");
   const json = JSON.parse(data);

   if (json != undefined){
       for(var i=0; i<json.Data.length; i++)
       {
//          var userId = (json.Data[i]).EntityName.match(/\(([^)]+)\)/)[1];
          var userId = "david.smith@bcm-demo110.com";
//          console.log(" - USER - ", userId ," - SCORE - ", (json.Data[i]).RiskInfo.Overview.RiskScore);
          icaRiskCache.set(userId,json.Data[i]);
       }
   }
}


/*
  Call ICA / RiskFabric to get user risk score
*/
function icaRiskFabric(){

  const http = require('http');

//  const baseUrl = 'icademoe3.eastus2.cloudapp.azure.com';
//  const targetHeaders = {'Authorization' : 'Basic aWNhYXBpdXNlcjpTeW1jMjAyMCE='};
  
  const baseUrl = 'riskfabric.iamdemo.broadcom.com';
  const targetUrl = '/restapi/search?query=david.smith&entityType=User&fields=RiskInfo&pageIndex=0&pageSize=500';
  const targetHeaders = {'Authorization' : 'Basic YXBpdXNlcjpTeW00bm93IQ=='};

  const myArgs = {
    host: baseUrl,
    path: targetUrl,
    headers: targetHeaders,
    method: "GET"
  };
  console.log('ICA RiskFabric - Request:');

  
  var connector = http.request(myArgs, (resp) => {
    console.log('Response from ICA RiskFabric - statusCode:', resp.statusCode);
  
    const respString = [];

    resp.on('data', (d) => {
        respString.push(d);
    });
    resp.on('end', function() {
        storeICA(Buffer.concat(respString).toString('utf-8'));
    });
  }).end();

  connector.on('error', (e) => {
      console.log('Response from ICA RiskFabric - ERROR:');
      console.error(e);
  });

}



/*
  Call CloudSoc / ThreatDetect to get user risk score
*/
function cloudsocThreatDetect(){

  const https = require('https');

  const userId = 'david.smith@bcm-demo110.com';

  const baseUrl = 'api-vip.elastica.net';
//  const targetUrl = '/bcm-demo110com/api/admin/v1/logs/get/?app=Detect&subtype=threatscore&threat_score=0,99&user='+userId;
  const targetUrl = '/bcm-demo110com/api/admin/v1/logs/get/?app=Detect&subtype=threatscore&threat_score=0,99';
  const targetHeaders = {'Authorization' : 'Basic MjIzYjRiMThkODU3MTFlYThkNjIwMjc2YWRlOGNiZmI6Q1BGblN3U1JTZ2FoVXBEeExvbzNlOVgxU1FMMmpUYTJkQ29LRXVDanl1Zw==',
                          'X-Elastica-Dbname-Resolved':'True'};

  const myArgs = {
    host: baseUrl,
    path: targetUrl,
    headers: targetHeaders,
    method: "GET"
  };
  console.log('CloudSoc ThreatDetect - Request:');

  var connector = https.request(myArgs, (resp) => {
    console.log('Response from CloudSoc ThreatDetect - statusCode:', resp.statusCode);
//    resp.pipe(res);

    const respString = [];

    resp.on('data', (d) => {
        respString.push(d);
    });
    resp.on('end', function() {
        storeCloudSoc(Buffer.concat(respString).toString('utf-8'));
    });



  }).end();

  connector.on('error', (e) => {
      console.log('Response from CloudSoc ThreatDetect - ERROR:');
      console.error(e);
  });

}
