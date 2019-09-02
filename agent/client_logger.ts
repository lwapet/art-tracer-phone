
import { log } from "./logger";
var net = require('net');
/*
In the node.js intro tutorial (http://nodejs.org/), they show a basic tcp 
server, but for some reason omit a client connecting to it.  I added an 
example at the bottom.
Save the following server in example.js:
*/
/*
var net = require('net');

var server = net.createServer(function(socket: any) {
	socket.write('Echo server\r\n');
	socket.pipe(socket);
});

server.listen(1337, '127.0.0.1');
*/
/*
And connect with a tcp client from the command line using netcat, the *nix 
utility for reading and writing across tcp/udp network connections.  I've only 
used it for debugging myself.
$ netcat 127.0.0.1 1337
You should see:
> Echo server
*/

/* Or use this example tcp client written in node.js.  (Originated with 
example code from 
http://www.hacksparrow.com/tcp-socket-programming-in-node-js.html.) */




export function test_client(){
    var client = new net.Socket();
    log("--> Connecting to OdileGUI server");
    client.setTimeout(1000);
    client.setEncoding('utf8');

    client.connect(10000, '127.0.0.1', function() {
        log('Connected');
        client.write('Hello Hello');
        client.end();
        log('data sent');
    });
   

    // When receive server send back data.
    client.on('data', function (data: any) {
        log('Server return data : ' + data);
    });

    // When connection disconnected.
    client.on('end',function () {
        log('Client socket disconnect. ');
    });

    client.on('timeout', function () {
        log('Client connection timeout. ');
    });

    client.on('error', function (err: any) {
        log(JSON.stringify(err));
    });

    //log("--> waiting for  server to receive data");
    /*client.on('data', function(data: any) {
        log('Received: ' + data);
        client.destroy(); // kill client after server's response

    });*/
    
    client.on('close', function() {
        log('Connection closed');
    });
}


export function send_log(log_to_send: String){
    var client = new net.Socket();
    log("--> Connecting to OdileGUI server");
    client.setTimeout(1000);
    client.setEncoding('utf8');



    client.connect(10000, '127.0.0.1', function() {
        log('Connected');
        client.write('--->' + log_to_send);
        client.end();
        log('data sent');
    });
   

    // When receive server send back data.
    client.on('data', function (data: any) {
        log('Server return data : ' + data);
    });

    // When connection disconnected.
    client.on('end',function () {
        log('Client socket disconnect. ');
    });

    client.on('timeout', function () {
        log('Client connection timeout. ');
    });

    client.on('error', function (err: any) {
        log(JSON.stringify(err));
    });

    //log("--> waiting for  server to receive data");
    /*client.on('data', function(data: any) {
        log('Received: ' + data);
        client.destroy(); // kill client after server's response

    });*/
    
    client.on('close', function() {
        log('Connection closed');
    });
}
