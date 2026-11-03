// força qualquer listen() a usar 127.0.0.1 (laboratório só local)
const net=require('net');const o=net.Server.prototype.listen;
net.Server.prototype.listen=function(...a){if(typeof a[0]==='number'||typeof a[0]==='string'&&/^\d+$/.test(a[0])){const p=+a[0];const cb=a.find(x=>typeof x==='function');return o.call(this,p,'127.0.0.1',cb)}if(a[0]&&typeof a[0]==='object'&&!a[0].path){a[0].host='127.0.0.1'}return o.apply(this,a)};
