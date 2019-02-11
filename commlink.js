'use strict';

function Commlink(crypto) {

  let commlink = {};

  if (typeof window !== 'undefined') {
    crypto = window.crypto || crypto;
  }

  commlink.toHex = (byteArray) => {
    return Array.from(new Uint8Array(byteArray)).map(val=>{
      return ('00' + val.toString(16)).slice(-2);
    }).join('');
  };

  commlink.fromHex = (str) => {
    return new Uint8Array(str.match(/.{0,2}/g).map(val=>{
      return parseInt(val,16);
    }));
  };

  commlink.toB64 = (byteArray) => {
    return btoa(Array.from(new Uint8Array(byteArray)).map(val => {
      return String.fromCharCode(val);
    }).join('')).replace(/\+/g, '-').replace(/\//g, '_').replace(/\=/g, '');
  };

  commlink.fromB64 = (str) => {
    return new Uint8Array(atob(str.replace(/\_/g,'/').replace(/\-/g,'+')).split('').map(val=>{
      return val.charCodeAt(0);
    }));
  };

  commlink.textEncoder = (str) => {
    return new Uint8Array(str.split('').map(val=>{
      return val.charCodeAt(0);
    }));
  };

  commlink.textDecoder = (bits) => {
    return Array.from(new Uint8Array(bits)).map(val=>{
      return String.fromCharCode(val);
    }).join('');
  };

  commlink.combine = (bitsA=[], bitsB=[]) => {
    let A = bitsA;
    let B = bitsB;
    if (typeof bitsA === 'string') {
      A = commlink.decode(bitsA);
    }
    if (typeof bitsB === 'string') {
      B = commlink.decode(bitsB);
    }
    let a = new Uint8Array(A);
    let b = new Uint8Array(B);
    let c = new Uint8Array(a.length + b.length);
    c.set(a);
    c.set(b,a.length);
    return c;
  };

  commlink.fromPassword = commlink.fromText = (str) => {
    return commlink.textEncoder(str);
  };

  commlink.encode = commlink.toB64;
  commlink.decode = commlink.fromB64;

  commlink.encrypt = async (msg = null, keyBits = null, iterations = 100000) => {
    let message = JSON.stringify(msg);
    let data = commlink.textEncoder(message);
    let salt = crypto.getRandomValues(new Uint8Array(32));
    let key = await crypto.subtle.importKey('raw', keyBits, {"name":"PBKDF2"}, false, ['deriveBits']);
    let secret = await crypto.subtle.deriveBits({"name":"PBKDF2","salt":salt,"hash":"sha-256", "iterations":parseInt(iterations)}, key, 512);
    let iv = secret.slice(0,12);
    let secretKey = await crypto.subtle.importKey('raw', secret.slice(32, 64), {"name":"AES-GCM"}, false, ['encrypt']);
    let encrypted = await crypto.subtle.encrypt({"name":"AES-GCM", "iv":iv}, secretKey, data);
    let it = commlink.textEncoder(iterations.toString());
    return  commlink.toB64(it) + '.' + commlink.toB64(salt) + '.' +  commlink.toB64(encrypted);
  };

  commlink.decrypt = async (payload, keyBits) => {
    let parts = payload.split('.');
    let iterations = parseInt(commlink.textDecoder(commlink.fromB64(parts[0])));
    let salt = commlink.fromB64(parts[1]);
    let data = commlink.fromB64(parts[2]);
    let key = await crypto.subtle.importKey('raw', keyBits, {"name":"PBKDF2"}, false, ['deriveBits']);
    let secret = await crypto.subtle.deriveBits({"name":"PBKDF2","salt":salt,"hash":"sha-256", "iterations":iterations}, key, 512);
    let iv = secret.slice(0,12);
    let secretKey = await crypto.subtle.importKey('raw', secret.slice(32, 64), {"name":"AES-GCM"}, false, ['decrypt']);
    let decrypted = await crypto.subtle.decrypt({"name":"AES-GCM", "iv":iv}, secretKey, data).catch(err => {
      return false;
    });
    if (decrypted) {
      return JSON.parse(commlink.textDecoder(decrypted));
    } else {
      return Promise.reject({"message":"Failed to decrypt message."});
    }
  };

  commlink.getId = async (encodedBits) => {
    return commlink.toHex(await crypto.subtle.digest("SHA-256", commlink.decode(encodedBits))).slice(-16);    
  };

  commlink.createECDH = async (curve="P-256") => {
    let DH = await crypto.subtle.generateKey({
      "name": "ECDH",
      "namedCurve": curve
    },true,['deriveBits']);
    let pub = await crypto.subtle.exportKey('raw', DH.publicKey);
    let key = commlink.encode(await crypto.subtle.exportKey('pkcs8', DH.privateKey));
    return {"id": await commlink.getId(commlink.encode(pub)), "pub": commlink.encode(pub), key};
  };

  commlink.createECDSA = async (curve="P-256") => {
    let user = await crypto.subtle.generateKey({
      "name":"ECDSA",
      "namedCurve":curve
    },true,['sign','verify']);
    let pub = await crypto.subtle.exportKey('raw', user.publicKey);
    let key = commlink.encode(await crypto.subtle.exportKey('pkcs8', user.privateKey));
    return {"id": await commlink.getId(commlink.encode(pub)), "pub": commlink.encode(pub), key};
  };

  commlink.sign = async (key, msg, curve="P-256") => {
    let message = JSON.stringify(msg);
    let signKey = await crypto.subtle.importKey('pkcs8', commlink.decode(key), {"name":"ECDSA","namedCurve":curve}, false, ['sign']);
    let sig = await crypto.subtle.sign({"name":"ECDSA","hash":"sha-256"}, signKey, commlink.textEncoder(message));
    return commlink.encode(sig);
  };

  commlink.verify = async (pub, sig, msg, curve="P-256") => {
    let message = JSON.stringify(msg);
    let verifyKey = await crypto.subtle.importKey('raw', commlink.decode(pub), {"name":"ECDSA","namedCurve":curve}, false, ['verify']);
    let verified = await crypto.subtle.verify({"name":"ECDSA","hash":"sha-256"}, verifyKey, commlink.decode(sig), commlink.textEncoder(message));
    return verified;
  };

  commlink.hmacSign = async (key, msg) => {
    let message = JSON.stringify(msg);
    let hmacKey = await crypto.subtle.importKey('raw', commlink.decode(key), {"name":"HMAC", "hash":"SHA-256"}, false, ['sign']);
    let sig = await crypto.subtle.sign({"name":"HMAC","hash":"SHA-256"}, hmacKey, commlink.textEncoder(message));
    return commlink.encode(sig);
  };

  commlink.hmacVerify = async (key, sig, msg) => {
    let message = JSON.stringify(msg);
    let verifyKey = await crypto.subtle.importKey('raw', commlink.decode(key), {"name":"HMAC","hash":"SHA-256"}, false, ['verify']);
    let verified = await crypto.subtle.verify({"name":"HMAC","hash":"sha-256"}, verifyKey, commlink.decode(sig), commlink.textEncoder(message));
    return verified;
  };

  commlink.createUser = async (curve="P-256") => {
    let user = await commlink.createECDH();
    user.sig = await commlink.sign(user.key, user.pub);
    return user;
  };

  commlink.link = async (key, pub, curve="P-256", size=256) => {

    let pubKey = await crypto.subtle.importKey('raw', commlink.decode(pub),{
      "name":"ECDH",
      "namedCurve": curve
    },true,[]);

    let privateKey = await crypto.subtle.importKey('pkcs8', commlink.decode(key), {
      "name":"ECDH",
      "namedCurve": curve
    },true,['deriveBits']);

    let shared = await crypto.subtle.deriveBits({
      "name":"ECDH",
      "public":pubKey
    },privateKey,size);

    let link = {};
    link.keyBits = commlink.encode(shared);
    link.id = await commlink.getId(link.keyBits);

    return link;

  };

  commlink.sendmsg = async (link, message, iterations=100000) => {
    let keyBits = commlink.decode(link.keyBits);
    let msg = await commlink.encrypt(message, keyBits, parseInt(iterations));
    let id = commlink.encode(await crypto.subtle.digest('SHA-256', new Uint8Array(Array.from(commlink.textEncoder(msg)).concat(new Uint8Array(keyBits)))));
    return {"link":link.id,"id":await commlink.getId(id),"encrypted":msg};
  };

  commlink.readmsg = async (link, payload) => {
    let keyBits = commlink.decode(link.keyBits);
    let id = await commlink.getId(commlink.encode(await crypto.subtle.digest('SHA-256', new Uint8Array(Array.from(commlink.textEncoder(payload.encrypted)).concat(new Uint8Array(keyBits))))));
    let message = await commlink.decrypt(payload.encrypted,keyBits);
    return {"link":link.id,"id":id, "decrypted":message, "idVerified":id===payload.id};
  };

  commlink.exporter = async (item, password, iterations = 100000) => {
    let encrypted = await commlink.encrypt(JSON.stringify(item),commlink.textEncoder(password), iterations);
    return encrypted;
  };

  commlink.importer = async (encrypted, password) => {
    let decrypted = await commlink.decrypt(encrypted,commlink.textEncoder(password));
    return JSON.parse(decrypted);
  };

  commlink.getPublic = async (entity={}) => {

    if (!entity || typeof entity !== 'object') {
      entity = {};
    }

    let result = {};

    if (entity.pub) {
      result.pub = entity.pub;
    }

    if (entity.sig) {
      result.sig = entity.sig;
    }

    if (entity.id) {
      result.id = entity.id;
    }

    return result;

  };

  commlink.stretch = async (bits=null, size=512, iterations=100000) => {
    return new Promise(async (resolve,reject) => {
      let keyBits = bits;
      if (typeof bits === 'string') {
        keyBits = commlink.decode(bits);
      }
      let salt = keyBits.slice(0, keyBits.length / 2);
      let kBits = keyBits.slice(keyBits.length / 2);
      let key = await crypto.subtle.importKey('raw', kBits, {"name":"PBKDF2"}, false, ['deriveBits']); 
      let stretched = await crypto.subtle.deriveBits({
        "name":"PBKDF2",
        "salt": salt,
        "hash":"sha-256",
        "iterations": parseInt(iterations)
      }, key, size);
      let id = await commlink.getId(commlink.encode(new Uint8Array(stretched)));
      resolve({id, "keyBits":commlink.encode(stretched)});
    });
  };

  commlink.createGrid = async (bitsA=[], bitsB=[], size=10, iterations=100000) => {
    return new Promise(async (resolve,reject) => {

      let combined = commlink.combine(bitsA, bitsB);
      let stretched = commlink.decode((await commlink.stretch(combined, 1024, iterations)).keyBits);
      let salt = stretched.slice(0, stretched.length / 2);
      let keyBits = stretched.slice(stretched.length / 2);

      let key = await crypto.subtle.importKey('raw', keyBits,{"name":"PBKDF2"}, false, ['deriveBits']);
      let bits = await crypto.subtle.deriveBits({"name":"PBKDF2","salt":salt,"hash":"sha-256","iterations":parseInt(iterations)},key, 512 * size);
      let arrayBits = Array.from(new Uint8Array(bits));

      let grid = [];

      let next = async (x) => {
        let cell = arrayBits.splice(0,64);
        let id = await commlink.getId(commlink.encode(cell));
        grid.push({"id":id, "keyBits":commlink.encode(cell)});
        done(x);
      };

      let done = (x) => {
        if (x > 0) {
          let y = x - 1;
          next(y);
        } else {
          return resolve(grid);
        }
      };

      next(size - 1);

    });
  };

  commlink.test = async (params={"password":"password","curve":"P-256","size":256,"iterations":100000}) => {

    let comm = commlink;

    let {password, curve, size, iterations} = params;
    let alice = {};

    alice.params = params;
    alice.user = await comm.createECDSA(curve);
    alice.user.sig = await comm.sign(alice.user.key, alice.user.pub, curve);
    alice.user.verified = await comm.verify(alice.user.pub, alice.user.sig, alice.user.pub, curve);

    alice.inbox = await comm.createECDH(curve);
    alice.inbox.sig = await comm.sign(alice.user.key, alice.inbox.pub, curve);
    alice.inbox.verified = await comm.verify(alice.user.pub, alice.inbox.sig, alice.inbox.pub, curve);

    alice.link = await comm.link(alice.inbox.key, alice.inbox.pub, curve, size);
    alice.grid = await comm.createGrid(alice.link.keyBits, alice.inbox.pub, 10, iterations);

    alice.pub = {
      "user": await comm.getPublic(alice.user),
      "inbox": await comm.getPublic(alice.inbox)
    };

    alice.encrypted = await comm.sendmsg(alice.grid[0], "hello world", iterations);
    alice.decrypted = await comm.readmsg(alice.grid[0], alice.encrypted);

    alice.exported = await comm.exporter(alice, password, iterations);
    alice.imported = await comm.importer(alice.exported, password);

    return alice;

  };

  commlink.testAliceAndBob = async () => {

    let comm = commlink;

    let alice = await comm.test();
    let bob = await comm.test();

    alice.prekey = await comm.createECDH();
    alice.prekey.sig = await comm.sign(alice.user.key, alice.prekey.pub);
    alice.pub.prekey = await comm.getPublic(alice.prekey);
    alice.pub.prekey.verify = await comm.verify(alice.pub.user.pub, alice.pub.prekey.sig, alice.pub.prekey.pub);

    bob.prekey = await comm.createECDH();
    bob.prekey.sig = await comm.sign(bob.user.key, bob.prekey.pub);
    bob.pub.prekey = await comm.getPublic(bob.prekey);
    bob.pub.prekey.verify = await comm.verify(bob.pub.user.pub, bob.pub.prekey.sig, bob.pub.prekey.pub);

    alice.contacts = {
      "bob":bob.pub
    };

    bob.contacts = {
      "alice":alice.pub
    };

    alice.contacts.bob.prelink = await comm.link(alice.prekey.key,alice.contacts.bob.prekey.pub);
    bob.contacts.alice.prelink = await comm.link(bob.prekey.key,bob.contacts.alice.prekey.pub);

    alice.contacts.bob.link = await comm.link(alice.inbox.key,alice.contacts.bob.inbox.pub);
    bob.contacts.alice.link = await comm.link(bob.inbox.key,bob.contacts.alice.inbox.pub);

    alice.contacts.bob.grid = {};
    bob.contacts.alice.grid = {};

    alice.contacts.bob.grid.main = await comm.createGrid(alice.contacts.bob.prelink.keyBits, alice.contacts.bob.link.keyBits, 11, 10000);
    bob.contacts.alice.grid.main = await comm.createGrid(bob.contacts.alice.prelink.keyBits, bob.contacts.alice.link.keyBits, 11, 10000);

    alice.contacts.bob.grid.send = await comm.createGrid(alice.contacts.bob.grid.main[0].keyBits, alice.contacts.bob.inbox.pub, 10, 10000);
    alice.contacts.bob.grid.recv = await comm.createGrid(alice.contacts.bob.grid.main[0].keyBits, alice.inbox.pub, 10, 10000);

    bob.contacts.alice.grid.send = await comm.createGrid(bob.contacts.alice.grid.main[0].keyBits, bob.contacts.alice.inbox.pub, 10, 10000);
    bob.contacts.alice.grid.recv = await comm.createGrid(bob.contacts.alice.grid.main[0].keyBits, bob.inbox.pub, 10, 10000);

    let toBob = await comm.sendmsg(alice.contacts.bob.grid.send[0], "Hello Bob!", 100000);
    let toAlice = await comm.sendmsg(bob.contacts.alice.grid.send[0], "Hello Alice!", 100000);

    let fromAlice = await comm.readmsg(bob.contacts.alice.grid.recv[0], toBob);
    let fromBob = await comm.readmsg(alice.contacts.bob.grid.recv[0], toAlice);

    return {
      alice, bob, fromAlice, fromBob, toAlice, toBob
    };

  };

  return commlink;

}

if (typeof module !== 'undefined' && module && module.exports) {
  module.exports = Commlink;
}
