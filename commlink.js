'use strict';

function Commlink(crypto) {

  let commlink = {};

  if (typeof window !== 'undefined') {
    crypto = window.crypto || crypto;
  }

  commlink.crypto = crypto;

  const getSaltBits = (salt) => {
    let saltBits = new Uint8Array(32);
    if (salt) {
      if (typeof salt === 'string') {
        saltBits = commlink.fromText(salt);
      } else {
        saltBits = salt;
      }
    }
    return saltBits;
  };

  const getKeyBits = (bits) => {
    let keyBits = bits;
    if (typeof bits === 'string') {
      keyBits = commlink.decode(bits);
    }
    return keyBits;
  };

  commlink.toHex = (byteArray) => {
    return Array.from(new Uint8Array(byteArray)).map(val => {
      return ('0' + val.toString(16)).slice(-2);
    }).join('');
  };

  commlink.fromHex = (str) => {
    let result = new Uint8Array(str.match(/.{0,2}/g).map(val => {
      return parseInt(val, 16);
    }));
    return result.slice(0,result.length - 1);
  };

  commlink.encode = commlink.toB64 = (byteArray) => {
    return btoa(Array.from(new Uint8Array(byteArray)).map(val => {
      return String.fromCharCode(val);
    }).join('')).replace(/\+/g, '-').replace(/\//g, '_').replace(/\=/g, '');
  };

  commlink.decode = commlink.fromB64 = (str) => {
    return new Uint8Array(atob(str.replace(/\_/g, '/').replace(/\-/g, '+')).split('').map(val => {
      return val.charCodeAt(0);
    }));
  };

  commlink.fromText = (str) => {
    return textEncoder(str);
  };

  commlink.toText = (byteArray) => {
    return textDecoder(byteArray);
  };

  const textEncoder = (str) => {
    return new Uint8Array(str.split('').map(val => {
      return val.charCodeAt(0);
    }));
  };

  const textDecoder = (bits) => {
    return Array.from(new Uint8Array(bits)).map(val => {
      return String.fromCharCode(val);
    }).join('');
  };

  commlink.combine = (bitsA = [], bitsB = []) => {
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
    c.set(b, a.length);
    return c;
  };

  commlink.getId = async (encodedBits) => {
    return commlink.toHex(await crypto.subtle.digest("SHA-256", commlink.decode(encodedBits))).slice(-16);
  };

  commlink.getPublic = async (entity = {}) => {
    let result = {};
    if (entity.id) {
      result.id = entity.id;
    }
    if (entity.uid) {
      result.uid = entity.uid;
    }
    if (entity.pub) {
      result.pub = entity.pub;
    }
    if (entity.msg) {
      result.msg = entity.msg;
    }
    if (entity.sig) {
      result.sig = entity.sig;
    }
    return result;
  };

  commlink.random = (size) => {
    return crypto.getRandomValues(new Uint8Array(size));
  };

  commlink.randomNumber = (digits, asString = false) => {
    let num = commlink.random(digits * 2).join('').slice(0, digits);
    if (asString) {
      return num;
    } else {
      return parseInt(num);
    }
  };

  commlink.createECDH = async (curve = "P-256") => {
    let DH = await crypto.subtle.generateKey({
      "name": "ECDH",
      "namedCurve": curve
    }, true, ['deriveBits']);
    let pub = await crypto.subtle.exportKey('raw', DH.publicKey);
    let key = commlink.encode(await crypto.subtle.exportKey('pkcs8', DH.privateKey));
    let id = await commlink.getId(commlink.encode(pub));
    return {
      "id": id,
      "pub": commlink.encode(pub),
      "key": key
    };
  };

  commlink.createECDSA = async (curve = "P-256") => {
    let user = await crypto.subtle.generateKey({
      "name": "ECDSA",
      "namedCurve": curve
    }, true, ['sign', 'verify']);
    let pub = await crypto.subtle.exportKey('raw', user.publicKey);
    let key = commlink.encode(await crypto.subtle.exportKey('pkcs8', user.privateKey));
    let id = await commlink.getId(commlink.encode(pub));
    return {
      "id": id,
      "pub": commlink.encode(pub),
      "key": key
    };
  };

  commlink.createUser = async (curve="P-256") => {
    let user = await commlink.createECDSA(curve||"P-256");
    user.sig = await commlink.sign(user.key, user.pub);
    return user;
  };

  commlink.sign = async (key, msg, curve = "P-256") => {
    let message = JSON.stringify(msg);
    let signKey = await crypto.subtle.importKey('pkcs8', commlink.decode(key), {
      "name": "ECDSA",
      "namedCurve": curve
    }, false, ['sign']);
    let sig = await crypto.subtle.sign({
      "name": "ECDSA",
      "hash": "sha-256"
    }, signKey, textEncoder(message));
    return commlink.encode(sig);
  };

  commlink.verify = async (pub, sig, msg, curve = "P-256") => {
    let message = JSON.stringify(msg);
    let verifyKey = await crypto.subtle.importKey('raw', commlink.decode(pub), {
      "name": "ECDSA",
      "namedCurve": curve
    }, false, ['verify']);
    let verified = await crypto.subtle.verify({
      "name": "ECDSA",
      "hash": "sha-256"
    }, verifyKey, commlink.decode(sig), textEncoder(message));
    return verified;
  };

  commlink.hmacSign = async (key, msg) => {
    let message = JSON.stringify(msg);
    let hmacKey = await crypto.subtle.importKey('raw', commlink.decode(key), {
      "name": "HMAC",
      "hash": "SHA-256"
    }, false, ['sign']);
    let sig = await crypto.subtle.sign({
      "name": "HMAC",
      "hash": "SHA-256"
    }, hmacKey, textEncoder(message));
    return commlink.encode(sig);
  };

  commlink.hmacVerify = async (key, sig, msg) => {
    let message = JSON.stringify(msg);
    let verifyKey = await crypto.subtle.importKey('raw', commlink.decode(key), {
      "name": "HMAC",
      "hash": "SHA-256"
    }, false, ['verify']);
    let verified = await crypto.subtle.verify({
      "name": "HMAC",
      "hash": "sha-256"
    }, verifyKey, commlink.decode(sig), textEncoder(message));
    return verified;
  };

  commlink.pbkdf2 = async (bits, salt = null, size = 256, iterations = 1, hashAlg = "SHA-256") => {
    let keyBits = getKeyBits(bits);
    let saltBits = getSaltBits(salt);

    let key = await crypto.subtle.importKey('raw', keyBits, {
      "name": "PBKDF2"
    }, false, ['deriveBits']);

    let result = await crypto.subtle.deriveBits({
      "name": "PBKDF2",
      "salt": saltBits,
      "iterations": iterations,
      "hash": hashAlg
    }, key, size);
    return commlink.encode(result);
  };

  commlink.hkdf = async (bits, salt = null, info = "", size = 256, hashAlg = "SHA-256") => {
    let keyBits = getKeyBits(bits);
    let saltBits = getSaltBits(salt);
    let infoBits = commlink.fromText(info || "");

    let key = await crypto.subtle.importKey('raw', keyBits, {
      "name": "HKDF"
    }, false, ['deriveBits']);

    let result = await crypto.subtle.deriveBits({
      "name": "HKDF",
      "salt": saltBits,
      "info": infoBits,
      "hash": hashAlg
    }, key, size);

    return commlink.encode(result);

  };

  commlink.ecdh = async (key, pub, curve = "P-256", size = 256) => {

    let pubKey = await crypto.subtle.importKey('raw', commlink.decode(pub), {
      "name": "ECDH",
      "namedCurve": curve
    }, true, []);

    let privateKey = await crypto.subtle.importKey('pkcs8', commlink.decode(key), {
      "name": "ECDH",
      "namedCurve": curve
    }, true, ['deriveBits']);

    let shared = await crypto.subtle.deriveBits({
      "name": "ECDH",
      "public": pubKey
    }, privateKey, size);

    let bits = commlink.encode(shared);

    return bits;

  };

  commlink.link = async (key, pub, curve = "P-256", size = 256) => {

    let pubKey = await crypto.subtle.importKey('raw', commlink.decode(pub), {
      "name": "ECDH",
      "namedCurve": curve
    }, true, []);

    let privateKey = await crypto.subtle.importKey('pkcs8', commlink.decode(key), {
      "name": "ECDH",
      "namedCurve": curve
    }, true, ['deriveBits']);

    let shared = await crypto.subtle.deriveBits({
      "name": "ECDH",
      "public": pubKey
    }, privateKey, size);

    let bits = commlink.encode(shared);
    let id = await commlink.getId(bits);
    return {id, bits};

  };

  commlink.chain = async (bits, info = "", size = 10, alg = "hkdf") => {
    let keyBits = bits;
    if (typeof bits === 'string') {
      keyBits = commlink.decode(bits);
    }
    let chain = [];
    let dBits = null;
    if (alg === 'pbkdf2') {
      dBits = await commlink.pbkdf2(keyBits, commlink.fromText(info||""), 256 * parseInt(size));
    } else {
      dBits = await commlink.hkdf(keyBits, null, info || "", 256 * parseInt(size));
    }
    let arrayBits = Array.from(commlink.decode(dBits));
    for (let i = 0; i < size; i++) {
      let cell = arrayBits.splice(0, 32);
      let id = await commlink.getId(commlink.encode(cell));
      chain.push(commlink.encode(cell));
    }
    return chain;
  };

  commlink.encrypt = async (msg = {}, bits = null, iterations = 100000) => {
    let keyBits = getKeyBits(bits);
    let message = JSON.stringify(msg);
    let data = textEncoder(message);
    let salt = crypto.getRandomValues(new Uint8Array(32));

    let secret = commlink.decode(await commlink.pbkdf2(keyBits, salt, 512, parseInt(iterations)));

    let iv = secret.slice(0, 12);

    let secretKey = await crypto.subtle.importKey('raw', secret.slice(32, 64), {
      "name": "AES-GCM"
    }, false, ['encrypt']);

    let encrypted = await crypto.subtle.encrypt({
      "name": "AES-GCM",
      "iv": iv
    }, secretKey, data);

    let it = textEncoder(iterations.toString());

    return commlink.toB64(it) + '.' + commlink.toB64(salt) + '.' + commlink.toB64(encrypted);

  };

  commlink.decrypt = async (payload = null, bits = null) => {
    let keyBits = getKeyBits(bits);
    let parts = payload.split('.');
    let iterations = parseInt(textDecoder(commlink.fromB64(parts[0])));
    let salt = commlink.fromB64(parts[1]);
    let data = commlink.fromB64(parts[2]);

    let secret = commlink.decode(await commlink.pbkdf2(keyBits, salt, 512, iterations));

    let iv = secret.slice(0, 12);

    let secretKey = await crypto.subtle.importKey('raw', secret.slice(32, 64), {
      "name": "AES-GCM"
    }, false, ['decrypt']);

    let decrypted = await crypto.subtle.decrypt({
      "name": "AES-GCM",
      "iv": iv
    }, secretKey, data).catch(err => {
      return false;
    });

    if (decrypted) {
      return JSON.parse(textDecoder(decrypted));
    } else {
      return Promise.reject({
        "message": "Failed to decrypt message."
      });
    }

  };

  commlink.exporter = async (item, password, iterations = 100000) => {
    let encrypted = await commlink.encrypt(JSON.stringify(item), textEncoder(password), iterations);
    return encrypted;
  };

  commlink.importer = async (encrypted, password) => {
    let decrypted = await commlink.decrypt(encrypted, textEncoder(password));
    return JSON.parse(decrypted);
  };

  commlink.test = async (params = {}) => {

    let {
      chainAlg,
      chainSize,
      iterations
    } = params;

    let alice = {};
    alice.id = await commlink.createUser();
    alice.pub = await commlink.getPublic(alice.id);
    

    let bob = {};
    bob.id = await commlink.createUser();
    bob.pub = await commlink.getPublic(bob.id);

    alice.link = await commlink.ecdh(alice.id.key, bob.pub.pub);
    bob.link = await commlink.ecdh(bob.id.key, alice.pub.pub);
    let link = await commlink.link(bob.id.key, alice.pub.pub);

    alice.bits = await commlink.pbkdf2(alice.link, null, 256, iterations || 1);
    bob.bits = await commlink.pbkdf2(bob.link, null, 256, iterations || 1);

    alice.chain = await commlink.chain(alice.bits, "", chainSize || 10, chainAlg || null);
    bob.chain = await commlink.chain(bob.bits, "", chainSize || 10, chainAlg || null);

    alice.toBob = await commlink.encrypt("Hello, Bob. I'm Alice.", alice.chain[0], iterations || 1);
    bob.toAlice = await commlink.encrypt("Hi, Alice. I am Bob.", bob.chain[0], iterations || 1);

    alice.fromBob = await commlink.decrypt(bob.toAlice, alice.chain[0]);
    bob.fromAlice = await commlink.decrypt(alice.toBob, bob.chain[0]);

    alice.exported = await commlink.exporter(alice, 'alicepassword', iterations || 1);
    bob.exported = await commlink.exporter(bob, 'bobpassword', iterations || 1);

    alice.imported = await commlink.importer(alice.exported, 'alicepassword');
    bob.imported = await commlink.importer(bob.exported, 'bobpassword');

    return {
      alice,
      bob,
      link
    };

  };

  return commlink;

}

if (typeof module !== 'undefined' && module && module.exports) {
  module.exports = Commlink;
}
