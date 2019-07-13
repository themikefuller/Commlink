'use strict';

function Commlink(crypto) {

  let commlink = {};

  if (typeof window !== 'undefined') {
    crypto = window.crypto || crypto;
  }

  const toHex = commlink.toHex = (byteArray) => {
    return Array.from(new Uint8Array(byteArray)).map(val => {
      return ('0' + val.toString(16)).slice(-2);
    }).join('');
  };

  const fromHex = commlink.fromHex = (str) => {
    let result = new Uint8Array(str.match(/.{0,2}/g).map(val => {
      return parseInt(val, 16);
    }));
    return result.slice(0, result.length - 1);
  };

  const encode = commlink.encode = (byteArray) => {
    return btoa(Array.from(new Uint8Array(byteArray)).map(val => {
      return String.fromCharCode(val);
    }).join('')).replace(/\+/g, '-').replace(/\//g, '_').replace(/\=/g, '');
  };

  const decode = commlink.decode = (str) => {
    return new Uint8Array(atob(str.replace(/\_/g, '/').replace(/\-/g, '+')).split('').map(val => {
      return val.charCodeAt(0);
    }));
  };

  const fromText = (string) => {
    return new Uint8Array(string.split('').map(val => {
      return val.charCodeAt(0);
    }));
  };

  const toText = (byteArray) => {
    return Array.from(new Uint8Array(byteArray)).map(val => {
      return String.fromCharCode(val);
    }).join('');
  };

  const combine = commlink.combine = (bitsA = [], bitsB = []) => {
    let A = bitsA;
    let B = bitsB;
    if (typeof bitsA === 'string') {
      A = decode(bitsA);
    }
    if (typeof bitsB === 'string') {
      B = decode(bitsB);
    }
    let a = new Uint8Array(A);
    let b = new Uint8Array(B);
    let c = new Uint8Array(a.length + b.length);
    c.set(a);
    c.set(b, a.length);
    return c;
  };

  const random = commlink.random = (size) => {
    return crypto.getRandomValues(new Uint8Array(size));
  };

  const createECDH = commlink.createECDH = async (curve = "P-256") => {
    let DH = await crypto.subtle.generateKey({
      "name": "ECDH",
      "namedCurve": curve
    }, true, ['deriveBits']);
    let pub = await crypto.subtle.exportKey('raw', DH.publicKey);
    let key = encode(await crypto.subtle.exportKey('pkcs8', DH.privateKey));
    return {
      "pub": encode(pub),
      "key": key
    };
  };

  const createECDSA = commlink.createECDSA = async (curve = "P-256") => {
    let user = await crypto.subtle.generateKey({
      "name": "ECDSA",
      "namedCurve": curve
    }, true, ['sign', 'verify']);
    let pub = await crypto.subtle.exportKey('raw', user.publicKey);
    let key = encode(await crypto.subtle.exportKey('pkcs8', user.privateKey));
    return {
      "pub": encode(pub),
      "key": key
    };
  };

  const ecdsaSign = commlink.ecdsaSign = commlink.sign = async (key, msg, curve = "P-256") => {
    let message = msg.toString();
    let signKey = await crypto.subtle.importKey('pkcs8', decode(key), {
      "name": "ECDSA",
      "namedCurve": curve
    }, false, ['sign']);
    let sig = await crypto.subtle.sign({
      "name": "ECDSA",
      "hash": "sha-256"
    }, signKey, fromText(message));
    return encode(sig);
  };

  const ecdsaVerify = commlink.ecdsaVerify = commlink.verify = async (pub, sig, msg, curve = "P-256") => {
    let message = msg.toString();
    let verifyKey = await crypto.subtle.importKey('raw', decode(pub), {
      "name": "ECDSA",
      "namedCurve": curve
    }, false, ['verify']);
    let verified = await crypto.subtle.verify({
      "name": "ECDSA",
      "hash": "sha-256"
    }, verifyKey, decode(sig), fromText(message));
    return verified;
  };

  const hmacSign = commlink.hmacSign = async (bits, msg) => {
    let message = msg.toString();
    let hmacKey = await crypto.subtle.importKey('raw', bits, {
      "name": "HMAC",
      "hash": "SHA-256"
    }, false, ['sign']);
    let sig = await crypto.subtle.sign({
      "name": "HMAC",
      "hash": "SHA-256"
    }, hmacKey, fromText(message));
    return encode(sig);
  };

  const hmacVerify = commlink.hmacVerify = async (bits, sig, msg) => {
    let message = msg.toString();
    let verifyKey = await crypto.subtle.importKey('raw', bits, {
      "name": "HMAC",
      "hash": "SHA-256"
    }, false, ['verify']);
    let verified = await crypto.subtle.verify({
      "name": "HMAC",
      "hash": "sha-256"
    }, verifyKey, decode(sig), fromText(message));
    return verified;
  };

  const digest = commlink.digest = async (bits, hashAlg = "SHA-256") => {
    let digest = await crypto.subtle.digest({
      "name": hashAlg
    }, bits);
    return toHex(digest);
  };

  const pbkdf2 = commlink.pbkdf2 = async (bits, salt, iterations = 1, size = 256, hashAlg = "SHA-256") => {

    let key = await crypto.subtle.importKey('raw', bits, {
      "name": "PBKDF2"
    }, false, ['deriveBits']);

    let result = await crypto.subtle.deriveBits({
      "name": "PBKDF2",
      "salt": salt,
      "iterations": iterations,
      "hash": hashAlg
    }, key, size);
    return encode(result);

  };


  const hkdf = commlink.hkdf = async (bits, salt, info, size = 256, hashAlg = "SHA-256") => {

    let key = await crypto.subtle.importKey('raw', bits, {
      "name": "hkdf"
    }, false, ['deriveBits']);

    let result = await crypto.subtle.deriveBits({
      "name": "hkdf",
      "salt": salt,
      "info": info,
      "hash": hashAlg
    }, key, size);
    return encode(result);

  };

  const ecdh = commlink.ecdh = async (key, pub, curve = "P-256", size = 256) => {

    let pubKey = await crypto.subtle.importKey('raw', decode(pub), {
      "name": "ECDH",
      "namedCurve": curve
    }, true, []);

    let privateKey = await crypto.subtle.importKey('pkcs8', decode(key), {
      "name": "ECDH",
      "namedCurve": curve
    }, true, ['deriveBits']);

    let shared = await crypto.subtle.deriveBits({
      "name": "ECDH",
      "public": pubKey
    }, privateKey, size);

    let bits = encode(shared);

    return bits;

  };

  const encrypt = commlink.encrypt = async (message, bits, AD = null) => {
    let key = await crypto.subtle.importKey('raw', bits, {
      "name": "AES-GCM"
    }, false, ['encrypt']);
    let iv = random(12);
    let msg = fromText(message);
    let cipher = await crypto.subtle.encrypt({
      "name": "AES-GCM",
      "iv": iv,
      "additionalData": AD || fromText('')
    }, key, msg);
    return encode(iv) + '.' + encode(cipher);
  };

  const decrypt = commlink.decrypt = async (ciphertext = "", bits, AD = null) => {
    let key = await crypto.subtle.importKey('raw', bits, {
      "name": "AES-GCM"
    }, false, ['decrypt']);
    let iv = decode(ciphertext.split('.')[0]);
    let cipher = decode(ciphertext.split('.')[1]);
    let decrypted = await crypto.subtle.decrypt({
      "name": "AES-GCM",
      "iv": iv,
      "additionalData": AD || fromText('')
    }, key, cipher).catch(err => {
      throw({"message":"Failed to decrypt message.", "error":err});
    });
    return toText(decrypted);
  };

  const passwordEncrypt = commlink.passwordEncrypt = async (message, password = "", iterations = 100000) => {
    let salt = random(32);
    let keyBits = await pbkdf2(fromText(password), salt, iterations, 256);
    let encrypted = await encrypt(message, decode(keyBits));
    return encode(fromText(iterations.toString())) + '.' + encode(salt) + '.' + encrypted;
  };

  const passwordDecrypt = commlink.passwordDecrypt = async (ciphertext = "", password = "") => {
    let iterations = toText(decode(ciphertext.split('.')[0]));
    let salt = ciphertext.split('.')[1];
    let keyBits = await pbkdf2(fromText(password), decode(salt), iterations, 256);
    let encrypted = ciphertext.split('.').slice(2).join('.');
    let decrypted = await decrypt(encrypted, decode(keyBits));
    return decrypted;
  };

  return commlink;

}

if (typeof module !== 'undefined' && module && module.exports) {
  module.exports = Commlink;
}
