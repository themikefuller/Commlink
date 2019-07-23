'use strict';

const path = require('path');
const Commlink = require(__dirname + path.sep + 'index.js');
const comm = Commlink();

async function Test(params={}) {

    let alice = {};
    alice.idk = await comm.createECDSA();
    alice.spk = await comm.createECDH();
    alice.sig = await comm.sign(alice.idk.key, alice.spk.pub);
    alice.card = {
      "idk":alice.idk.pub,
      "spk":alice.spk.pub,
      "sig":alice.sig
    };

    let bob = {};
    bob.idk = await comm.createECDSA();
    bob.spk = await comm.createECDH();
    bob.sig = await comm.sign(bob.idk.key, bob.spk.pub);
    bob.card = {
      "idk":bob.idk.pub,
      "spk":bob.spk.pub,
      "sig":bob.sig
    };

    alice.card.verified = await comm.verify(alice.card.idk, alice.card.sig, alice.card.spk);
    bob.card.verified = await comm.verify(bob.card.idk, bob.card.sig, bob.card.spk);

    alice.sharedKey = await comm.ecdh(alice.spk.key, bob.card.spk);
    bob.sharedKey = await comm.ecdh(bob.spk.key, alice.card.spk);

    alice.hashKey = await comm.hkdf(comm.decode(alice.sharedKey), new Uint8Array([0]), comm.fromText("Hash"), 256, "SHA-256");
    bob.hashKey = await comm.hkdf(comm.decode(bob.sharedKey), new Uint8Array([0]), comm.fromText("Hash"), 256, "SHA-256");

    alice.encrypted = await comm.encrypt("Hello Bob!", comm.decode(alice.sharedKey));
    bob.decrypted = await comm.decrypt(alice.encrypted, comm.decode(bob.sharedKey));

    return {alice, bob};

}

Test({}).then(console.log).catch(console.log);
