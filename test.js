'use strict';

const path = require('path');
const Commlink = require(__dirname + path.sep + 'index.js');
const comm = Commlink();
const commlink = comm;

async function Test(params={}) {

    let alice = {};
    alice.idk = await commlink.createECDSA();
    alice.spk = await commlink.createECDH();
    alice.sig = await commlink.sign(alice.idk.key, alice.spk.pub);
    alice.card = {
      "idk":alice.idk.pub,
      "spk":alice.spk.pub,
      "sig":alice.sig
    };

    let bob = {};
    bob.idk = await commlink.createECDSA();
    bob.spk = await commlink.createECDH();
    bob.sig = await commlink.sign(bob.idk.key, bob.spk.pub);
    bob.card = {
      "idk":bob.idk.pub,
      "spk":bob.spk.pub,
      "sig":bob.sig
    };

    alice.card.verified = await commlink.verify(alice.card.idk, alice.card.sig, alice.card.spk);
    bob.card.verified = await commlink.verify(bob.card.idk, bob.card.sig, bob.card.spk);

    alice.sharedKey = await commlink.ecdh(alice.spk.key, bob.card.spk);
    bob.sharedKey = await commlink.ecdh(bob.spk.key, alice.card.spk);

    alice.encrypted = await commlink.encrypt("Hello Bob!", comm.decode(alice.sharedKey));
    bob.decrypted = await commlink.decrypt(alice.encrypted, comm.decode(bob.sharedKey));

    return {alice, bob};

}

Test({}).then(console.log).catch(console.log);
