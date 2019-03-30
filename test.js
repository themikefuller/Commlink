'use strict';

const path = require('path');
const Commlink = require(__dirname + path.sep + 'index.js');
const comm = Commlink();

let params1 = {"chainAlg":"pbkdf2"};
let params2 = {"chainAlg":"hkdf"};

comm.test(params1).then(console.log).catch(console.log);
// This test fails in nginx currently. The crypto package does not support hkdf
// comm.test(params2).then(console.log).catch(console.log);
