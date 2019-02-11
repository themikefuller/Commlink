'use strict';

const path = require('path');
const Commlink = require(__dirname + path.sep + 'index.js');
const comm = Commlink();

comm.testAliceAndBob().then(console.log).catch(console.log);
