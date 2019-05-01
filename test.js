'use strict';

const path = require('path');
const Commlink = require(__dirname + path.sep + 'index.js');
const comm = Commlink();

comm.test({}).then(console.log).catch(console.log);
