'use strict';

const WebCrypto = require("node-webcrypto-ossl");
const webcrypto = new WebCrypto();

const path = require('path');
const Commlink = require(__dirname + path.sep + 'commlink.js');

const Comm = () => {
  return Commlink(webcrypto);
};

module.exports = Comm;
