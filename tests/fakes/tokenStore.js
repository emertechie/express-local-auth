var _ = require('lodash');

function FakeTokenStore() {
    this.tokens = [];
    this.lastId = 0;
}

FakeTokenStore.prototype.add = function(tokenDetails, callback) {
    var cloned = clone(tokenDetails);
    cloned.tokenId = 'Token#' + (++this.lastId);
    this.tokens.push(cloned);
    callback(null, cloned);
};

FakeTokenStore.prototype.removeByEmail = function(email, callback) {
    _.remove(this.tokens, function(token) {
        return token.email === email;
    });
    callback(null);
};

FakeTokenStore.prototype.findByToken = function(token, callback) {
    var found = _.find(this.tokens, function(token) {
        return token.token === token;
    });
    callback(null, found);
};

function clone(obj) {
    return JSON.parse(JSON.stringify(obj));
}

module.exports = FakeTokenStore;