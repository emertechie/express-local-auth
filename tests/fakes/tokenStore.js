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

FakeTokenStore.prototype.removeAllByEmail = function(email, callback) {
    _.remove(this.tokens, function(token) {
        return token.email === email;
    });
    callback(null);
};

FakeTokenStore.prototype.findByEmail = function(email, callback) {
    var found = _.find(this.tokens, function(tokenDetails) {
        return tokenDetails.email === email;
    });
    callback(null, found);
};

function clone(tokenDetails) {
    var parsed = JSON.parse(JSON.stringify(tokenDetails));
    parsed.expiry = new Date(parsed.expiry);
    return parsed;
}

module.exports = FakeTokenStore;