var _ = require('lodash');

function FakeTokenStore() {
    this.tokens = [];
    this.lastId = 0;
}

FakeTokenStore.prototype.add = function(tokenDetails, callback) {
    var cloned = cloneToken(tokenDetails);
    cloned.tokenId = 'Token#' + (++this.lastId);
    this.tokens.push(cloned);
    callback(null);
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

function cloneToken(tokenDetails) {
    var parsed = _.clone(tokenDetails);
    parsed.expiry = new Date(parsed.expiry);
    return parsed;
}

module.exports = FakeTokenStore;