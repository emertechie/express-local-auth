var _ = require('lodash');

function FakeUserStore() {
    this.users = [];
}

FakeUserStore.prototype.add = function(userDetails, callback) {
    var user = clone(userDetails);
    user.userId = this.fakeUserId || ('User#' + (this.users.length + 1));
    this.users.push(user);
    callback(null, user);
};

FakeUserStore.prototype.remove = function(userId, callback) {
    _.remove(this.users, function(user) {
        return user.userId === userId;
    });
    callback(null);
};

FakeUserStore.prototype.findByEmail = function(email, callback) {
    var found = _.find(this.users, function(user) {
        return user.email === email;
    });
    callback(null, found);
};

function clone(obj) {
    return JSON.parse(JSON.stringify(obj));
}

module.exports = FakeUserStore;