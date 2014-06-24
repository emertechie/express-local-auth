var _ = require('lodash');

function FakeUserStore() {
    this.users = [];
}

FakeUserStore.prototype.add = function(userDetails, callback) {
    if (this.simulatedError) {
        callback(simulatedError, null);
    } else {
        var user = clone(userDetails);
        user.userId = this.fakeUserId || ('User#' + (this.users.length + 1));
        this.users.push(user);
        callback(null, user);
    }
};

FakeUserStore.prototype.remove = function(userId, callback) {
    _.remove(this.users, function(user) {
        return user.userId === userId;
    });
    callback(null);
};

function clone(obj) {
    return JSON.parse(JSON.stringify(obj));
}

module.exports = FakeUserStore;