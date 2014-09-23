var _ = require('lodash');

function FakeUserStore() {
    this.users = [];
}

FakeUserStore.prototype.add = function(userDetails, callback) {
    var userAlreadyExists = !!_findByEmailSync.call(this, userDetails.email);
    if (userAlreadyExists) {
        return callback(null, userAlreadyExists);
    }

    var user = clone(userDetails);
    user.id = this.fakeUserId || ('User#' + (this.users.length + 1));
    this.users.push(user);
    callback(null, userAlreadyExists, user);
};

FakeUserStore.prototype.get = function(userId, cb) {
    var user = _.find(this.users, function(user) {
        return user.id === userId;
    });
    cb(null, user);
};

FakeUserStore.prototype.update = function(user, callback) {
    var userIdx = _.findIndex(this.users, function(candidateUser) {
        return candidateUser.id === user.userId;
    });

    if (userIdx === -1) {
        return callback(null, null);
    }

    var updated = clone(user);
    this.users[userIdx] = updated;
    return callback(null, updated);
};

FakeUserStore.prototype.remove = function(userId, callback) {
    _.remove(this.users, function(user) {
        return user.id === userId;
    });
    callback(null);
};

FakeUserStore.prototype.findByEmail = function(email, callback) {
    var found = _findByEmailSync.call(this, email);
    callback(null, found);
};

function _findByEmailSync(email) {
    return _.find(this.users, function(user) {
        return user.email === email;
    });
}

function clone(obj) {
    return JSON.parse(JSON.stringify(obj));
}

module.exports = FakeUserStore;