module.exports = {
    loginPath: '/login',
    hash: function(unhashed, cb) {
        cb(null, 'hashed-' + unhashed);
    },
    verifyHash: function(unhashed, hashed, cb) {
        var matches = 'hashed-' + unhashed === hashed;
        return cb(null, matches);
    },
    markLoggedInAfterAuthentication: function(req, user, cb) {
        cb(null);
    },
    logOut: function(req, user, cb) {
        cb(null);
    }
};