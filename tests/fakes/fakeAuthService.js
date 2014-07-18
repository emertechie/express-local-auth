module.exports = {
    loginPath: '/login',
    hashPassword: function(password, cb) {
        cb(null, 'hashed-' + password);
    },
    verifyPassword: function(unhashedPassword, hashedPassword, cb) {
        var matches = 'hashed-' + unhashedPassword === hashedPassword;
        return cb(null, matches);
    },
    markLoggedInAfterAuthentication: function(req, user, cb) {
        cb(null);
    },
    logOut: function(req, user, cb) {
        cb(null);
    }
};