module.exports = {
    loginPath: '/login',
    hashPassword: function(password, cb) {
        cb(null, 'hashed-' + password);
    },
    markLoggedInAfterAuthentication: function(req, user, cb) {
        cb(null);
    },
    logOut: function(req, user, cb) {
        cb(null);
    }
};