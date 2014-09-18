module.exports = {
    sendRegistrationEmail: function(user, verifyQueryString, cb) {
        cb(null);
    },
    sendForgotPasswordEmail: function(user, token, cb) {
        cb(null);
    },
    sendForgotPasswordNotificationForUnregisteredEmail: function(email, cb) {
        cb(null);
    },
    sendPasswordSuccessfullyResetEmail: function(user, cb) {
        cb(null);
    },
    sendPasswordChangedEmail: function(user, cb) {
        cb(null);
    }
};