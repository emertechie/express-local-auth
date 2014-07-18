module.exports = {
    sendRegistrationEmail: function(user, verifyEmailToken, cb) {
        cb(null);
    },
    sendForgotPasswordEmail: function(user, token, cb) {
        cb(null);
    },
    sendForgotPasswordNotificationForUnregisteredEmail: function(email, cb) {
        cb(null);
    },
    sendPasswordResetEmail: function(user, cb) {
        cb(null);
    },
    sendPasswordChangedEmail: function(user, cb) {
        cb(null);
    }
};