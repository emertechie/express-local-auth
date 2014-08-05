module.exports = {
    sendRegistrationEmail: function(user, verifyQueryString, cb) {
        var msg = 'Pretending to send registration email to ' + user.email;
        if (verifyQueryString) {
            msg += '. To verify email, visit /verifyemail' + verifyQueryString;
        }
        console.log(msg);
        cb(null);
    },
    sendForgotPasswordEmail: function(user, verifyQueryString, cb) {
        console.log('Pretending to send password reset email to ' + user.email + ' with reset URL: /resetpassword' + verifyQueryString);
        cb(null);
    },
    sendForgotPasswordNotificationForUnregisteredEmail: function(email, cb) {
        console.log('Pretending to send notification of password reset for unknown email ' + email);
        cb(null);
    },
    sendPasswordResetEmail: function(user, cb) {
        console.log('Pretending to send password reset email to ' + user.email);
        cb(null);
    },
    sendPasswordChangedEmail: function(user, cb) {
        console.log('Pretending to send password changed email to ' + user.email);
        cb(null);
    }
};