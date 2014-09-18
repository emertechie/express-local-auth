var _ = require('lodash'),
    expressValidator = require('express-validator'),
    passport = require('passport'),
    auth = require('./auth'),
    registration = require('./registration'),
    forgotPassword = require('./forgotPassword'),
    changePassword = require('./changePassword');

var minuteInMs = 1000 * 60;

module.exports = function(router, sharedServices, options) {

    sharedServices = _.defaults(sharedServices || {}, {
        userIdGetter: function(user) {
            return user.id;
        }
    });

    if (!router) {
        throw new Error('Missing required router parameter');
    }
    if (!sharedServices) {
        throw new Error('Missing required configuration parameter');
    }
    if (!sharedServices.logger) {
        throw new Error('Missing required logger service');
    }
    if (!sharedServices.userStore) {
        throw new Error('Missing required userStore service');
    }
    if (!sharedServices.passwordResetTokenStore) {
        throw new Error('Missing required passwordResetTokenStore service');
    }
    if (!sharedServices.emailService) {
        throw new Error('Missing required emailService service');
    }
    if (!sharedServices.userIdGetter) {
        throw new Error('Missing required userIdGetter service');
    }

    options = _.defaults(options || {}, {
        loginPath: '/login',
        useSessions: true,
        normalizeCase: true,
        failedLoginsBeforeLockout: 10,
        accountLockedMs: 20 * minuteInMs,
        tokenExpirationMins: 60,
        verifyEmail: false,
        isAuthenticated: function (req, cb) {
            return cb(null, req.isAuthenticated() ? req.user : false);
        }
    });

    if (options.verifyEmail && !sharedServices.verifyEmailTokenStore) {
        throw new Error('Missing required verifyEmailTokenStore service');
    }

    configureRouter(router, options);

    var components = {};
    components.auth = auth(sharedServices, options);

    // Note: Only supporting sharedServices.authService for some tests
    var authService = sharedServices.authService ? sharedServices.authService : components.auth.service;

    components.registration = registration(sharedServices, authService, options);
    components.forgotPassword = forgotPassword(sharedServices, authService, options);
    components.changePassword = changePassword(sharedServices, authService, options);

    var localAuth = {
        components: components
    };

    _.assign(localAuth, components.auth.routeHandlers);
    _.assign(localAuth, components.registration.routeHandlers);
    _.assign(localAuth, components.forgotPassword.routeHandlers);
    _.assign(localAuth, components.changePassword.routeHandlers);

    return localAuth;
};

function configureRouter(router, options) {
    router.use(passport.initialize());

    if (options.useSessions) {
        router.use(passport.session());
    }

    expressValidator.validator.extend('matches', function (str, expectedMatchParam, req) {
        var valueToMatch = req.param(expectedMatchParam);
        return str === valueToMatch;
    });
    router.use(expressValidator());
}
