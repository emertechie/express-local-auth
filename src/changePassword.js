var expressValidator = require('express-validator'),
    _ = require('lodash'),
    uuid = require('node-uuid'),
    async = require('async'),
    utils = require('./utils');

// TODO: remove router
module.exports = function(router, sharedServices, authService, options) {
    /*if (!router) {
        throw new Error('Missing required router parameter');
    }
    if (!sharedServices) {
        throw new Error('Missing required configuration parameter');
    }
    if (!sharedServices.logger) {
        throw new Error('Missing required logger config');
    }
    if (!sharedServices.userStore) {
        throw new Error('Missing required userStore config');
    }
    if (!sharedServices.emailService) {
        throw new Error('Missing required emailService config');
    }
    */

    var userStore = sharedServices.userStore;
    var emailService = sharedServices.emailService;
    var logger = sharedServices.logger;

    /*options = _.defaults(options || {}, {
        tokenExpirationMins: 60,
        verifyEmail: false,
        useSession: true,
        normalizeCase: true
    });*/

    expressValidator.validator.extend('matches', function (str, expectedMatchParam, req) {
        var valueToMatch = req.param(expectedMatchParam);
        return str === valueToMatch;
    });

    router.use(expressValidator());

    var routeHandlers = {
        changePassword: function(routeOptions) {
            var errorRedirect = utils.getErrorRedirectOption(routeOptions || {}, options.useSession);

            return function changePasswordHandler(req, res, next) {

                authService.isAuthenticated(req, function (err, authenticatedUser) {
                    if (err) {
                        logger.error('Error checking if user is authenticated in change password handler', err);
                        return next(err);
                    }

                    if (!authenticatedUser) {
                        return res.redirect(authService.loginPath);
                    }

                    var email = authenticatedUser.email;

                    req.checkBody('oldPassword', 'Old password required').notEmpty();
                    req.checkBody('newPassword', 'New password required').notEmpty();
                    req.checkBody('confirmNewPassword', 'New password confirmation required').notEmpty();
                    if (utils.handleValidationErrors(errorRedirect)(req, res, next)) {
                        return;
                    }

                    // Only check confirm password after we know others are ok to avoid returning a redundant error
                    req.checkBody('confirmNewPassword', 'New password and confirm password do not match').matches('newPassword', req);
                    if (utils.handleValidationErrors(errorRedirect)(req, res, next)) {
                        return;
                    }

                    authService.verifyHash(req.body.oldPassword, authenticatedUser.hashedPassword, function(err, passwordMatches) {
                        if (err) {
                            logger.error('Error verifying old password hash for user "%s" in change password handler', email, err);
                            return next(err);
                        }

                        if (!passwordMatches) {
                            logger.info('Incorrect old password for user "%s" in change password handler', email, err);
                            return utils.handleError('Incorrect password', errorRedirect, 401)(req, res, next);
                        }

                        authService.hash(req.body.newPassword, function(err, hashedPassword) {
                            if (err) {
                                logger.error('Error hashing new password for user "%s" in change password handler', email, err);
                                return next(err);
                            }

                            authenticatedUser.hashedPassword = hashedPassword;

                            userStore.update(authenticatedUser, function(err) {
                                if (err) {
                                    logger.error('Error updating user "%s" in change password handler', email, err);
                                    return next(err);
                                }

                                emailService.sendPasswordChangedEmail(authenticatedUser, function(err) {
                                    if (err) {
                                        logger.error('Could not send password changed email for user "%s"', email, err);
                                    }

                                    logger.info('User "%s" successfully changed password', email);
                                    next();
                                });
                            });
                        });
                    });
                });
            };
        }
    };

    return {
        routeHandlers: routeHandlers
    };
};