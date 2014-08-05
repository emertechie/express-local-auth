var _ = require('lodash'),
    uuid = require('node-uuid'),
    async = require('async'),
    utils = require('./utils');

module.exports = function(sharedServices, authService, options) {
    var userStore = sharedServices.userStore;
    var passwordResetTokenStore = sharedServices.passwordResetTokenStore;
    var emailService = sharedServices.emailService;
    var logger = sharedServices.logger;
    var userIdGetter = sharedServices.userIdGetter;

    var routeHandlers = {
        forgotPassword: function(routeOptions) {
            var errorRedirect = utils.getErrorRedirectOption(routeOptions || {}, options.useSession);

            return function forgotPasswordHandler(req, res, next) {
                req.checkBody('email', 'Valid email address required').notEmpty().isEmail();
                if (utils.handleValidationErrors(errorRedirect)(req, res, next)) {
                    return;
                }

                var email = options.normalizeCase ? req.body.email.toLowerCase() : req.body.email;

                userStore.findByEmail(email, function(err, user) {
                    if (err) {
                        logger.error('Error finding user "%s" in user store', email, err);
                        return next(err);
                    }

                    // Make these available for next handler
                    res.locals.user = user;
                    res.locals.email = email;

                    if (user) {
                        if (options.verifyEmail && !user.emailVerified) {
                            var errorMsg = 'Please verify your email address first by clicking on the link in the registration email';
                            return utils.handleError(errorMsg, errorRedirect, 400)(req, res, next);
                        }

                        var unhashedToken = uuid.v4().replace(/-/g, '');

                        var tokenObj = {
                            email: email,
                            userId: userIdGetter(user),
                            expiry: new Date(Date.now() + (options.tokenExpirationMins * 60 * 1000))
                        };

                        async.waterfall([
                            function(callback) {
                                authService.hash(unhashedToken, callback);
                            },
                            function(hashedToken, callback) {
                                tokenObj.hashedToken = hashedToken;
                                callback(null);
                            },
                            function(callback) {
                                passwordResetTokenStore.removeAllByEmail(email, callback);
                            },
                            function(callback) {
                                passwordResetTokenStore.add(tokenObj, callback);
                            },
                            function(addedToken, callback) {
                                logger.info('Sending forgot password email for user "%s"', email);

                                var verifyQueryString = '?email=' + email + '&token=' + unhashedToken;
                                emailService.sendForgotPasswordEmail(user, verifyQueryString, callback);
                            }
                        ], function(err) {
                            if (err) {
                                logger.error('Error during forgot password process for user "%s"', email, err);
                                return next(err);
                            }
                            next();
                        });
                    } else {
                        logger.info('Forgot password process attempted for unregistered email "%s"', email);

                        emailService.sendForgotPasswordNotificationForUnregisteredEmail(email, function(err) {
                            if (err) {
                                return next(err);
                            }
                            next();
                        });
                    }
                });
            };
        },
        resetPasswordView: function() {
            return function changePasswordViewHandler(req, res, next) {
                var hasTokenParam = 'token' in req.query;
                var hasFlashErrors = (req.session && req.session.flash)
                    ? req.session.flash.validationErrors || req.session.flash.errors
                    : false;

                if (!hasTokenParam || hasFlashErrors) {
                    // we've probably redirected to page on an error so just render view:
                    return next();
                }

                req.checkQuery('token', 'Password reset token required').notEmpty();
                req.checkQuery('email', 'Email address required').notEmpty();
                var errorRedirect = false;
                if (utils.handleValidationErrors(errorRedirect)(req, res, next)) {
                    return;
                }

                var token = req.query.token;
                var email = options.normalizeCase ? req.query.email.toLowerCase() : req.query.email;
                // Add these to locals so they can be rendered as hidden form inputs
                res.locals.token = token;
                res.locals.email = email;

                findAndVerifyPasswordResetToken(email, token, function(err, isValid) {
                    if (err) {
                        logger.error('Error finding or verifying password reset token for email "%s" while rendering password reset view', email, err);
                        return next(err);
                    }

                    if (!isValid) {
                        logger.info('Invalid password reset token found for email "%s" while rendering password reset view', email);
                        var useRedirect = false;
                        return utils.handleError('Unknown or expired token', useRedirect, 400)(req, res, next);
                    }

                    next();
                });
            };
        },
        resetPassword: function(routeOptions) {
            var errorRedirect = utils.getErrorRedirectOption(routeOptions || {}, options.useSession);

            return function changePasswordHandler(req, res, next) {

                req.checkBody('email', 'Email address required').notEmpty();
                req.checkBody('token', 'Password reset token required').notEmpty();
                req.checkBody('password', 'New password required').notEmpty();
                req.checkBody('confirmPassword', 'Password confirmation required').notEmpty();

                var errorRedirectQueryParams = '?email=' + (req.body.email || '') + '&token=' + (req.body.token || '');

                if (utils.handleValidationErrors(errorRedirect, errorRedirectQueryParams)(req, res, next)) {
                    return;
                }

                // Only check confirm password after we know others are ok to avoid returning a redundant error
                req.checkBody('confirmPassword', 'Password and confirm password do not match').matches('password', req);
                if (utils.handleValidationErrors(errorRedirect, errorRedirectQueryParams)(req, res, next)) {
                    return;
                }

                var token = req.body.token;
                var email = options.normalizeCase ? req.body.email.toLowerCase() : req.body.email;
                var password = req.body.password;

                findAndVerifyPasswordResetToken(email, token, function(err, isValid, tokenDetails) {
                    if (err) {
                        logger.error('Error finding or verifying password reset token for email "%s" in reset password handler', email, err);
                        return next(err);
                    }

                    if (!isValid) {
                        logger.info('Invalid password reset token found for email "%s" in reset password handler', email);
                        return utils.handleError('Unknown or expired token', errorRedirect, errorRedirectQueryParams, 400)(req, res, next);
                    }

                    authService.hash(password, function(err, hashedPassword) {
                        if (err) {
                            logger.error('Error hashing password for email "%s" in reset password handler', email, err);
                            return next(err);
                        }

                        userStore.get(tokenDetails.userId, function(err, user) {
                            if (err) {
                                logger.error('Error getting user "%s" in reset password handler', email, err);
                                return next(err);
                            }
                            if (!user) {
                                logger.info('Unknown user "%s" in reset password handler', email);
                                return utils.handleError('Unknown or expired token', errorRedirect, errorRedirectQueryParams, 400)(req, res, next);
                            }

                            user.hashedPassword = hashedPassword;

                            userStore.update(user, function(err) {
                                if (err) {
                                    logger.error('Error updating user "%s" in reset password handler', email, err);
                                    return next(err);
                                }

                                passwordResetTokenStore.removeAllByEmail(tokenDetails.email, function(err) {
                                    if (err) {
                                        logger.error('Error removing all password reset tokens for user "%s"', email, err);
                                        return next(err);
                                    }

                                    emailService.sendPasswordResetEmail(user, function(err) {
                                        if (err) {
                                            logger.error('Could not send password reset email for user "%s"', email, err);
                                        }

                                        logger.info('User "%s" successfully reset password', email);
                                        next();
                                    });
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

    function findAndVerifyPasswordResetToken(email, unhashedToken, cb) {
        passwordResetTokenStore.findByEmail(email, function(err, tokenDetails) {
            if (err) {
                return cb(err);
            }

            var isValidStep1 =
                tokenDetails &&
                tokenDetails.hashedToken &&
                tokenDetails.expiry &&
                tokenDetails.expiry instanceof Date &&
                tokenDetails.expiry.getTime() >= Date.now();

            if (!isValidStep1) {
                cb(null, isValidStep1, isValidStep1 ? tokenDetails : null);
            } else {
                authService.verifyHash(unhashedToken, tokenDetails.hashedToken, function(err, isValidStep2) {
                    if (err) {
                        return cb(err);
                    }
                    cb(null, isValidStep2, isValidStep2 ? tokenDetails : null);
                });
            }
        });
    }
};