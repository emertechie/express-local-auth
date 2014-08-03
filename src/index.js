var expressValidator = require('express-validator'),
    _ = require('lodash'),
    uuid = require('node-uuid'),
    async = require('async');

module.exports = function(options) {

    options = _.defaults(options || {}, {
        tokenExpirationMins: 60,
        verifyEmail: false,
        useSession: true
    });

    expressValidator.validator.extend('matches', function(str, expectedMatchParam, req) {
        var valueToMatch = req.param(expectedMatchParam);
        return str === valueToMatch;
    });

    return function RegistrationComponentFactory(router, authService, config) {
        if (!router) {
            throw new Error('Missing required router parameter');
        }
        if (!config) {
            throw new Error('Missing required configuration parameter');
        }
        if (!config.logger) {
            throw new Error('Missing required logger config');
        }
        if (!config.userStore) {
            throw new Error('Missing required userStore config');
        }
        if (!config.passwordResetTokenStore) {
            throw new Error('Missing required passwordResetTokenStore config');
        }
        if (!config.emailService) {
            throw new Error('Missing required emailService config');
        }
        if (options.verifyEmail && !config.verifyEmailTokenStore) {
            throw new Error('Missing required verifyEmailTokenStore config');
        }
        var userStore = config.userStore;
        var passwordResetTokenStore = config.passwordResetTokenStore;
        var verifyEmailTokenStore = config.verifyEmailTokenStore;
        var emailService = config.emailService;
        var logger = config.logger;

        router.use(expressValidator());

        return {
            routeHandlers: buildRouteHandlers(authService, userStore, emailService)
        };

        function buildRouteHandlers(authService, userStore, emailService) {
            return {
                register: function(routeOptions) {
                    var errorRedirect = getErrorRedirectOption(routeOptions || {}, options.useSession);

                    return function registerHandler(req, res, next) {
                        req.checkBody('email', 'Valid email address required').notEmpty().isEmail();
                        req.checkBody('password', 'Password required').notEmpty();
                        if (handleValidationErrors(req, res, next, errorRedirect)) {
                            return;
                        }

                        var email = req.body.email;
                        var userDetails = {
                            email: email,
                            username: req.body.username || email,
                            password: req.body.password
                        };
                        if (options.verifyEmail) {
                            userDetails.emailVerified = false;
                        }

                        authService.hash(userDetails.password, function(err, hashedPassword) {
                            if (err) {
                                logger.error('Error hashing password while registering user "%s"', email, err);
                                return next(err);
                            }

                            delete userDetails.password; // Make sure no possibility of storing unhashed password
                            userDetails.hashedPassword = hashedPassword;

                            userStore.add(userDetails, function(err, userAlreadyExists, user) {
                                if (err) {
                                    logger.error('Error adding user "%s" to userStore', email, err);
                                    return next(err);
                                }
                                if (userAlreadyExists) {
                                    logger.info('Registration details for user "%s" already exist', email);
                                    return handleError(req, res, next, 'errors', 'Registration details already in use', errorRedirect);
                                }

                                var sendRegEmailAndLogIn = function(verifyQueryString) {
                                    emailService.sendRegistrationEmail(user, verifyQueryString, function(err) {
                                        if (err) {
                                            // log error but continue
                                            logger.error('Error sending registration email to "%s"', email, err);
                                        }

                                        authService.markLoggedInAfterAuthentication(req, user, function(err) {
                                            if (err) {
                                                logger.error('Could not log in user "%s" after registration', email, err);
                                                return next(err);
                                            }

                                            logger.info('Successfully registered user "%s"', email);
                                            next();
                                        });
                                    });
                                };

                                if (options.verifyEmail) {
                                    var tokenObj = {
                                        email: email,
                                        userId: config.userIdGetter(user)
                                    };

                                    var unhashedToken = uuid.v4().replace(/-/g, '');
                                    authService.hash(unhashedToken, function(err, hashedToken) {
                                        if (err) {
                                            logger.error('Error hashing veryify email token for user "%s" during registration', email, err);
                                            return next(err);
                                        }

                                        tokenObj.hashedToken = hashedToken;

                                        verifyEmailTokenStore.add(tokenObj, function(err) {
                                            if (err) {
                                                logger.error('Could not add verify email token to store for user "%s" during registration', email, err);
                                                return next(err);
                                            }

                                            logger.debug('Added verify email token for user "%s" during registration', email);
                                            var verifyQueryString = '?email=' + email + '&token=' + unhashedToken;
                                            sendRegEmailAndLogIn(verifyQueryString);
                                        });
                                    });
                                } else {
                                    sendRegEmailAndLogIn();
                                }
                            });
                        });
                    }
                },
                verifyEmailView: function() {
                    return function verifyEmailAddressHandler(req, res, next) {
                        req.checkQuery('email', 'Valid email address required').notEmpty().isEmail();
                        req.checkQuery('token', 'Verify email token required').notEmpty();
                        // TODO: Use handleValidationErrors function for all this
                        var validationErrors = req.validationErrors(true);
                        if (validationErrors) {
                            res.status(400);
                            res.locals.validationErrors = [ validationErrors ];
                            return next();
                        }

                        var email = req.query.email;
                        var token = req.query.token;

                        findAndVerifyRegistrationEmailToken(email, token, function(err, verified) {
                            if (err) {
                                logger.error('Error finding or verfying the verify email token using email "%s"', email, err);
                                return cb(err);
                            }

                            if (verified) {
                                userStore.findByEmail(email, function(err, user) {
                                    if (err) {
                                        logger.error('error finding user "%s" in verify email view', email, err);
                                        return next(err);
                                    }

                                    if (!user) {
                                        logger.info('Unknown user "%s" for verify email token "%s"', email, token);

                                        res.status(400);
                                        var useRedirect = false;
                                        return handleError(req, res, next, 'errors', 'Unknown or invalid token', useRedirect);
                                    }

                                    user.emailVerified = true;

                                    userStore.update(user, function(err) {
                                        if (err) {
                                            logger.error('Error updaing user "%s" after email verified', email, err);
                                            return next(err);
                                        }

                                        verifyEmailTokenStore.removeAllByEmail(email, function(err) {
                                            if (err) {
                                                logger.error('Error removing all verify email tokens for user "%s"', email, err);
                                                return next(err);
                                            }

                                            logger.info('User "%s" successfully verified email', email);
                                            next();
                                        });
                                    });
                                });
                            } else {
                                logger.info('Unknown or invalid verify email token "%s" for email "%s"', token, email);

                                res.status(400);
                                var useRedirect = false;
                                handleError(req, res, next, 'errors', 'Unknown or invalid token', useRedirect);
                            }
                        });
                    };
                },
                unregister: function() {
                    return function unregisterHandler(req, res, next) {
                        authService.isAuthenticated(req, function (err, authenticatedUser) {
                            if (err) {
                                logger.error('Error checking if user is authenticated during unregister', err);
                                return next(err);
                            }

                            if (!authenticatedUser) {
                                return res.redirect(authService.loginPath);
                            }

                            var email = authenticatedUser.email;

                            authService.logOut(req, authenticatedUser, function (err) {
                                if (err) {
                                    logger.error('Error logging out user "%s" during unregister', email, err);
                                    return next(err);
                                }

                                var userId = config.userIdGetter(authenticatedUser);
                                userStore.remove(userId, function (err) {
                                    if (err) {
                                        logger.error('Error removing user "%s" from user store during unregister', email, err);
                                        return next(err);
                                    }

                                    logger.error('User "%s" successfully unregistered', email, err);
                                    next();
                                });
                            });
                        });
                    }
                },
                forgotPassword: function(routeOptions) {
                    var errorRedirect = getErrorRedirectOption(routeOptions || {}, options.useSession);

                    return function forgotPasswordHandler(req, res, next) {
                        req.checkBody('email', 'Valid email address required').notEmpty().isEmail();
                        if (handleValidationErrors(req, res, next, errorRedirect)) {
                            return;
                        }

                        var email = req.body.email;

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
                                    return handleError(req, res, next, 'errors', errorMsg, errorRedirect);
                                }

                                var unhashedToken = uuid.v4().replace(/-/g, '');

                                var tokenObj = {
                                    email: email,
                                    userId: config.userIdGetter(user),
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
                        // TODO: Use handleValidationErrors function for all this
                        var validationErrors = req.validationErrors(true);
                        if (validationErrors) {
                            res.status(400);
                            res.locals.validationErrors = [ validationErrors ];
                            return next();
                        }

                        var token = req.query.token;
                        var email = req.query.email;
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

                                res.status(400);
                                var useRedirect = false;
                                return handleError(req, res, next, 'errors', 'Unknown or expired token', useRedirect);
                            }

                            next();
                        });
                    };
                },
                resetPassword: function(routeOptions) {
                    var errorRedirect = getErrorRedirectOption(routeOptions || {}, options.useSession);

                    return function changePasswordHandler(req, res, next) {

                        req.checkBody('email', 'Email address required').notEmpty();
                        req.checkBody('token', 'Password reset token required').notEmpty();
                        req.checkBody('password', 'New password required').notEmpty();
                        req.checkBody('confirmPassword', 'Password confirmation required').notEmpty();

                        var errorRedirectQueryParams = '?email=' + (req.body.email || '') + '&token=' + (req.body.token || '');

                        if (handleValidationErrors(req, res, next, errorRedirect, errorRedirectQueryParams)) {
                            return;
                        }

                        // Only check confirm password after we know others are ok to avoid returning a redundant error
                        req.checkBody('confirmPassword', 'Password and confirm password do not match').matches('password', req);
                        if (handleValidationErrors(req, res, next, errorRedirect, errorRedirectQueryParams)) {
                            return;
                        }

                        var token = req.body.token;
                        var email = req.body.email;
                        var password = req.body.password;

                        findAndVerifyPasswordResetToken(email, token, function(err, isValid, tokenDetails) {
                            if (err) {
                                logger.error('Error finding or verifying password reset token for email "%s" in reset password handler', email, err);
                                return next(err);
                            }

                            if (!isValid) {
                                logger.info('Invalid password reset token found for email "%s" in reset password handler', email);
                                return handleError(req, res, next, 'errors', 'Unknown or expired token', errorRedirect, errorRedirectQueryParams);
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
                                        return handleError(req, res, next, 'errors', 'Unknown or expired token', errorRedirect, errorRedirectQueryParams);
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
                },
                changePassword: function(routeOptions) {
                    var errorRedirect = getErrorRedirectOption(routeOptions || {}, options.useSession);

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
                            if (handleValidationErrors(req, res, next, errorRedirect)) {
                                return;
                            }

                            // Only check confirm password after we know others are ok to avoid returning a redundant error
                            req.checkBody('confirmNewPassword', 'New password and confirm password do not match').matches('newPassword', req);
                            if (handleValidationErrors(req, res, next, errorRedirect)) {
                                return;
                            }

                            authService.verifyHash(req.body.oldPassword, authenticatedUser.hashedPassword, function(err, passwordMatches) {
                                if (err) {
                                    logger.error('Error verifying old password hash for user "%s" in change password handler', email, err);
                                    return next(err);
                                }

                                if (!passwordMatches) {
                                    logger.info('Incorrect old password for user "%s" in change password handler', email, err);
                                    return handleError(req, res, next, 'errors', 'Incorrect password', errorRedirect);
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

            function findAndVerifyRegistrationEmailToken(email, unhashedToken, cb) {
                verifyEmailTokenStore.findByEmail(email, function(err, tokenDetails) {
                    if (err) {
                        return cb(err);
                    }

                    if (!tokenDetails) {
                        logger.info('Could not find verify email token using email "%s"', email);
                        return cb(null, false, null);
                    }

                    authService.verifyHash(unhashedToken, tokenDetails.hashedToken, function(err, verified) {
                        if (err) {
                            return cb(err);
                        }
                        cb(null, verified, tokenDetails);
                    });
                });
            }

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

            function handleValidationErrors(req, res, next, validationRedirect, redirectQueryParams) {
                var validationErrors = req.validationErrors(true);
                if (validationErrors) {
                    handleError(req, res, next, 'validationErrors', validationErrors, validationRedirect, redirectQueryParams);
                    return true;
                }
            }

            function handleError(req, res, next, errorName, error, errorRedirect, redirectQueryParams) {
                if (errorRedirect) {
                    req.flash(errorName, error);
                    var redirectPath = getErrorRedirectPath(req, errorRedirect, redirectQueryParams);
                    res.redirect(redirectPath);
                } else {
                    // Note: Assigning an error array to match the format you get if using flash (so view logic stays the same either way)
                    res.locals[errorName] = [ error ];
                    next();
                }
            }

            function getErrorRedirectOption(routeOptions, useSession) {
                return routeOptions.errorRedirect === false
                    ? false
                    : routeOptions.errorRedirect || useSession;
            }

            function getErrorRedirectPath(req, errorRedirect, redirectQueryParams) {
                var path = (errorRedirect === true)
                    ? req.path // so, things like POST /register will redirect to GET /register with errors in flash
                    : errorRedirect;

                return path + (redirectQueryParams || '');
            }
        }
    };
};
