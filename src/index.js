var express = require('express'),
    expressValidator = require('express-validator'),
    _ = require('lodash'),
    uuid = require('node-uuid'),
    async = require('async');

module.exports = function(options) {

    options = _.defaults(options || {}, {
        registerView: 'register',
        tokenExpirationMins: 60,
        useSession: true
    });

    expressValidator.validator.extend('matches', function(str, expectedMatchParam, req) {
        var valueToMatch = req.param(expectedMatchParam);
        return str === valueToMatch;
    });

    return function RegistrationComponentFactory(router, authService, config) {
        if (!router) {
            throw new Error('Required router parameter');
        }
        if (!config) {
            throw new Error('Required configuration parameter missing');
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
        var userStore = config.userStore;
        var passwordResetTokenStore = config.passwordResetTokenStore;
        var emailService = config.emailService;

        router.use(expressValidator());

        return {
            routeHandlers: buildRouteHandlers(authService, userStore, emailService)
        };

        function buildRouteHandlers(authService, userStore, emailService) {
            return {
                registerView: function() {
                    return function registerViewHandler(req, res) {
                        res.render(options.registerView);
                    }
                },
                register: function(routeOptions) {
                    var errorRedirect = getErrorRedirectOption(routeOptions || {}, options.useSession);

                    return function registerHandler(req, res, next) {
                        req.checkBody('email', 'Valid email address required').notEmpty().isEmail();
                        req.checkBody('password', 'Password required').notEmpty();
                        if (anyValidationErrors(req, res, next, errorRedirect)) {
                            return;
                        }

                        var email = req.param('email');
                        var userDetails = {
                            email: email,
                            username: req.param('username') || email,
                            password: req.param('password')
                        };

                        authService.hashPassword(userDetails.password, function(err, hashedPassword) {
                            if (err) {
                                // TODO logger.error('Error hashing password while registering user', err);
                                return next(err);
                            }

                            delete userDetails.password; // Make sure no possibility of storing unhashed password
                            userDetails.hashedPassword = hashedPassword;

                            userStore.add(userDetails, function(err, userAlreadyExists, user) {
                                if (err) {
                                    return next(err);
                                }
                                if (userAlreadyExists) {
                                    return handleError(req, res, next, 'error', 'Registration details already in use', errorRedirect);
                                }

                                var userId = config.userIdGetter(user);

                                emailService.sendRegistrationEmail(user, function(err) {
                                    if (err) {
                                        // log error but don't return it
                                        // TODO logger.error('Error sending registration email for user ' + userId, err);
                                    }

                                    authService.markLoggedInAfterAuthentication(req, user, function(err) {
                                        if (err) {
                                            // TODO logger.error('Could not log in user ' + userId + ' after registration', err);
                                            return next(err);
                                        }

                                        next();
                                    });
                                });
                            });
                        });
                    }
                },
                unregister: function() {
                    return function unregisterHandler(req, res, next) {
                        authService.isAuthenticated(req, function (err, authenticatedUser) {
                            if (err) {
                                return next(err);
                            }

                            if (authenticatedUser) {
                                authService.logOut(req, authenticatedUser, function (err) {
                                    if (err) {
                                        return next(err);
                                    }

                                    var userId = config.userIdGetter(authenticatedUser);
                                    userStore.remove(userId, function (err) {
                                        if (err) {
                                            return next(err);
                                        }

                                        next();
                                    });
                                });
                            } else {
                                res.redirect(authService.loginPath);
                            }
                        });
                    }
                },
                forgotPassword: function(routeOptions) {
                    var errorRedirect = getErrorRedirectOption(routeOptions || {}, options.useSession);

                    return function forgotPasswordHandler(req, res, next) {
                        req.checkBody('email', 'Valid email address required').notEmpty().isEmail();
                        if (anyValidationErrors(req, res, next, errorRedirect)) {
                            return;
                        }

                        var email = req.body.email;

                        userStore.findByEmail(email, function(err, user) {
                            if (err) {
                                return next(err);
                            }

                            // Note: setting this in case next handler needs to know if user found
                            res.locals.user = user;

                            if (user) {
                                var tokenObj = {
                                    email: email,
                                    userId: config.userIdGetter(user),
                                    token: uuid.v4(),
                                    expiry: new Date(Date.now() + (options.tokenExpirationMins * 60 * 1000))
                                };

                                async.waterfall([
                                    function(callback) {
                                        passwordResetTokenStore.removeAllByEmail(email, callback);
                                    },
                                    function(callback) {
                                        passwordResetTokenStore.add(tokenObj, callback);
                                    },
                                    function(addedToken, callback) {
                                        emailService.sendPasswordResetEmail(user, tokenObj.token, callback);
                                    }
                                ], function(err) {
                                    if (err) {
                                        return next(err);
                                    }
                                    next();
                                });
                            } else {
                                emailService.sendPasswordResetNotificationForUnregisteredEmail(email, function(err) {
                                    if (err) {
                                        return next(err);
                                    }
                                    next();
                                });
                            }
                        });
                    };
                },
                changePasswordView: function(routeOptions) {
                    return function changePasswordViewHandler(req, res, next) {
                        var hasTokenParam = 'token' in req.query;
                        if (!hasTokenParam) {
                            // we've probably redirected to page on an error so just render view:
                            return next();
                        }

                        req.checkQuery('token', 'Password reset token required').notEmpty();
                        var validationErrors = req.validationErrors(true);
                        if (validationErrors) {
                            // Note: Just putting validationErrors in locals since this is a GET request
                            res.locals.validationErrors = validationErrors;
                            return next();
                        }

                        var token = req.query.token;

                        findAndVerifyToken(token, function(err, isValid) {
                            if (err) {
                                return next(err);
                            }

                            // Note: Just putting error in locals since this is a GET request
                            if (!isValid) {
                                res.locals.error = 'Unknown or expired token';
                            }

                            next();
                        });
                    };
                },
                changePassword: function(routeOptions) {
                    var errorRedirect = getErrorRedirectOption(routeOptions || {}, options.useSession);

                    return function changePasswordHandler(req, res, next) {

                        req.checkBody('token', 'Password reset token required').notEmpty();
                        req.checkBody('password', 'New password required').notEmpty();
                        req.checkBody('confirmPassword', 'Password confirmation required').notEmpty();

                        var errorRedirectQueryParams = req.body.token ? '?token=' + req.body.token : '';

                        if (anyValidationErrors(req, res, next, errorRedirect, errorRedirectQueryParams)) {
                            return;
                        }

                        // Only check confirm password after we know others are ok to avoid returning a redundant error
                        req.checkBody('confirmPassword', 'Password and confirm password do not match').matches('password', req);
                        if (anyValidationErrors(req, res, next, errorRedirect, errorRedirectQueryParams)) {
                            return;
                        }

                        var token = req.body.token;
                        var password = req.body.password;

                        findAndVerifyToken(token, function(err, isValid, tokenDetails) {
                            if (err) {
                                return next(err);
                            }

                            if (!isValid) {
                                return handleError(req, res, next, 'error', 'Unknown or expired token', errorRedirect, errorRedirectQueryParams);
                            }

                            authService.hashPassword(password, function(err, hashedPassword) {
                                if (err) {
                                    return next(err);
                                }

                                userStore.get(tokenDetails.userId, function(err, user) {
                                    if (err) {
                                        return next(err);
                                    }
                                    if (!user) {
                                        return handleError(req, res, next, 'error', 'Unknown or expired token', errorRedirect, errorRedirectQueryParams);
                                    }

                                    user.hashedPassword = hashedPassword;

                                    userStore.update(user, function(err) {
                                        if (err) {
                                            return next(err);
                                        }

                                        passwordResetTokenStore.removeAllByEmail(tokenDetails.email, function(err) {
                                            if (err) {
                                                return next(err);
                                            }

                                            emailService.sendPasswordChangedEmail(user, function(err) {
                                                if (err) {
                                                    // TODO logger.error('Could not send password changed email for user with email: ' + tokenDetails.email);
                                                }
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

            function findAndVerifyToken(token, cb) {
                passwordResetTokenStore.findByToken(token, function(err, tokenDetails) {
                    if (err) {
                        return cb(err);
                    }

                    var isValid =
                        tokenDetails &&
                        tokenDetails.token &&
                        tokenDetails.expiry &&
                        tokenDetails.expiry instanceof Date &&
                        tokenDetails.expiry.getTime() >= Date.now();

                    cb(null, isValid, tokenDetails);
                });
            }

            function anyValidationErrors(req, res, next, validationRedirect, redirectQueryParams) {
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
                    res.locals[errorName] = error;
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
