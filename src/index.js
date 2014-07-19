var express = require('express'),
    expressValidator = require('express-validator'),
    _ = require('lodash'),
    uuid = require('node-uuid'),
    async = require('async');

module.exports = function(options) {

    options = _.defaults(options || {}, {
        registerView: 'register',
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
        if (options.verifyEmail && !config.verifyEmailTokenStore) {
            throw new Error('Missing required verifyEmailTokenStore config');
        }
        var userStore = config.userStore;
        var passwordResetTokenStore = config.passwordResetTokenStore;
        var verifyEmailTokenStore = config.verifyEmailTokenStore;
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
                        if (handleValidationErrors(req, res, next, errorRedirect)) {
                            return;
                        }

                        var email = req.param('email');
                        var userDetails = {
                            email: email,
                            username: req.param('username') || email,
                            password: req.param('password')
                        };
                        if (options.verifyEmail) {
                            userDetails.emailVerified = false;
                        }

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

                                var sendRegEmailAndLogIn = function(verifyEmailToken) {
                                    emailService.sendRegistrationEmail(user, verifyEmailToken, function(err) {
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
                                };

                                if (options.verifyEmail) {
                                    var tokenObj = {
                                        email: email,
                                        userId: config.userIdGetter(user),
                                        token: uuid.v4()
                                    };
                                    verifyEmailTokenStore.add(tokenObj, function(err) {
                                        if (err) {
                                            return next(err);
                                        }
                                        sendRegEmailAndLogIn(tokenObj.token);
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
                        req.checkQuery('token', 'Verify email token required').notEmpty();
                        var validationErrors = req.validationErrors(true);
                        if (validationErrors) {
                            res.status(400);
                            res.locals.validationErrors = validationErrors;
                            return next();
                        }

                        var token = req.query.token;

                        verifyEmailTokenStore.findByToken(token, function(err, tokenDetails) {
                            if (err) {
                                return cb(err);
                            }

                            if (tokenDetails) {

                                userStore.findByEmail(tokenDetails.email, function(err, user) {
                                    if (err) {
                                        return next(err);
                                    }

                                    if (!user) {
                                        res.status(400);
                                        res.locals.error = 'Unknown or invalid token';
                                        return next();
                                    }

                                    user.emailVerified = true;

                                    userStore.update(user, function(err) {
                                        if (err) {
                                            return next(err);
                                        }

                                        verifyEmailTokenStore.removeAllByEmail(tokenDetails.email, function(err) {
                                            if (err) {
                                                return next(err);
                                            }

                                            next();
                                        });
                                    });
                                });
                            } else {
                                res.status(400);
                                res.locals.error = 'Unknown or invalid verify email token';
                                next();
                            }
                        });
                    };
                },
                unregister: function() {
                    return function unregisterHandler(req, res, next) {
                        authService.isAuthenticated(req, function (err, authenticatedUser) {
                            if (err) {
                                return next(err);
                            }

                            if (!authenticatedUser) {
                                return res.redirect(authService.loginPath);
                            }

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
                                return next(err);
                            }

                            // Note: setting this in case next handler needs to know if user found
                            res.locals.user = user;

                            if (user) {
                                var unhashedToken = uuid.v4().replace(/-/g, '');

                                var tokenObj = {
                                    email: email,
                                    userId: config.userIdGetter(user),
                                    expiry: new Date(Date.now() + (options.tokenExpirationMins * 60 * 1000))
                                };

                                async.waterfall([
                                    function(callback) {
                                        authService.hashPassword(unhashedToken, callback);
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
                                        var verifyQueryString = '?email=' + email + '&token=' + unhashedToken;
                                        emailService.sendForgotPasswordEmail(user, verifyQueryString, callback);
                                    }
                                ], function(err) {
                                    if (err) {
                                        return next(err);
                                    }
                                    next();
                                });
                            } else {
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
                            ? req.session.flash.validationErrors || req.session.flash.error
                            : false;

                        if (!hasTokenParam || hasFlashErrors) {
                            // we've probably redirected to page on an error so just render view:
                            return next();
                        }

                        req.checkQuery('token', 'Password reset token required').notEmpty();
                        req.checkQuery('email', 'Email address required').notEmpty();
                        var validationErrors = req.validationErrors(true);
                        if (validationErrors) {
                            res.status(400);
                            res.locals.validationErrors = validationErrors;
                            return next();
                        }

                        var token = req.query.token;
                        var email = req.query.email;

                        findAndVerifyPasswordResetToken(email, token, function(err, isValid) {
                            if (err) {
                                return next(err);
                            }

                            if (!isValid) {
                                res.status(400);
                                res.locals.error = 'Unknown or expired token';
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

                                            emailService.sendPasswordResetEmail(user, function(err) {
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
                },
                changePassword: function(routeOptions) {
                    var errorRedirect = getErrorRedirectOption(routeOptions || {}, options.useSession);

                    return function changePasswordHandler(req, res, next) {

                        authService.isAuthenticated(req, function (err, authenticatedUser) {
                            if (err) {
                                return next(err);
                            }

                            if (!authenticatedUser) {
                                return res.redirect(authService.loginPath);
                            }

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

                            authService.verifyPassword(req.body.oldPassword, authenticatedUser.hashedPassword, function(err, passwordMatches) {
                                if (err) {
                                    return next(err);
                                }

                                if (!passwordMatches) {
                                    return handleError(req, res, next, 'error', 'Incorrect password', errorRedirect);
                                }

                                authService.hashPassword(req.body.newPassword, function(err, hashedPassword) {
                                    if (err) {
                                        return next(err);
                                    }

                                    authenticatedUser.hashedPassword = hashedPassword;

                                    userStore.update(authenticatedUser, function(err) {
                                        if (err) {
                                            return next(err);
                                        }

                                        emailService.sendPasswordChangedEmail(authenticatedUser, function(err) {
                                            if (err) {
                                                // TODO logger.error('Could not send password changed email for user with email: ' + tokenDetails.email);
                                            }
                                            next();
                                        });
                                    });
                                });
                            });
                        });
                    };
                }
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
                        authService.verifyPassword(unhashedToken, tokenDetails.hashedToken, function(err, isValidStep2) {
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
