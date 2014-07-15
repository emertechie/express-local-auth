var express = require('express'),
    expressValidator = require('express-validator'),
    bodyParser = require('body-parser'),
    _ = require('lodash'),
    uuid = require('node-uuid'),
    async = require('async');

module.exports = function(options) {

    expressValidator.validator.extend('matches', function(str, expectedMatchParam, req) {
        var valueToMatch = req.param(expectedMatchParam);
        return str === valueToMatch;
    });

    options = _.defaults(options || {}, {
        tokenExpirationMins: 60,
        logger: console
    });

    var logger = options.logger;

    return function RegistrationComponentFactory(userStore, passwordResetTokenStore, authService, emailService, config) {

        if (!userStore || !passwordResetTokenStore || !authService || !emailService || !config) {
            throw new Error('Required parameters missing');
        }

        var userIdGetter = config.userIdGetter;

        var validationErrorsRespose = function(validationErrors, req, res) {
            res.json(400, validationErrors);
        };

        var invalidTokenRespose = function(res) {
            res.send(400, 'Unknown or expired token');
        };

        var responses = _.defaults(options.responses || {}, {
            registered: function(user, res) {
                var userId = userIdGetter(user);
                res.send(201, JSON.stringify(userId));
            },
            // todo: test
            duplicateUserRegistration: function(req, res) {
                res.send(400, 'Registration details already in use');
            },
            registrationValidationErrors: validationErrorsRespose,
            unregistered: function(res) {
                res.send(200);
            },
            requestPasswordResetValidationErrors: validationErrorsRespose,
            passwordResetEmailSent: function(email, res) {
                res.send(200, 'Password reset email sent to: ' + email);
            },
            passwordResetPageValidationErrors: validationErrorsRespose,
            passwordResetPageInvalidToken: invalidTokenRespose,
            changePasswordInvalidToken: invalidTokenRespose,
            passwordResetPage: function(token, res) {
                res.json(200, { token: token });
            },
            resetPasswordValidationErrors: validationErrorsRespose,
            passwordChanged: function(res) {
                res.send(200, 'Password has been changed');
            }
        });

        return {
            router: buildRouter()
        };

        function buildRouter() {

            var router = express.Router();

            router.use(bodyParser());
            router.use(expressValidator());

            router.post('/register', function (req, res, next) {

                req.checkBody('email', 'Valid email address required').notEmpty().isEmail();
                req.checkBody('password', 'Password required').notEmpty();
                if (returnValidationErrors(req, res, responses.registrationValidationErrors)) {
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
                        logger.error('Error hashing password while registering user', err);
                        return next(err);
                    }

                    delete userDetails.password; // Make sure no possibility of storing unhashed password
                    userDetails.hashedPassword = hashedPassword;

                    userStore.add(userDetails, function(err, userAlreadyExists, user) {
                        if (err) {
                            return next(err);
                        }
                        if (userAlreadyExists) {
                            return responses.duplicateUserRegistration(req, res);
                        }

                        var userId = userIdGetter(user);

                        emailService.sendRegistrationEmail(user, function(err) {
                            if (err) {
                                // log error but don't return it
                                logger.error('Error sending registration email for user ' + userId, err);
                            }

                            authService.markLoggedInAfterAuthentication(req, user, function(err) {
                                if (err) {
                                    logger.error('Could not log in user ' + userId + ' after registration', err);
                                    return next(err);
                                }

                                responses.registered(user, res);
                            });
                        });
                    });
                });
            });

            router.post('/unregister', function (req, res, next) {
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

                                responses.unregistered(res);
                            });
                        });
                    } else {
                        authService.responses.unauthenticated(res);
                    }
                });
            });

            router.post('/forgotpassword', function(req, res, next) {

                req.checkBody('email', 'Valid email address required').notEmpty().isEmail();
                if (returnValidationErrors(req, res, responses.requestPasswordResetValidationErrors)) {
                    return;
                }

                var email = req.body.email;

                userStore.findByEmail(email, function(err, user) {
                    if (err) {
                        return next(err);
                    }

                    if (user) {
                        var tokenObj = {
                            email: email,
                            userId: userIdGetter(user),
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
                            responses.passwordResetEmailSent(email, res);
                        });
                    } else {
                        emailService.sendPasswordResetNotificationForUnregisteredEmail(email, function(err) {
                            if (err) {
                                return next(err);
                            }
                            responses.passwordResetEmailSent(email, res);
                        });
                    }
                });
            });

            router.get('/changepassword', function(req, res, next) {

                req.checkQuery('token', 'Password reset token required').notEmpty();
                if (returnValidationErrors(req, res, responses.passwordResetPageValidationErrors)) {
                    return;
                }

                var token = req.query.token;

                findAndVerifyToken(token, function(err, isValid) {
                    if (err) {
                        return next(err);
                    }
                    if (isValid) {
                        responses.passwordResetPage(token, res);
                    } else {
                        responses.passwordResetPageInvalidToken(res);
                    }
                });
            });

            router.post('/changepassword', function(req, res, next) {

                req.checkBody('token', 'Password reset token required').notEmpty();
                req.checkBody('password', 'New password required').notEmpty();
                req.checkBody('confirmPassword', 'Password confirmation required').notEmpty();
                if (returnValidationErrors(req, res, responses.resetPasswordValidationErrors)) {
                    return;
                }
                // Only check confirm password after we know others are ok to avoid returning a redundant error
                req.checkBody('confirmPassword', 'Password and confirm password do not match').matches('password', req);
                if (returnValidationErrors(req, res, responses.resetPasswordValidationErrors)) {
                    return;
                }

                var token = req.body.token;
                var password = req.body.password;

                findAndVerifyToken(token, function(err, isValid, tokenDetails) {
                    if (err) {
                        return next(err);
                    }

                    if (isValid) {

                        authService.hashPassword(password, function(err, hashedPassword) {
                            if (err) {
                                return next(err);
                            }

                            userStore.get(tokenDetails.userId, function(err, user) {
                                if (err) {
                                    return next(err);
                                }
                                if (!user) {
                                    return responses.changePasswordInvalidToken(res);
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
                                                logger.error('Could not send password changed email for user with email: ' + tokenDetails.email);
                                            }
                                            responses.passwordChanged(res);
                                        });
                                    });
                                });
                            });
                        });
                    } else {
                        responses.changePasswordInvalidToken(res);
                    }
                });
            });

            // TODO: Callback to verify email
            // app.get('/verifyemail', ... userStore.emailVerified(userId));

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

            return router;
        }

        function returnValidationErrors(req, res, responseGenerator) {
            var validationErrors = req.validationErrors(true);
            if (validationErrors) {
                responseGenerator(validationErrors, req, res);
                return true;
            }
        }
    };
};