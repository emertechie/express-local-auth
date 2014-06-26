var express = require('express'),
    expressValidator = require('express-validator'),
    bodyParser = require('body-parser'),
    _ = require('lodash');

module.exports = function(options) {

    options = options || {};
    var logger = options.logger || console;

    return function RegistrationComponentFactory(userStore, authService, emailService, config) {

        if (!userStore || !authService || !emailService || !config) {
            throw new Error('Required parameters missing');
        }

        var userIdGetter = config.userIdGetter;

        var responses = _.defaults(options.responses || {}, {
            registered: function(user, res) {
                var userId = userIdGetter(user);
                res.send(201, JSON.stringify(userId));
            },
            registrationValidationErrors: function(validationErrors, req, res) {
                res.json(400, validationErrors);
            },
            unregistered: function(res) {
                res.send(200);
            }
        });

        return {
            router: buildRouter()
        };

        function buildRouter() {

            var router = express.Router();

            router.use(bodyParser());
            router.use(expressValidator());

            router.post('/register', function (req, res) {

                req.checkBody('email', 'Valid email address required').notEmpty().isEmail();
                req.checkBody('password', 'Password required').notEmpty();
                var validationErrors = req.validationErrors(true);
                if (validationErrors) {
                    return responses.registrationValidationErrors(validationErrors, req, res);
                }

                var email = req.param('email');
                var userDetails = {
                    email: email,
                    username: req.param('username') || email,
                    password: req.param('password')
                };

                register(req, userDetails, function (err, user) {
                    if (err) {
                        return res.send(err.statusCode || 500, err.message ? err.message : err);
                    }

                    responses.registered(user, res);
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

            // TODO: Forgot password. * Rendering email *
            // app.post('/forgotPassword', ... send email);
            // app.post('/forgotPassword/callback', ... send email);

            // TODO: Callback to verify email
            // app.get('/verifyemail', ... userStore.emailVerified(userId));

            return router;
        }

        function makeError(statusCodeOrError, message) {
            if (arguments.length === 1) {
                message = arguments[0];
                statusCodeOrError = 500;
            }
            return {
                statusCode: statusCodeOrError,
                message: message
            };
        }

        function register(req, userDetails, callback) {
            if (!userDetails.email || !userDetails.password) {
                return callback(makeError(400, 'Must provide email & password'));
            }

            authService.hashPassword(userDetails.password, function(err, hashedPassword) {
                if (err) {
                    errorHandler('Error hashing password', err);
                    return callback(makeError(500, 'Could not register user'));
                }

                delete userDetails.password; // Make sure no possibility of storing unhashed password
                userDetails.hashedPassword = hashedPassword;

                userStore.add(userDetails, function (err, user) {
                    if (err) {
                        return callback(makeError(err));
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
                                return callback(makeError(500, err));
                            }
                            callback(null, user);
                        });
                    });
                });
            });
        }
    };
};