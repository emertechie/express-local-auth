var express = require('express'),
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
            unregistered: function(res) {
                res.send(200);
            }
        });

        return {
            router: buildRouter()
        };

        function buildRouter() {

            var router = express.Router();

            router.post('/register', function (req, res) {

                var userDetails = {
                    username: req.param("username"),
                    password: req.param("password")
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
            if (!userDetails.username || !userDetails.password) {
                return callback(makeError(400, 'Must provide username & password'));
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