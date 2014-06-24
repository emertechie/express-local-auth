var express = require('express');

module.exports = function(options) {

    options = options || {};
    var logger = options.logger || console;

    return function RegistrationComponentFactory(userStore, authService, emailService, config) {

        if (!userStore || !authService || !emailService || !config) {
            throw new Error('Required parameters missing');
        }

        var userIdGetter = config.userIdGetter;

        var registrationOkResponse = options.registrationOkResponse || function(user, res) {
            var userId = userIdGetter(user);
            res.send(201, JSON.stringify(userId));
        };

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

                        authService.logIn(req, user, function(err) {
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

                registrationOkResponse(user, res);
            });
        });

        // TODO: Authenticated /unregister endpoint to delete account
        // app.post('/unregister', ... userStore.remove(userId));

        // TODO: Forgot password. * Rendering email *
        // app.post('/forgotPassword', ... send email);
        // app.post('/forgotPassword/callback', ... send email);

        // TODO: Callback to verify email
        // app.get('/verifyemail', ... userStore.emailVerified(userId));

        return {
            router: router
        };
    }
};