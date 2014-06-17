var express = require('express'),
    bcrypt = require('bcrypt');

module.exports = function(options) {

    options = options || {};
    var logger = options.logger || console;

    return function RegistrationComponentFactory(userStore, authService, emailService) {

        if (!userStore || !authService || !emailService) {
            throw new Error('Required services missing');
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

        function register(userDetails, callback) {
            if (!userDetails.username || !userDetails.password) {
                return callback(makeError(400, 'Must provide username & password'));
            }

            bcrypt.hash(userDetails.password, 10, function (hashingErr, hashedPassword) {
                if (hashingErr) {
                    errorHandler('Error hashing password', hashingErr);
                    return callback(makeError(500, 'Could not register user'));
                }

                delete userDetails.password; // Make sure no possibility of storing unhashed password
                userDetails.hashedPassword = hashedPassword;

                userStore.add(userDetails, function (err, userId) {
                    if (err) {
                        return callback(makeError(err));
                    }

                    delete userDetails.hashedPassword;
                    userDetails.userId = userId;

                    emailService.sendRegistrationEmail(userDetails, function(err) {
                        if (err) {
                            // log error but don't return error
                            logger.error('Error sending registration email for user ' + userId, err);
                        }

                        authService.logIn(userId, function(err) {
                            if (err) {
                                logger.error('Could not log in user ' + userId + ' after registration', err);
                                return callback(makeError(500, err));
                            }

                            var successResponse = options.resultTransformer
                                ? options.resultTransformer(userId)
                                : userId;

                            callback(null, successResponse);
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

            register(userDetails, function (err, response) {
                if (err) {
                    return res.send(err.statusCode || 500, err.message ? err.message : err);
                }

                res.send(201, JSON.stringify(response));
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