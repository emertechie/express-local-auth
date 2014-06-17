var express = require('express'),
    bcrypt = require('bcrypt');

module.exports = function(services, options) {

    if (!services || !services.auth || !services.email || !services.logger) {
        throw new Error('Required services missing');
    }

    options = options || {};

    return function RegistrationRouterFactory(userStore) {
        var router = express.Router();

        router.post('/register', function (req, res) {

            var username = req.param("username");
            var password = req.param("password");

            if (!username || !password) {
                return res.send(400, 'Must provide username & password');
            }

            bcrypt.hash(password, 10, function (hashingErr, hashedPassword) {
                if (hashingErr) {
                    errorHandler('Error hashing password', hashingErr);
                    return res.send(500, 'Could not register user');
                }

                var userDetails = {
                    username: username,
                    hashedPassword: hashedPassword
                };

                userStore.add(userDetails, function (err, userId) {
                    if (err) {
                        if (err.status_code && err.message) {
                            return res.send(err.status_code, err.message);
                        } else {
                            return res.send(500, err);
                        }
                    }

                    // userDetails without password
                    var safeUserDetails = {
                        userId: userId,
                        username: username
                    };

                    services.auth.logIn(userId, function(err) {
                        if (err) {
                            services.logger.error('Could not log in user ' + userId + ' after registration', err);
                            return res.send(500, err);
                        }

                        if (services.email) {
                            services.email.sendRegistrationEmail(safeUserDetails, function(err) {
                                if (err) {
                                    services.logger.error('Error sending registration email for user ' + userId, err);
                                }
                                sendResponse();
                            });
                        } else {
                            sendResponse();
                        }
                    });

                    function sendResponse() {
                        var successResponse = options.resultTransformer
                            ? options.resultTransformer(userId)
                            : userId;
                        res.send(201, JSON.stringify(successResponse));
                    }
                });
            });
        });

        // TODO: Authenticated /unregister endpoint to delete account
        // app.post('/unregister', ... userStore.remove(userId));

        // TODO: Forgot password. * Rendering email *
        // app.post('/forgotPassword', ... send email);
        // app.post('/forgotPassword/callback', ... send email);

        // TODO: Callback to verify email
        // app.get('/verifyemail', ... userStore.emailVerified(userId));

        return router;
    }
};