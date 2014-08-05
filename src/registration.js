var expressValidator = require('express-validator'),
    _ = require('lodash'),
    uuid = require('node-uuid'),
    async = require('async'),
    utils = require('./utils');

// TODO: remove router
module.exports = function(router, sharedServices, authService, options) {
    /*if (!router) {
        throw new Error('Missing required router parameter');
    }
    if (!sharedServices) {
        throw new Error('Missing required configuration parameter');
    }
    if (!sharedServices.logger) {
        throw new Error('Missing required logger service');
    }
    if (!sharedServices.userStore) {
        throw new Error('Missing required userStore service');
    }
    if (!sharedServices.emailService) {
        throw new Error('Missing required emailService service');
    }
    if (!authService) {
        throw new Error('Missing required authService parameter');
    }
    if (!sharedServices.userIdGetter) {
        throw new Error('Missing required userIdGetter service');
    }

    options = _.defaults(options || {}, {
        tokenExpirationMins: 60,
        verifyEmail: false,
        useSession: true,
        normalizeCase: true
    });

    if (options.verifyEmail && !sharedServices.verifyEmailTokenStore) {
        throw new Error('Missing required verifyEmailTokenStore service');
    }
    */

    var userStore = sharedServices.userStore;
    var verifyEmailTokenStore = sharedServices.verifyEmailTokenStore;
    var emailService = sharedServices.emailService;
    var logger = sharedServices.logger;
    var userIdGetter = sharedServices.userIdGetter;

    expressValidator.validator.extend('matches', function(str, expectedMatchParam, req) {
        var valueToMatch = req.param(expectedMatchParam);
        return str === valueToMatch;
    });

    router.use(expressValidator());

    var routeHandlers = {
        register: function (routeOptions) {
            var errorRedirect = utils.getErrorRedirectOption(routeOptions || {}, options.useSession);

            return function registerHandler(req, res, next) {
                req.checkBody('email', 'Valid email address required').notEmpty().isEmail();
                req.checkBody('password', 'Password required').notEmpty();
                if (utils.handleValidationErrors(errorRedirect)(req, res, next)) {
                    return;
                }

                var email = options.normalizeCase ? req.body.email.toLowerCase() : req.body.email;
                var userDetails = {
                    email: email,
                    username: req.body.username || email,
                    password: req.body.password
                };
                if (options.verifyEmail) {
                    userDetails.emailVerified = false;
                }

                authService.hash(userDetails.password, function (err, hashedPassword) {
                    if (err) {
                        logger.error('Error hashing password while registering user "%s"', email, err);
                        return next(err);
                    }

                    delete userDetails.password; // Make sure no possibility of storing unhashed password
                    userDetails.hashedPassword = hashedPassword;

                    userStore.add(userDetails, function (err, userAlreadyExists, user) {
                        if (err) {
                            logger.error('Error adding user "%s" to userStore', email, err);
                            return next(err);
                        }
                        if (userAlreadyExists) {
                            logger.info('Registration details for user "%s" already exist', email);
                            return utils.handleError('Registration details already in use', errorRedirect, 409)(req, res, next);
                        }

                        var sendRegEmailAndLogIn = function (verifyQueryString) {
                            emailService.sendRegistrationEmail(user, verifyQueryString, function (err) {
                                if (err) {
                                    // log error but continue
                                    logger.error('Error sending registration email to "%s"', email, err);
                                }

                                authService.markLoggedInAfterAuthentication(req, user, function (err) {
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
                                userId: userIdGetter(user)
                            };

                            var unhashedToken = uuid.v4().replace(/-/g, '');
                            authService.hash(unhashedToken, function (err, hashedToken) {
                                if (err) {
                                    logger.error('Error hashing veryify email token for user "%s" during registration', email, err);
                                    return next(err);
                                }

                                tokenObj.hashedToken = hashedToken;

                                verifyEmailTokenStore.add(tokenObj, function (err) {
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
        verifyEmailView: function () {
            return function verifyEmailAddressHandler(req, res, next) {
                req.checkQuery('email', 'Valid email address required').notEmpty().isEmail();
                req.checkQuery('token', 'Verify email token required').notEmpty();
                var errorRedirect = false;
                if (utils.handleValidationErrors(errorRedirect)(req, res, next)) {
                    return;
                }

                var email = options.normalizeCase ? req.query.email.toLowerCase() : req.query.email;
                var token = req.query.token;

                findAndVerifyRegistrationEmailToken(email, token, function (err, verified) {
                    if (err) {
                        logger.error('Error finding or verfying the verify email token using email "%s"', email, err);
                        return cb(err);
                    }

                    if (verified) {
                        userStore.findByEmail(email, function (err, user) {
                            if (err) {
                                logger.error('error finding user "%s" in verify email view', email, err);
                                return next(err);
                            }

                            if (!user) {
                                logger.info('Unknown user "%s" for verify email token "%s"', email, token);
                                var useRedirect = false;
                                return utils.handleError('Unknown or invalid token', useRedirect, 400)(req, res, next);
                            }

                            user.emailVerified = true;

                            userStore.update(user, function (err) {
                                if (err) {
                                    logger.error('Error updaing user "%s" after email verified', email, err);
                                    return next(err);
                                }

                                verifyEmailTokenStore.removeAllByEmail(email, function (err) {
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
                        var useRedirect = false;
                        utils.handleError('Unknown or invalid token', useRedirect, 400)(req, res, next);
                    }
                });
            };
        },
        unregister: function () {
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

                        var userId = userIdGetter(authenticatedUser);
                        userStore.remove(userId, function (err) {
                            if (err) {
                                logger.error('Error removing user "%s" from user store during unregister', email, err);
                                return next(err);
                            }

                            logger.info('User "%s" successfully unregistered', email, err);
                            next();
                        });
                    });
                });
            }
        }
    };

    return {
        routeHandlers: routeHandlers
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
};