var express = require('express'),
    expressValidator = require('express-validator'),
    _ = require('lodash');

module.exports = function(options) {

    options = _.defaults(options || {}, {
        registerView: 'register',
        useSession: true
    });

    return function RegistrationComponentFactory(router, authService, config) {
        if (!router) {
            throw new Error('Required router parameter');
        }
        if (!config) {
            throw new Error('Required configuration parameter missing');
        }
        if (!config.userStore) {
            throw new Error('Missing required userStore service');
        }
        if (!config.emailService) {
            throw new Error('Missing required email service');
        }
        var userStore = config.userStore;
        var emailService = config.emailService;

        /*var authService = buildAuthService(userStore, config);
        configurePassport(userStore, config, authService);

        router.use(passport.initialize());
        router.use(expressValidator());
        if (options.useSession) {
            router.use(passport.session());
        }*/

        router.use(expressValidator());

        /*if (options.useSession) {
            router.use(passport.session());
        }*/

        return {
            routeHandlers: buildRouteHandlers(authService, userStore, emailService)
            // service: authService
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
                                    return handleError('error', 'Registration details already in use', errorRedirect, req, res, next);
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
                }
            };

            function anyValidationErrors(req, res, next, validationRedirect) {
                var validationErrors = req.validationErrors(true);
                if (validationErrors) {
                    handleError('validationErrors', validationErrors, validationRedirect, req, res, next);
                    return true;
                }
            }

            function handleError(errorName, error, errorRedirect, req, res, next) {
                if (errorRedirect) {
                    req.flash(errorName, error);
                    var redirectPath = getErrorRedirectPath(req, errorRedirect);
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

            function getErrorRedirectPath(req, errorRedirect) {
                return (errorRedirect === true)
                    ? req.path // so, things like POST /register will redirect to GET /register with errors in flash
                    : errorRedirect;
            }
        }
    };
};
