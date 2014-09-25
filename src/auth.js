var passport = require('passport'),
    LocalStrategy = require('passport-local').Strategy,
    bcrypt = require('bcrypt'),
    _ = require('lodash'),
    utils = require('./utils');

module.exports = function(sharedServices, options) {
    var userStore = sharedServices.userStore;
    var logger = sharedServices.logger;
    var userIdGetter = sharedServices.userIdGetter;

    var authService = buildAuthService(userStore);
    configurePassport(userStore, authService);

    return {
        routeHandlers: buildRouteHandlers(authService),
        service: authService
    };

    function buildAuthService(userStore) {
        return {
            loginPath: options.loginPath,
            hash: function (unhashed, cb) {
                var genSaltRounds = 10;
                bcrypt.hash(unhashed, genSaltRounds, function (hashingErr, hashed) {
                    if (hashingErr) {
                        // Error should be logged by caller in context of current op
                        return cb(hashingErr);
                    }
                    cb(null, hashed);
                });
            },
            verifyHash: function (unhashed, hashed, cb) {
                bcrypt.compare(unhashed, hashed, function (err, same) {
                    if (err) {
                        // Error should be logged by caller in context of current op
                        return cb(err);
                    }
                    cb(null, same);
                });
            },
            // Note: long name to indicate that *no* authentication is done in this method
            markLoggedInAfterAuthentication: function (req, user, cb) {
                req.logIn(user, function (err) {
                    if (err) {
                        logger.error('Error from req.logIn while trying to mark user "%s" as logged in', user.email, err);
                        return cb(err);
                    }
                    if (userStore.logIn) {
                        var userId = userIdGetter(user);
                        userStore.logIn(userId, function (err) {
                            if (err) {
                                logger.error('Error from user store while trying to mark user "%s" as logged in', user.email, err);
                                return next(err);
                            }

                            logger.info('Marked user "%s" as logged in, via user store', user.email);
                            cb(null, user);
                        });
                    } else {
                        logger.info('Marked user "%s" as logged in', user.email);
                        cb(null, user);
                    }
                });
            },
            logOut: function (req, user, cb) {
                req.logOut();
                if (user && userStore.logOut) {
                    var userId = userIdGetter(user);
                    userStore.logOut(userId, function (err) {
                        if (err) {
                            logger.error('Error from user store while trying log out user "%s"', user.email, err);
                            return next(err);
                        }
                        logger.info('Logged out user "%s", via user store', user.email);
                        cb(null);
                    });
                } else {
                    logger.info('Logged out user "%s"', user.email);
                    cb(null, user);
                }
            },
            isAuthenticated: function (req, cb) {
                options.isAuthenticated(req, function (err, authenticatedUser) {
                    if (err) {
                        logger.error('Error checking if request is authenticated', err);
                        return cb(err);
                    }
                    cb(null, authenticatedUser ? authenticatedUser : !!authenticatedUser);
                });
            }
        };
    }

    function configurePassport(userStore, authService) {
        passport.use(new LocalStrategy({
                usernameField: 'email'
            },
            function verify(email, password, done) {
                email = options.normalizeCase ? email.toLowerCase() : email;
                userStore.findByEmail(email, function (err, user) {
                    if (err) {
                        logger.error('Error finding user "%s" in user store in verify fn', email, err);
                        return done(err);
                    }
                    if (!user) {
                        logger.info('Could not find user "%s" in user store in verify fn', email);
                        return done(null, false, { userNameValid: false });
                    }

                    var verifyPassword = function () {
                        authService.verifyHash(password, user.hashedPassword, function (err, verifiied) {
                            if (err) {
                                logger.error('Error verifying password hash for user "%s" in verify fn', user.email, err);
                                return done(err);
                            }

                            if (!verifiied) {
                                user.failedLoginAttempts = (user.failedLoginAttempts || 0) + 1;

                                if (user.failedLoginAttempts >= options.failedLoginsBeforeLockout) {
                                    var now = Date.now();
                                    user.lockedUntil = now + options.accountLockedMs;
                                    logger.info('Incorrect password for user "%s" in verify fn. The max failedLoginAttempts (%d) reached, account locked out until %d',
                                        user.email, user.failedLoginAttempts, user.lockedUntil);
                                } else {
                                    logger.info('Incorrect password for user "%s" in verify fn. user.failedLoginAttempts=', user.email, user.failedLoginAttempts);
                                }

                                userStore.update(user, function (err) {
                                    if (err) {
                                        logger.error('Error updating failed login attempt count for user "%s" in verify fn', user.email, err);
                                        return done(err);
                                    }

                                    return done(null, false, { passwordValid: false });
                                });
                            } else {
                                if (user.failedLoginAttempts > 0) {
                                    user.failedLoginAttempts = 0;

                                    userStore.update(user, function (err) {
                                        if (err) {
                                            logger.error('Error resetting failed login attempt count for user "%s" in verify fn', user.email, err);
                                            return done(err);
                                        }

                                        logger.debug('Successfully verified user "%s" and reset failed login attempts count in verify fn', user.email);
                                        return done(null, user);
                                    });
                                } else {
                                    logger.debug('Successfully verified user "%s" in verify fn', user.email);
                                    return done(null, user);
                                }
                            }
                        });
                    };

                    if (user.lockedUntil) {
                        var now = Date.now();
                        if (user.lockedUntil > now) {
                            logger.info('Could not authenticate user "%s" because account is locked out', email);
                            return done(null, false, { accountLocked: true });
                        } else {
                            logger.info('Lockout period expired for user "%s". Unlocking', email);
                            user.lockedUntil = null;
                            user.failedLoginAttempts = 0;

                            userStore.update(user, function (err) {
                                if (err) {
                                    logger.error('Error updating user "%s" to reset failedLoginAttempts back to 0', user.email, err);
                                    return done(err);
                                }
                                verifyPassword();
                            });
                        }
                    } else {
                        verifyPassword();
                    }
                });
            }
        ));

        passport.serializeUser(function (user, done) {
            var userId = userIdGetter(user);
            done(null, userId);
        });

        passport.deserializeUser(function (id, done) {
            userStore.get(id, done);
        });
    }

    function buildRouteHandlers(authService) {
        var handlers = {
            ensureAuthenticated: function () {
                return function ensureAuthenticatedHandler(req, res, next) {
                    authService.isAuthenticated(req, function (err, authenticatedUser) {
                        if (err) {
                            return next(err);
                        }
                        if (authenticatedUser) {
                            next();
                        } else {
                            res.redirect(options.loginPath);
                        }
                    });
                }
            },
            login: function (routeOptions) {
                var errorCfg = utils.getErrorConfig(options, routeOptions);

                return function loginHandler(req, res, next) {
                    req.checkBody('email', 'Valid email address required').notEmpty().isEmail();
                    req.checkBody('password', 'Password required').notEmpty();
                    if (utils.handleValidationErrors(errorCfg)(req, res, next)) {
                        return;
                    }

                    passport.authenticate('local', function (err, user, info) {
                        if (err) {
                            logger.error('Error authenticating user "%s" during login', req.body.email, err);
                            return next(err);
                        }
                        if (!user) {
                            logger.info('User "%s" failed authentication during login', req.body.email, info);

                            if (info && info.accountLocked) {
                                utils.handleError('Your account has been locked temporarily. Please try again later', errorCfg, 401)(req, res, next);
                            } else {
                                utils.handleError('Invalid credentials', errorCfg, 401)(req, res, next);
                            }
                        } else {
                            authService.markLoggedInAfterAuthentication(req, user, function (err) {
                                next(err);
                            });
                        }
                    })(req, res, next);
                }
            },
            logout: function () {
                return function logoutHander(req, res, next) {
                    authService.isAuthenticated(req, function (err, authenticatedUser) {
                        if (err) {
                            return next(err);
                        }
                        if (authenticatedUser) {
                            authService.logOut(req, authenticatedUser, function (err) {
                                next(err);
                            });
                        } else {
                            res.redirect(options.loginPath);
                        }
                    });
                }
            }
        };

        // Aliases
        handlers.logIn = handlers.login;
        handlers.logOut = handlers.logout;

        return handlers;
    }
};