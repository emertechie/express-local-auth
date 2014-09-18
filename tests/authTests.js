var express = require('express'),
    session = require('express-session'),
    bodyParser = require('body-parser'),
    cookieParser = require('cookie-parser'),
    flash = require('connect-flash'),
    assert = require('chai').assert,
    request = require('supertest'),
    _ = require('lodash'),
    FakeUserStore = require('./fakes/userStore'),
    utils = require('./utils');

var secondInMs = 1000 * 60;
var minuteInMs = secondInMs * 60;

describe('Forms-based Username and Password auth', function() {

    var configureExpress, configureLocalAuth, configureStandardRoutes, configureApp;
    var app, localAuth, authService, userStore;
    var loginSuccessRedirectPath, logoutSuccessRedirectPath,
        existingUserEmail, existingUsername, existingUserPassword;

    beforeEach(function() {

        existingUsername = 'foo';
        existingUserEmail = 'foo@bar.com';
        existingUserPassword = 'bar';

        loginSuccessRedirectPath = '/home';
        logoutSuccessRedirectPath = '/loggedOut';

        userStore = new FakeUserStore();

        configureExpress = function(options) {
            options = options || {
                useSessions: true
            };

            var app = express();
            app.use(express.static(__dirname + '/public'));
            app.set('views', __dirname + '/views');
            app.set('view engine', 'jade');
            app.use(bodyParser.json());

            if (options.useSessions) {
                app.use(cookieParser());
                // Note: In a real app running with HTTPS, you should use following to limit cookie access:
                // session({..., cookie: { httpOnly: true, secure: true } })
                app.use(session({ secret: 'keyboard cat' } ));
                app.use(flash());
            }

            app.use(function(err, req, res, next) {
                console.error(err);
                res.send(500, err);
            });

            return app;
        };

        configureLocalAuth = function(app, options) {
            localAuth = utils.configureLocalAuth(app, {
                userStore: userStore
            }, options);
            authService = localAuth.components.auth.service;
        };

        configureStandardRoutes = function(app) {
            app.get('/login', function(req, res) {
                res.send(200, 'dummy login page');
            });
            app.post('/login', localAuth.login(), function(req, res) {
                res.redirect(loginSuccessRedirectPath);
            });
            app.get('/logout', localAuth.logout(), function(req, res) {
                res.redirect(logoutSuccessRedirectPath);
            });
        };

        configureApp = function(options) {
            options = options || {};
            var useSessions = (options.auth && 'useSessions' in options.auth) ? options.auth.useSessions : true;
            app = configureExpress();
            configureLocalAuth(app, options);
            configureStandardRoutes(app);
            return app;
        };
    });

    describe('Validation', function() {

        describe('With session (redirect with flash)', function() {

            var loginValidationErrors;

            beforeEach(function(done) {
                app = configureExpress();
                configureLocalAuth(app);

                app.post('/login', localAuth.login(), function(req, res) {
                    // Should have redirected before here on validation errors
                    res.redirect('/home');
                });

                app.get('/login', function(req, res) {
                    // Capture values for test
                    loginValidationErrors = req.session.flash.validationErrors;

                    res.send(200, 'dummy login page');
                });

                setupExistingUser(authService, userStore, existingUserEmail, existingUsername, existingUserPassword, done);
            });

            it('requires email', function(done) {
                var email = '';
                verifyLoginValidation(email, existingUserPassword, done, function() {
                    assert.lengthOf(loginValidationErrors, 1);
                    var error = loginValidationErrors[0].email;
                    assert.equal(error.param, 'email');
                    assert.equal(error.msg, 'Valid email address required');
                });
            });

            it('requires valid email', function(done) {
                var email = 'foobar';
                verifyLoginValidation(email, existingUserPassword, done, function() {
                    assert.lengthOf(loginValidationErrors, 1);
                    var error = loginValidationErrors[0].email;
                    assert.equal(error.param, 'email');
                    assert.equal(error.msg, 'Valid email address required');
                });
            });

            it('requires password', function(done) {
                var password = '';
                verifyLoginValidation(existingUserEmail, password, done, function() {
                    assert.lengthOf(loginValidationErrors, 1);
                    var error = loginValidationErrors[0].password;
                    assert.equal(error.param, 'password');
                    assert.equal(error.msg, 'Password required');
                });
            });

            function verifyLoginValidation(email, password, done, redirectVerifyFn) {
                request(app)
                    .post('/login')
                    .send({ email: email, password: password })
                    .expect(302)
                    .expect('location', '/login')
                    .end(function(err, res) {
                        if (err) {
                            return done(err);
                        }

                        request(app)
                            .get('/login')
                            .set('cookie', res.headers['set-cookie'])
                            .expect(200)
                            .expect(function() {
                                assert.ok(loginValidationErrors, 'Validation errors found');
                                redirectVerifyFn();
                            })
                            .end(done);
                    });
            }
        });

        describe('Without session', function() {

            var loginValidationErrors;

            beforeEach(function(done) {
                app = configureExpress();
                configureLocalAuth(app, {
                    useSessions: false
                });

                app.post('/login', localAuth.login(), function(req, res) {
                    loginValidationErrors = res.locals.validationErrors;
                    res.send(200);
                    // What you would probably do instead (locals.validationErrors accessible in view):
                    // res.render('login')
                });

                setupExistingUser(authService, userStore, existingUserEmail, existingUsername, existingUserPassword, done);
            });

            it('validates without needing session', function(done) {
                request(app)
                    .post('/login')
                    .send({ email: '', password: existingUserPassword })
                    .expect(200)
                    .expect(function() {
                        assert.lengthOf(loginValidationErrors, 1);
                        var error = loginValidationErrors[0].email;
                        assert.ok(error, 'Email error found');
                        assert.equal(error.param, 'email');
                        assert.equal(error.msg, 'Valid email address required');
                    })
                    .end(done);
            });
        });
    });

    describe('Standard routes behaviour', function() {

        describe('With session', function() {

            var loginErrors, failedLoginsBeforeLockout, accountLockedMs, originalDateNow, now;

            beforeEach(function(done) {
                failedLoginsBeforeLockout = 3;
                accountLockedMs = minuteInMs * 20;

                app = configureExpress();
                configureLocalAuth(app, {
                    failedLoginsBeforeLockout: failedLoginsBeforeLockout,
                    accountLockedMs: accountLockedMs
                });

                now = 1000;
                originalDateNow = Date.now;
                Date.now = function() {
                    return now;
                };

                // Set up some standard routes and capture any login flash errors
                app.post('/login', localAuth.login(), function(req, res) {
                    res.redirect(loginSuccessRedirectPath);
                });
                app.get('/login', function(req, res) {
                    loginErrors = req.flash('errors');
                    res.send(200, 'dummy login page');
                });
                app.get('/logout', localAuth.logout(), function(req, res) {
                    res.redirect(logoutSuccessRedirectPath);
                });

                // Set up couple of custom routes
                app.get('/private', localAuth.ensureAuthenticated(), function(req, res) {
                    res.send(200, 'private stuff');
                });
                app.get('/public', function(req, res) {
                    res.send(200, 'public stuff');
                });

                setupExistingUser(authService, userStore, existingUserEmail, existingUsername, existingUserPassword, done);
            });

            afterEach(function() {
                Date.now = originalDateNow;
            });

            describe('Low-level session cookie details', function() {

                it('should set a session id cookie after successful login', function(done) {
                    request(app)
                        .post('/login')
                        .send({ email: existingUserEmail, password: existingUserPassword })
                        .expect(302)
                        .expect('location', loginSuccessRedirectPath)
                        .end(function(err, res) {
                            if (err) {
                                return done(err);
                            }
                            var cookies = res.headers['set-cookie'];
                            assert.equal(1, cookies.length, 'Cookie set');
                            assert.equal(0, cookies[0].indexOf('connect.sid='), 'Connect session ID cookie set');
                            done(null);
                        });
                });

                it('should not set session id cookie after logout', function(done) {
                    request(app)
                        .post('/login')
                        .send({ email: existingUserEmail, password: existingUserPassword })
                        .end(function(err, res) {
                            if (err) {
                                return done(err);
                            }

                            var cookies = res.headers['set-cookie'];
                            request(app)
                                .get('/logout')
                                .set('cookie', cookies)
                                .expect(302)
                                .expect('location', logoutSuccessRedirectPath)
                                .expect(function(res) {
                                    var cookies = res.headers['set-cookie'];
                                    assert.isUndefined(cookies);
                                })
                                .end(done);
                        });
                });
            });

            it('should log user in with valid credentials', function(done) {
                request(app)
                    .post('/login')
                    .send({ email: existingUserEmail, password: existingUserPassword })
                    .expect(302)
                    .expect('location', loginSuccessRedirectPath)
                    .end(done);
            });

            it('should ignore case of email address when logging in', function(done) {
                var uppercaseEmail = existingUserEmail.toUpperCase();

                request(app)
                    .post('/login')
                    .send({ email: uppercaseEmail, password: existingUserPassword })
                    .expect(302)
                    .expect('location', loginSuccessRedirectPath)
                    .end(done);
            });

            it('should not log in user with invalid credentials', function(done) {
                request(app)
                    .post('/login')
                    .send({ email: 'unknown@example.com', password: existingUserPassword })
                    .expect(302)
                    .expect('location', '/login')
                    .end(function(err, res) {
                        if (err) {
                            return done(err);
                        }

                        // GET /login and verify we have correct flash error:
                        request(app)
                            .get('/login')
                            .set('cookie', res.headers['set-cookie'])
                            .end(function(err) {
                                if (err) {
                                    return done(err);
                                }
                                assert.deepEqual(loginErrors, [ 'Invalid credentials' ]);
                                done();
                            });
                    });
            });

            it('should lock account for period of time after a number of failed login attempts', function(done) {
                var wrongPasswordPostData = { email: existingUserEmail, password: 'unknown-password' };
                var correctPasswordPostData = { email: existingUserEmail, password: existingUserPassword };

                lockAccountOut(wrongPasswordPostData, function(err) {
                    if (err) {
                        return done(err);
                    }

                    // Try with valid credentials:
                    verifyPostRedirectGet(app, '/login', correctPasswordPostData, function verifyAfterGet() {
                        assert.deepEqual(loginErrors, [ 'Your account has been locked temporarily. Please try again later' ]);
                        assert.equal(userStore.users[0].lockedUntil, now + accountLockedMs);
                        assert.equal(userStore.users[0].failedLoginAttempts, 3);
                    }, function verifyLoginSuccessfully() {

                        // Now roll clock on:
                        now += accountLockedMs;

                        // Try with valid credentials again. Should work now:
                        request(app)
                            .post('/login')
                            .send(correctPasswordPostData)
                            .expect('location', loginSuccessRedirectPath)
                            .end(done);
                    });
                });
            });

            it('should unlock account after locked out period and allow successful login', function(done) {
                var wrongPasswordPostData = { email: existingUserEmail, password: 'unknown-password' };
                var correctPasswordPostData = { email: existingUserEmail, password: existingUserPassword };

                lockAccountOut(wrongPasswordPostData, function(err) {
                    if (err) {
                        return done(err);
                    }

                    // Roll clock on:
                    now += accountLockedMs;

                    // Try with valid credentials again. Should work now:
                    request(app)
                        .post('/login')
                        .send(correctPasswordPostData)
                        .expect('location', loginSuccessRedirectPath)
                        .end(function(err) {
                            if (err) {
                                return done(err);
                            }

                            assert.isUndefined(userStore.users[0].lockedUntil);
                            assert.equal(userStore.users[0].failedLoginAttempts, 0);

                            done();
                        });
                });
            });

            it('should clear failed login attempt count after successful login', function(done) {
                var wrongPasswordPostData = { email: existingUserEmail, password: 'unknown-password' };
                var correctPasswordPostData = { email: existingUserEmail, password: existingUserPassword };

                // Failed login attempt:
                verifyPostRedirectGet(app, '/login', wrongPasswordPostData, function verifyAfterGet() {
                    assert.deepEqual(loginErrors, [ 'Invalid credentials' ]);
                    assert.equal(userStore.users[0].failedLoginAttempts, 1);
                }, function(err) {
                    if (err) {
                        return done(err);
                    }

                    // Valid login:
                    request(app)
                        .post('/login')
                        .send(correctPasswordPostData)
                        .expect('location', loginSuccessRedirectPath)
                        .end(function(err) {
                            if (err) {
                                return done(err);
                            }

                            assert.equal(userStore.users[0].failedLoginAttempts, 0);

                            done();
                        });
                });
            });

            it('should ensure only logged in users can log out', function(done) {
                request(app)
                    .get('/logout')
                    .expect(302)
                    .expect('location', '/login', 'redirected to login page')
                    .end(done);
            });

            it('can log user out', function(done) {
                logIn(existingUserEmail, existingUserPassword, function(err, res) {
                    if (err) {
                        return done(err);
                    }

                    request(app)
                        .get('/logout')
                        .set('cookie', res.headers['set-cookie'])
                        .expect(302)
                        .expect('location', logoutSuccessRedirectPath, 'redirected after log out')
                        .end(function(err, res) {
                            if (err) {
                                return done(err);
                            }

                            // Make sure we can't get into authenticated route:
                            var cookies = res.headers['set-cookie'];
                            request(app)
                                .get('/private')
                                .set('cookie', cookies)
                                .expect(302)
                                .expect('location', '/login')
                                .end(done);
                        });
                });
            });

            it('should block unauthenticated access to protected custom route', function(done) {
                request(app)
                    .get('/private')
                    .expect(302)
                    .expect('location', '/login')
                    .end(done);
            });

            it('should allow authenticated access to protected custom route', function(done) {
                logIn(existingUserEmail, existingUserPassword, function(err, res) {
                    if (err) {
                        return done(err);
                    }

                    var cookies = res.headers['set-cookie'];

                    request(app)
                        .get('/private')
                        .set('cookie', cookies)
                        .expect(200, 'private stuff')
                        .end(done);
                });
            });

            it('should allow unauthenticated access to unprotected custom route', function(done) {
                request(app)
                    .get('/public')
                    .expect(200, 'public stuff')
                    .end(done);
            });

            function lockAccountOut(wrongPasswordPostData, done) {
                assert.lengthOf(userStore.users, 1);
                assert.isUndefined(userStore.users[0].lockedUntil);

                // Attempt 1
                verifyPostRedirectGet(app, '/login', wrongPasswordPostData, function verifyAfterGet() {
                        assert.deepEqual(loginErrors, [ 'Invalid credentials' ]);
                        assert.isUndefined(userStore.users[0].lockedUntil);
                    },
                    function attempt2(err) {
                        if (err) {
                            return done(err);
                        }

                        // Attempt 2
                        verifyPostRedirectGet(app, '/login', wrongPasswordPostData, function verifyAfterGet() {
                                assert.deepEqual(loginErrors, [ 'Invalid credentials' ]);
                                assert.isUndefined(userStore.users[0].lockedUntil);
                            },
                            function attempt3(err) {
                                if (err) {
                                    return done(err);
                                }

                                // Attempt 3
                                verifyPostRedirectGet(app, '/login', wrongPasswordPostData, function verifyAfterGet() {
                                    assert.deepEqual(loginErrors, [ 'Invalid credentials' ]);

                                    // Should now be set:
                                    assert.isDefined(userStore.users[0].lockedUntil);
                                }, done);
                            });
                    });
            }
        });

        describe('Without session', function() {

            // Note: Only defining tests here that have different behaviour when flash not enabled

            var loginErrors;

            beforeEach(function(done) {
                app = configureExpress();
                configureLocalAuth(app, {
                    useSessions: false
                });

                app.post('/login', localAuth.login(), function(req, res) {
                    loginErrors = res.locals.errors;
                    res.send(200);
                    // What you would probably do instead (locals.validationErrors accessible in view):
                    // res.render('login')
                });
                app.get('/logout', localAuth.logout(), function(req, res) {
                    res.redirect(logoutSuccessRedirectPath);
                });

                // Set up couple of custom routes
                app.get('/private', localAuth.ensureAuthenticated(), function(req, res) {
                    res.send(200, 'private stuff');
                });
                app.get('/public', function(req, res) {
                    res.send(200, 'public stuff');
                });

                setupExistingUser(authService, userStore, existingUserEmail, existingUsername, existingUserPassword, done);
            });

            it('should not log in user with invalid credentials', function(done) {
                request(app)
                    .post('/login')
                    .send({ email: 'unknown@example.com', password: existingUserPassword })
                    .expect(200)
                    .end(function(err) {
                        if (err) {
                            return done(err);
                        }

                        assert.deepEqual(loginErrors, [ 'Invalid credentials' ]);
                        done();
                    });
            });
        });
    });

    xdescribe('Persisting user login status to user store', function() {

        beforeEach(function(done) {
            configureApp();
            setupExistingUser(authService, userStore, existingUserEmail, existingUsername, existingUserPassword, done);
        });

        it('can notify user store on log-in if user store provides logIn func', function(done) {
            assert.equal(0, userStore.userIdsLoggedIn.length);

            logIn(existingUserEmail, existingUserPassword, function(err, res) {
                if (err) {
                    return done(err);
                }

                assert.deepEqual(['User#1'], userStore.userIdsLoggedIn);
                done();
            });
        });

        it('can notify user store on log-out if user store provides logOut func', function(done) {

            assert.equal(0, userStore.userIdsLoggedOut.length);

            logIn(existingUserEmail, existingUserPassword, function(err, res) {
                if (err) {
                    return done(err);
                }

                logOut(res, function(err) {
                    if (err) {
                        return done(err);
                    }

                    assert.deepEqual(['User#1'], userStore.userIdsLoggedOut);
                    done();
                });
            });
        });
    });

    describe('Using custom isAuthenticated func', function() {
        beforeEach(function(done) {
            app = configureExpress();

            configureLocalAuth(app, {
                isAuthenticated: function(req, cb) {
                    // Test-code only. Don't do this!
                    var userId = req.headers['magic-token'];

                    userStore.get(userId, function(err, user) {
                        if (err) {
                            return cb(err);
                        }
                        cb(null, user || false);
                    });
                }
            });

            app.get('/login', function(req, res) {
                res.send(200, 'Fake login view');
            });
            app.post('/login', localAuth.login(), function(req, res) {
                // Test-code only. Don't do this!
                res.set('magic-token', req.user.id);

                res.redirect(loginSuccessRedirectPath);
            });

            app.get('/private', localAuth.ensureAuthenticated(), function(req, res) {
                res.send(200, 'private stuff');
            });

            setupExistingUser(authService, userStore, existingUserEmail, existingUsername, existingUserPassword, done);
        });

        it('can use a custom isAuthenticted func to authenticate valid login', function(done) {
            logIn(existingUserEmail, existingUserPassword, function(err, res) {
                if (err) {
                    done(err);
                }
                var token = res.headers['magic-token'];

                request(app)
                    .get('/private')
                    .set('magic-token', token)
                    .expect(200, 'private stuff')
                    .end(done);
            });
        });

        it('can use a custom isAuthenticted func to block invalid login', function(done) {
            logIn(existingUserEmail, existingUserPassword, function(err, res) {
                if (err) {
                    done(err);
                }
                // var token = res.headers['magic-token'];

                request(app)
                    .get('/private')
                    // .set('magic-token', token)
                    .expect(302)
                    .expect('location', '/login')
                    .end(done);
            });
        });
    });

    function setupExistingUser(authService, userStore, email, username, password, done) {
        authService.hash(password, function(err, hashedPassword) {
            if (err) {
                return done(err);
            }

            var existingUser = {
                email: email,
                username: username,
                hashedPassword: hashedPassword
            };

            userStore.add(existingUser, function(err) {
                if (err) {
                    return done(err);
                }
                done();
            });
        });
    }

    function logIn(email, password, cb) {
        request(app)
            .post('/login')
            .send({ email: email, password: password })
            .expect(302)
            .expect('location', loginSuccessRedirectPath)
            .end(function(err, res) {
                if (err) {
                    return cb(err);
                }
                cb(null, res);
            });
    }

    function logOut(res, cb) {
        request(app)
            .get('/logout')
            .set('cookie', res.headers['set-cookie'])
            .expect(302)
            .expect('location', logoutSuccessRedirectPath)
            .end(function(err, res) {
                if (err) {
                    return cb(err);
                }
                cb(null, res);
            });
    }

    function verifyPostRedirectGet(app, path, sendData, /* opt: */ redirectPath, /* opt: */ options, verifyAfterGetFn, done) {

        // Allow for optional redirectPath and/or options:
        var args = [].slice.call(arguments);
        if (args.length === 5) {
            verifyAfterGetFn = redirectPath;
            done = options;
            redirectPath = null;
            options = null;
        } else if (args.length === 6) {
            if (typeof args[3] === 'string') {
                // We have optional redirectPath but not options:
                done = verifyAfterGetFn;
                verifyAfterGetFn = options;
                options = null;
            } else {
                // We have options but not redirectPath:
                done = verifyAfterGetFn;
                verifyAfterGetFn = options;
                options = redirectPath;
                redirectPath = null;
            }
        }

        redirectPath = redirectPath || path;
        options = options || {};

        request(app)
            .post(path)
            .send(sendData)
            .expect(302)
            .expect('location', redirectPath)
            .end(function(err, res) {
                if (err) {
                    return done(err);
                }

                var redirectPath = res.headers['location'];

                request(app)
                    .get(redirectPath)
                    .set('cookie', res.headers['set-cookie'])
                    .expect(options.expectedGetStatus || 200)
                    .expect(function(res) {
                        verifyAfterGetFn(res);
                    })
                    .end(done);
            });
    }
});