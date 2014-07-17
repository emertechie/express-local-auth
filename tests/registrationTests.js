var assert = require('chai').assert,
    request = require('supertest'),
    FakeUserStore = require('./fakes/userStore'),
    FakeTokenStore = require('./fakes/tokenStore'),
    fakeEmailService = require('./fakes/fakeEmailService'),
    fakeAuthService = require('./fakes/fakeAuthService'),
    utils = require('./utils'),
    _ = require('lodash'),
    sinon = require('sinon'),
    sentry = require('sentry');

describe('Registration', function() {

    var app, userStore;
    var configureApp, configureSentry, configureStandardRoutes;

    beforeEach(function() {
        userStore = new FakeUserStore();

        configureSentry = function(app, options) {
            utils.configureSentry(app, userStore, new FakeTokenStore(), fakeEmailService, fakeAuthService, options);
        };

        configureStandardRoutes = function(app) {
            app.post('/register', sentry.register(), function(req, res) {
                res.send(201);
            });
            app.post('/unregister', sentry.unregister(), function(req, res) {
                res.send(200, 'unregistered');
            });
        };

        configureApp = function(options) {
            options = options || {};
            app = utils.configureExpress();
            configureSentry(app, options);
            configureStandardRoutes(app);
            return app;
        };
    });

    describe('User Registration', function() {

        var registerValidationErrors, registerError;

        beforeEach(function() {
            app = utils.configureExpress();
            configureSentry(app);

            app.post('/register', sentry.register(), function(req, res) {
                // Should have redirected before here on errors
                res.send(201);
                // Normally something like: res.redirect('/home');
            });
            app.get('/register', function(req, res) {
                // Capture values for test
                registerValidationErrors = req.session.flash.validationErrors;
                registerError = req.session.flash.error;
                res.send(200, 'dummy register page');
            });
        });

        it('should require email address', function(done) {
            verifyRegisterValidationErrors('', 'bar', done, function() {
                assert.lengthOf(registerValidationErrors, 1);
                var error = registerValidationErrors[0].email;
                assert.equal(error.param, 'email');
                assert.equal(error.msg, 'Valid email address required');
            });
        });

        it('should require valid email address', function(done) {
            verifyRegisterValidationErrors('foo', 'bar', done, function() {
                assert.lengthOf(registerValidationErrors, 1);
                var error = registerValidationErrors[0].email;
                assert.equal(error.param, 'email');
                assert.equal(error.msg, 'Valid email address required');
            });
        });

        it('should require password', function(done) {
            verifyRegisterValidationErrors('foo@bar.com', '', done, function() {
                assert.lengthOf(registerValidationErrors, 1);
                var error = registerValidationErrors[0].password;
                assert.equal(error.param, 'password');
                assert.equal(error.msg, 'Password required');
            });
        });

        it('should allow registration with username, email and password', function(done) {
            assert.lengthOf(userStore.users, 0);

            request(app)
                .post('/register')
                .send({ username: 'foo', email: 'foo@example.com', password: 'bar'})
                .expect(201)
                .expect(function() {
                    assert.lengthOf(userStore.users, 1);
                    assert.deepEqual(userStore.users[0], {
                        username: 'foo',
                        email: 'foo@example.com',
                        id: "User#1",
                        hashedPassword: 'hashed-bar'
                    });
                })
                .end(done);
        });

        it('should allow registration with just email and password and username defaults to email', function(done) {
            assert.lengthOf(userStore.users, 0);

            request(app)
                .post('/register')
                .send({ email: 'foo@example.com', password: 'bar'})
                .expect(201)
                .expect(function() {
                    assert.lengthOf(userStore.users, 1);
                    assert.deepEqual(userStore.users[0], {
                        username: 'foo@example.com',
                        email: 'foo@example.com',
                        id: "User#1",
                        hashedPassword: 'hashed-bar'
                    });
                })
                .end(done);
        });

        it('should use auth service to log user in after registration', function(done) {
            assert.lengthOf(userStore.users, 0);

            var loggedInUserId;
            fakeAuthService.markLoggedInAfterAuthentication = function(req, user, callback) {
                loggedInUserId = user.id;
                callback(null);
            };

            request(app)
                .post('/register')
                .send({ email: 'foo@example.com', password: 'bar'})
                .expect(function() {
                    assert.equal(loggedInUserId, 'User#1');
                })
                .end(done);
        });

        it('should prevent same user registering more than once', function(done) {
            assert.lengthOf(userStore.users, 0);

            request(app)
                .post('/register')
                .send({ email: 'foo@example.com', password: 'bar'})
                .expect(201)
                .end(function() {

                    assert.notOk(registerError, 'Unexpected error found');

                    request(app)
                        .post('/register')
                        .send({ email: 'foo@example.com', password: 'bar'})
                        .expect(302)
                        .expect('location', '/register')
                        .end(function(err, res) {
                            if (err) {
                                return done(err);
                            }

                            request(app)
                                .get('/register')
                                .set('cookie', res.headers['set-cookie'])
                                .expect(200)
                                .expect(function() {
                                    assert.equal(registerError, 'Registration details already in use', 'Error found');
                                })
                                .end(done);
                        });
                });
        });

        // tested indirectly in test(s) above, but want to make it more explicit
        it('should not make unhashed password available for storage', function(done) {
            request(app)
                .post('/register')
                .send({ email: 'foo@example.com', password: 'bar'})
                .expect(function() {
                    assert.lengthOf(userStore.users, 1);
                    assert.isUndefined(userStore.users[0].password);
                })
                .end(done);
        });

        it('should use email service to send registration email', function(done) {

            assert.lengthOf(userStore.users, 0);

            var userForRegEmail;
            fakeEmailService.sendRegistrationEmail = function(userDetails, callback) {
                userForRegEmail = _.clone(userDetails);
                callback(null);
            };

            request(app)
                .post('/register')
                .send({ email: 'foo@example.com', username: 'foo', password: 'bar'})
                .expect(function() {
                    assert.equal(userForRegEmail.id, 'User#1');
                    assert.equal(userForRegEmail.email, 'foo@example.com');
                    assert.equal(userForRegEmail.username, 'foo');
                })
                .end(done);
        });

        function verifyRegisterValidationErrors(email, password, done, redirectVerifyFn) {
            request(app)
                .post('/register')
                .send({ email: email, password: password })
                .expect(302)
                .expect('location', '/register')
                .end(function(err, res) {
                    if (err) {
                        return done(err);
                    }

                    request(app)
                        .get('/register')
                        .set('cookie', res.headers['set-cookie'])
                        .expect(200)
                        .expect(function() {
                            assert.ok(registerValidationErrors, 'Validation errors found');
                            redirectVerifyFn();
                        })
                        .end(done);
                });
        }
    });

    describe('User Unregistration', function() {

        var email, password;

        beforeEach(function() {
            configureApp();

            email = 'foo@example.com';
            password = 'bar';
        });

        it('should log existing user out when unregistering', function(done) {
            setUpExistingUser(email, password, function(err) {
                if (err) {
                    return done(err);
                }

                var mock = sinon.mock(fakeAuthService);
                mock.expects("logOut").once().yields(null);

                request(app)
                    .post('/unregister')
                    .expect(200, 'unregistered')
                    .expect(function() {
                        mock.verify();
                    })
                    .end(done);
            });
        });

        it('should remove existing user from userStore when unregistering', function(done) {
            setUpExistingUser(email, password, function(err) {
                if (err) {
                    return done(err);
                }

                assert.lengthOf(userStore.users, 1);

                request(app)
                    .post('/unregister')
                    .expect(200, 'unregistered')
                    .expect(function() {
                        assert.lengthOf(userStore.users, 0);
                    })
                    .end(done);
            });
        });

        it('should redirect unknown user to login page when unregistering', function(done) {
            fakeAuthService.isAuthenticated = function(req, cb) {
                var authenticatedUser = false;
                cb(null, authenticatedUser);
            };

            request(app)
                .post('/unregister')
                .expect(302)
                .expect('location', '/login')
                .end(done);
        });

        function setUpExistingUser(email, password, cb) {

            // Set up registered user
            registerUser(email, password, function(err) {
                if (err) {
                    return cb(err);
                }

                // Set up auth service to authenticate user:
                fakeAuthService.isAuthenticated = function(req, cb) {
                    var authenticatedUser = {
                        id: userStore.users[0].id,
                        email: email,
                        username: email,
                        password: password
                    };
                    cb(null, authenticatedUser);
                };

                cb();
            });
        }
    });

    function registerUser(email, password, cb) {
        request(app)
            .post('/register')
            .send({ email: email, password: password})
            .expect(201)
            .end(cb);
    }
});