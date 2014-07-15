var assert = require('chai').assert,
    express = require('express'),
    session = require('express-session'),
    flash = require('connect-flash'),
    bodyParser = require('body-parser'),
    cookieParser = require('cookie-parser'),
    request = require('supertest'),
    FakeUserStore = require('./fakes/userStore'),
    FakeTokenStore = require('./fakes/tokenStore'),
    _ = require('lodash'),
    sinon = require('sinon'),
    registration = require('../src/index'),
    sentry = require('sentry');

describe('Registration', function() {

    var app, userStore, passwordResetTokenStore, fakeEmailService, fakeAuthService;
    var configureApp, configureExpress, configureSentry, configureStandardRoutes;

    beforeEach(function() {
        userStore = new FakeUserStore();
        passwordResetTokenStore = new FakeTokenStore();

        fakeEmailService = {
            sendRegistrationEmail: function(user, cb) {
                cb(null);
            },
            sendPasswordResetEmail: function(user, token, cb) {
                cb(null);
            },
            sendPasswordResetNotificationForUnregisteredEmail: function(email, cb) {
                cb(null);
            },
            sendPasswordChangedEmail: function(user, cb) {
                cb(null);
            }
        };

        fakeAuthService = {
            hashPassword: function(password, cb) {
                cb(null, 'hashed-' + password);
            },
            markLoggedInAfterAuthentication: function(req, user, cb) {
                cb(null);
            }
        };

        configureExpress = function(options) {
            options = options || {
                useSession: true
            };

            var app = express();
            app.use(express.static(__dirname + '/public'));
            app.set('views', __dirname + '/views');
            app.set('view engine', 'jade');
            app.use(bodyParser.json());

            if (options.useSession) {
                app.use(cookieParser());
                // Note: In a real app running with HTTPS, you should use following to limit cookie access:
                // session({..., cookie: { httpOnly: true, secure: true } })
                app.use(session({ secret: 'keyboard cat', resave: false, saveUninitialized: false } ));
                app.use(flash());
            }

            app.use(function(err, req, res, next) {
                console.error(err);
                res.send(500, err);
            });

            return app;
        };

        configureSentry = function(app, options) {
            options = options || {};

            var sentryOptions = _.defaults(options.sentry || {}, {
                userStore: userStore,
                emailService: fakeEmailService,
                auth: function() {
                    return {
                        service: fakeAuthService,
                        routeHandlers: {}
                    }
                },
                registration: registration(options.registration)
            });
            sentry.initialize(app, sentryOptions);
        };

        configureStandardRoutes = function(app) {
            app.post('/register', sentry.register(), function(req, res) {
                res.send(201);
            });
        };

        configureApp = function(options) {
            options = options || {};
            app = configureExpress();
            configureSentry(app, options);
            configureStandardRoutes(app);
            return app;
        };
    });

    describe('User Registration', function() {

        var registerValidationErrors, registerError;

        beforeEach(function() {
            app = configureExpress();
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
});