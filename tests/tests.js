var assert = require('chai').assert,
    express = require('express'),
    bodyParser = require('body-parser'),
    request = require('supertest'),
    FakeUserStore = require('./fakes/userStore'),
    _ = require('lodash'),
    registration = require('../src/index');

describe('Registration', function() {

    var app, userStore, authService, emailService, config, configure;

    beforeEach(function() {

        // todo: this is horrible. do something better
        config = {
            userIdGetter: function(user) {
                return user.userId
            }
        };

        userStore = new FakeUserStore();

        authService = {
            hashPassword: function(password, cb) {
                cb(null, 'HASHED-' + password);
            },
            markLoggedInAfterAuthentication: function(req, user, callback) {
                callback(null);
            },
            logOut: function(req, user, callback) {
                callback(null);
            },
            responses: {
                unauthenticated: function(res) {
                    res.send(401);
                }
            }
        };

        emailService = {
            sendRegistrationEmail: function(userDetails, callback) {
                callback(null);
            }
        };

        configure = function(options) {
            options = options || {};
            options.logger = { error: function(){} };

            var componentFactory = registration(options);
            var component = componentFactory(userStore, authService, emailService, config);

            app = express();
            app.use(bodyParser());
            app.use(component.router);

            return app;
        };
    });

    describe('User Registration', function() {

        var loggedInUserId, simlulatedLogInErr, userDetailsSeenForRegEmail;

        beforeEach(function() {
            loggedInUserId = null;
            simlulatedLogInErr = null;
            userDetailsSeenForRegEmail = null;

            authService.markLoggedInAfterAuthentication = function(req, user, callback) {
                loggedInUserId = config.userIdGetter(user);
                callback(simlulatedLogInErr || null);
            };

            emailService = {
                sendRegistrationEmail: function(userDetails, callback) {
                    userDetailsSeenForRegEmail = _.clone(userDetails);
                    callback(null);
                }
            };
        });

        it('should allow registration with username and password', function(done) {
            configure();

            assert.lengthOf(userStore.users, 0);

            request(app)
                .post('/register')
                .send({ username: 'foo', password: 'bar'})
                .expect(201)
                .expect(function() {
                    assert.lengthOf(userStore.users, 1);
                    assert.deepEqual(userStore.users[0], {
                        username: 'foo',
                        userId: "User#1",
                        hashedPassword: 'HASHED-bar'
                    });
                })
                .end(done);
        });

        // tested indirectly above, but want to make it more explicit
        it('should not make unhashed password available for storage', function(done) {
            configure();

            request(app)
                .post('/register')
                .send({ username: 'foo', password: 'bar'})
                .expect(function() {
                    assert.lengthOf(userStore.users, 1);
                    assert.isUndefined(userStore.users[0].password);
                })
                .end(done);
        });

        it('should use auth service to log user in after registration', function(done) {
            configure();

            var userId = 99;
            userStore.fakeUserId = userId;

            request(app)
                .post('/register')
                .send({ username: 'foo', password: 'bar'})
                .expect(function() {
                    assert.equal(loggedInUserId, userId);
                })
                .end(done);
        });

        it('should return error if user cannot be logged in', function(done) {
            configure();

            userStore.fakeUserId = 99;
            simlulatedLogInErr = 'it blows up';

            request(app)
                .post('/register')
                .send({ username: 'foo', password: 'bar'})
                .expect(500, simlulatedLogInErr)
                .end(done);
        });

        it('should use email service to send registration email', function(done) {
            configure();

            userStore.fakeUserId = 99;

            request(app)
                .post('/register')
                .send({ username: 'foo', password: 'bar'})
                .expect(function() {
                    assert.equal(userDetailsSeenForRegEmail.userId, 99);
                    assert.equal(userDetailsSeenForRegEmail.username, 'foo');
                })
                .end(done);
        });

        it('should return new user id as successful registration response', function(done) {
            configure();

            var userId = 99;
            userStore.fakeUserId = userId;

            request(app)
                .post('/register')
                .send({ username: 'foo', password: 'bar'})
                .expect(201, userId.toString())
                .end(done);
        });
    });

    describe('User Unregistration', function() {

        it('should allow authenticated user to unregister', function(done) {
            var username = 'foo';
            var password = 'bar';

            authService.isAuthenticated = function(req, cb) {
                var authenticatedUser = {
                    username: username,
                    password: password
                };
                cb(null, authenticatedUser);
            };

            configure();

            registerUser(username, password, function(err) {
                if (err) {
                    return done(err);
                }

                request(app)
                    .post('/unregister')
                    .expect(200)
                    .end(done);
            });
        });

        it('should not allow unauthenticated user to unregister', function(done) {
            var username = 'foo';
            var password = 'bar';

            authService.isAuthenticated = function(req, cb) {
                var authenticatedUser = false;
                cb(null, authenticatedUser);
            };

            configure();

            registerUser(username, password, function(err) {
                if (err) {
                    return done(err);
                }

                request(app)
                    .post('/unregister')
                    .expect(401)
                    .end(done);
            });
        });
    });

    describe('Custom Responses', function() {

        it('can return custom successful registration response', function(done) {
            var userId = 99;
            userStore.fakeUserId = userId;

            configure({
                responses: {
                    registered: function(user, res) {
                        res.send(201, JSON.stringify({
                            transformed: config.userIdGetter(user)
                        }));
                    }
                }
            });

            var expectedResponseBody = JSON.stringify({
                transformed: userId
            });

            request(app)
                .post('/register')
                .send({ username: 'foo', password: 'bar'})
                .expect(201, expectedResponseBody)
                .end(done);
        });

        it('can return custom unregistered response', function(done) {
            var username = 'foo';
            var password = 'bar';
            setupAuthServiceToAuthenticateUser(username, password);

            configure({
                responses: {
                    unregistered: function(res) {
                        return res.redirect('/home');
                    }
                }
            });

            registerUser(username, password, function(err) {
                if (err) {
                    return done(err);
                }

                request(app)
                    .post('/unregister')
                    .expect(302)
                    .expect('location', '/home')
                    .end(done);
            });
        });
    });

    function setupAuthServiceToAuthenticateUser(username, password) {
        authService.isAuthenticated = function(req, cb) {
            var authenticatedUser = {
                username: username,
                password: password
            };
            cb(null, authenticatedUser);
        };
    }

    function registerUser(username, password, cb) {
        request(app)
            .post('/register')
            .send({ username: username, password: password})
            .expect(201)
            .end(function(err, res) {
                if (err) {
                    return done(err);
                }
                cb(null, res);
            });
    }
});
