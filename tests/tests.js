var assert = require('chai').assert,
    express = require('express'),
    request = require('supertest'),
    FakeUserStore = require('./fakes/userStore'),
    _ = require('lodash'),
    sinon = require('sinon'),
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

        it('should require email address', function(done) {
            configure();
            request(app)
                .post('/register')
                .send({ email: '', password: 'bar'})
                .expect(400, '{"email":{"param":"email","msg":"Valid email address required","value":""}}')
                .end(done);
        });

        it('should require valid email address', function(done) {
            configure();
            request(app)
                .post('/register')
                .send({ email: 'foo', password: 'bar'})
                .expect(400, '{"email":{"param":"email","msg":"Valid email address required","value":"foo"}}')
                .end(done);
        });

        it('should require password', function(done) {
            configure();
            request(app)
                .post('/register')
                .send({ email: 'foo@example.com', password: ''})
                .expect(400, '{"password":{"param":"password","msg":"Password required","value":""}}')
                .end(done);
        });

        it('should allow registration with username, email and password', function(done) {
            configure();

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
                        userId: "User#1",
                        hashedPassword: 'HASHED-bar'
                    });
                })
                .end(done);
        });

        it('should allow registration with just email and password and username defaults to email', function(done) {
            configure();

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
                .send({ email: 'foo@example.com', password: 'bar'})
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
                .send({ email: 'foo@example.com', password: 'bar'})
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
                .send({ email: 'foo@example.com', password: 'bar'})
                .expect(500, simlulatedLogInErr)
                .end(done);
        });

        it('should use email service to send registration email', function(done) {
            configure();

            userStore.fakeUserId = 99;

            request(app)
                .post('/register')
                .send({ email: 'foo@example.com', username: 'foo', password: 'bar'})
                .expect(function() {
                    assert.equal(userDetailsSeenForRegEmail.userId, 99);
                    assert.equal(userDetailsSeenForRegEmail.email, 'foo@example.com');
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
                .send({ email: 'foo@example.com', password: 'bar'})
                .expect(201, userId.toString())
                .end(done);
        });
    });

    describe('User Unregistration', function() {

        it('should allow authenticated user to unregister', function(done) {
            var email = 'foo@example.com';
            var password = 'bar';

            authService.isAuthenticated = function(req, cb) {
                var authenticatedUser = {
                    email: email,
                    username: email,
                    password: password
                };
                cb(null, authenticatedUser);
            };

            configure();

            registerUser(email, password, function(err) {
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
            var email = 'foo@example.com';
            var password = 'bar';

            authService.isAuthenticated = function(req, cb) {
                var authenticatedUser = false;
                cb(null, authenticatedUser);
            };

            configure();

            registerUser(email, password, function(err) {
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
                .send({ email: 'foo@example.com', password: 'bar'})
                .expect(201, expectedResponseBody)
                .end(done);
        });

        it('can return custom registration validation error response', function(done) {
            configure({
                responses: {
                    registrationValidationErrors: function(errors, req, res) {
                        var invalidProps = _.keys(errors);
                        res.send(400, 'Custom validation error message for ' + JSON.stringify(invalidProps))
                    }
                }
            });

            request(app)
                .post('/register')
                .send({ email: '', password: ''})
                .expect(400, 'Custom validation error message for ["email","password"]')
                .end(done);
        });

        it('can return custom unregistered response', function(done) {
            var email = 'foo@example.com';
            var password = 'bar';
            setupAuthServiceToAuthenticateUser(email, password);

            configure({
                responses: {
                    unregistered: function(res) {
                        return res.redirect('/home');
                    }
                }
            });

            registerUser(email, password, function(err) {
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

    describe('Forgot Password', function() {

        describe('Full Successful Password Reset Flow', function() {
            xit('should allow successful password reset', function(done) {
                // todo
            });
        });

        describe('Step 1 - Requesting Reset', function() {

            xit('sends password reset email for existing account on entering matching email', function(done) {
                configure();

                /*request(app)
                    .post('/forgotpassword')
                    .set({ email:  })*/

                // todo
            });

            xit('sends reset attempt notification email on entering unknown email', function(done) {
                // todo
            });

            xit('ensures user account not locked after sending password reset email to counter malicious reset requests', function(done) {
                // todo
            });

            xit('ensures password reset URL does not contain any user identifiers to prevent guessing', function(done) {
                // todo
            });

            xit('invalidates any pending reset requests on receipt of a new password reset request', function(done) {
                // todo
            });
        });

        describe('Step 2 - Visiting Reset URL', function() {

            xit('ensures invalid password request tokens are ignored', function(done) {
                // todo
            });

            xit('ensures that password reset request is only valid for limited period of time', function(done) {
                // todo
                // maybe set up PasswordResetTokenStore with a predefined record with a timestamp < now and test it fails
            });
        });

        describe('Step 3 - Changing Password', function() {
            xit('allows password to be changed', function(done) {
                // todo
            });

            xit('deletes password reset token after password changed', function(done) {
                // todo
            });

            xit('emails user confirmation of change after password changed', function(done) {
                // todo
            });
        });
    });
    
    function setupAuthServiceToAuthenticateUser(email, password) {
        authService.isAuthenticated = function(req, cb) {
            var authenticatedUser = {
                email: email,
                username: email,
                password: password
            };
            cb(null, authenticatedUser);
        };
    }

    function registerUser(email, password, cb) {
        request(app)
            .post('/register')
            .send({ email: email, password: password})
            .expect(201)
            .end(function(err, res) {
                if (err) {
                    return done(err);
                }
                cb(null, res);
            });
    }
});
