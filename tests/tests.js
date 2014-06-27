var assert = require('chai').assert,
    express = require('express'),
    request = require('supertest'),
    FakeUserStore = require('./fakes/userStore'),
    FakeTokenStore = require('./fakes/tokenStore'),
    _ = require('lodash'),
    sinon = require('sinon'),
    registration = require('../src/index');

describe('Registration', function() {

    var app, userStore, passwordResetTokenStore, authService, emailService, config, configure;

    beforeEach(function() {

        // todo: this is horrible. do something better
        config = {
            userIdGetter: function(user) {
                return user.userId
            }
        };

        userStore = new FakeUserStore();
        passwordResetTokenStore = new FakeTokenStore();

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
            },
            sendPasswordResetEmail: function(user, cb) {
                cb(null);
            },
            sendPasswordResetNotificationForUnregisteredEmail: function(email, cb) {
                cb(null);
            }
        };

        configure = function(options) {
            options = options || {};
            options.logger = { error: function(){} };

            var componentFactory = registration(options);
            var component = componentFactory(userStore, passwordResetTokenStore, authService, emailService, config);

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

        describe('Custom Responses', function() {
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
    });

    describe('Forgot Password', function() {

        var existingUserEmail, existingUserPassword;

        beforeEach(function() {
            existingUserEmail = 'foo@example.com';
            existingUserPassword = 'bar';

            emailService.sendPasswordResetEmail = sinon.stub().yields(null);
            emailService.sendPasswordResetNotificationForUnregisteredEmail = sinon.stub().yields(null);
        });

        describe('Full Successful Password Reset Flow', function() {
            xit('should allow successful password reset', function(done) {
                // todo
            });
        });

        describe('Step 1 - Requesting Reset', function() {

            it('requires valid email', function(done) {
                configure();
                request(app)
                    .post('/forgotpassword')
                    .send({ email: '' })
                    .expect(400, '{"email":{"param":"email","msg":"Valid email address required","value":""}}')
                    .end(done);
            });

            it('sends password reset email for existing account on entering matching email', function(done) {
                configure();

                registerUser(existingUserEmail, existingUserPassword, function(err) {
                    if (err) {
                        return done(err);
                    }

                    request(app)
                        .post('/forgotpassword')
                        .send({ email: existingUserEmail })
                        .expect(200)
                        .expect(function() {
                            var emailSentOk = emailService.sendPasswordResetEmail
                                .calledWith(sinon.match.has("email", existingUserEmail));
                            assert.isTrue(emailSentOk, 'Sends email');
                        })
                        .end(done);
                });
            });

            it('sends reset attempt notification email on entering unknown email', function(done) {
                configure();

                var unknownEmail = 'unknown_email@example.com';

                request(app)
                    .post('/forgotpassword')
                    .send({ email: unknownEmail })
                    .expect(200)
                    .expect(function() {
                        var called = emailService.sendPasswordResetNotificationForUnregisteredEmail.calledWith(unknownEmail);
                        assert.isTrue(called, 'Sends notification email');
                    })
                    .end(done);
            });

            xit('ensures user account not locked after sending password reset email to counter malicious reset requests', function(done) {
                configure();

                registerUser(existingUserEmail, existingUserPassword, function(err) {
                    if (err) {
                        return done(err);
                    }

                    requestPasswordReset(existingUserEmail, function(err) {
                        if (err) {
                            return done(err);
                        }

                        // TODO: HOW TO TEST THIS?

                        done();
                    });
                });
            });

            it('stores new password reset token for email', function(done) {
                configure();
                registerUser(existingUserEmail, existingUserPassword, function(err) {
                    if (err) {
                        return done(err);
                    }
                    requestPasswordReset(existingUserEmail, function(err) {
                        if (err) {
                            return done(err);
                        }

                        assert.lengthOf(passwordResetTokenStore.tokens, 1);

                        var tokenDetails = passwordResetTokenStore.tokens[0];
                        assert.equal(tokenDetails.email, existingUserEmail);
                        assert.isNotNull(tokenDetails.token);
                        assert.isNotNull(tokenDetails.expiry);

                        done();
                    });
                });
            });

            it('ensures password reset token does not contain any user identifiers to prevent guessing', function(done) {
                var email = 'user@example.com';
                var expectedUserId = 'User#1';

                configure();
                registerUser(email, existingUserPassword, function(err) {
                    if (err) {
                        return done(err);
                    }
                    requestPasswordReset(email, function(err) {
                        if (err) {
                            return done(err);
                        }

                        // Double-check the user ID is what we expect
                        assert.lengthOf(userStore.users, 1);
                        assert.equal(userStore.users[0].userId, expectedUserId);

                        var emailSentOk = emailService.sendPasswordResetEmail.calledWith(
                            sinon.match.has("email", email),
                            sinon.match(/^((?!user).)*$/i) // makes sure 'user' not present - which covers email address and user id
                        );
                        assert.isTrue(emailSentOk, 'Password reset URL does not contain any user identifier');

                        done();
                    });
                });
            });

            it('deletes any pending reset tokens for same email on receipt of a new password reset request', function(done) {
                configure();
                registerUser(existingUserEmail, existingUserPassword, function(err) {
                    if (err) {
                        return done(err);
                    }
                    requestPasswordReset(existingUserEmail, function (err) {
                        if (err) {
                            return done(err);
                        }

                        assert.lengthOf(passwordResetTokenStore.tokens, 1);
                        assert.equal(passwordResetTokenStore.tokens[0].tokenId, 'Token#1');

                        requestPasswordReset(existingUserEmail, function (err) {
                            if (err) {
                                return done(err);
                            }

                            assert.lengthOf(passwordResetTokenStore.tokens, 1);
                            assert.equal(passwordResetTokenStore.tokens[0].tokenId, 'Token#2');

                            done();
                        });
                    });
                });
            });

            describe('Custom Responses', function() {
                it('can return custom password reset email sent response', function(done) {
                    configure({
                        responses: {
                            passwordResetEmailSent: function(email, res) {
                                res.send(200, 'Custom response after password reset email sent to: ' + email);
                            }
                        }
                    });

                    var unknownEmail = 'unknown_email@example.com';

                    request(app)
                        .post('/forgotpassword')
                        .send({ email: unknownEmail })
                        .expect(200, 'Custom response after password reset email sent to: unknown_email@example.com')
                        .end(done);
                });
            });
        });

        describe('Step 2 - Visiting Reset URL', function() {

            it('ensures token is required', function(done) {
                configure();
                request(app)
                    .get('/forgotpassword/callback?token=')
                    .expect(400, '{"token":{"param":"token","msg":"Password reset token required","value":""}}')
                    .end(done);
            });

            it('ensures invalid password request tokens are ignored', function(done) {
                configure();
                request(app)
                    .get('/forgotpassword/callback?token=unknown')
                    .expect(400, 'Unknown or expired token')
                    .end(done);
            });

            it('ensures that password reset request is only valid for limited period of time', function(done) {
                configure();

                registerUser(existingUserEmail, existingUserPassword, function(err) {
                    if (err) {
                        return done(err);
                    }
                    requestPasswordReset(existingUserEmail, function (err) {
                        if (err) {
                            return done(err);
                        }

                        var expiredToken = setupExpiredPasswordResetToken();

                        request(app)
                            .get('/forgotpassword/callback?token=' + expiredToken)
                            .expect(400, 'Unknown or expired token')
                            .end(done);
                    });
                });
            });

            it('renders password reset response if password reset token is valid', function(done) {
                configure();

                registerUser(existingUserEmail, existingUserPassword, function(err) {
                    if (err) {
                        return done(err);
                    }
                    requestPasswordReset(existingUserEmail, function (err) {
                        if (err) {
                            return done(err);
                        }

                        assert.lengthOf(passwordResetTokenStore.tokens, 1);
                        var token = passwordResetTokenStore.tokens[0].token;

                        request(app)
                            .get('/forgotpassword/callback?token=' + token)
                            .expect(200, 'Update password')
                            .end(done);
                    });
                });
            });

            describe('Custom Responses', function() {

                it('can render custom bad password reset token page', function(done) {
                    configure({
                        responses: {
                            badPasswordResetTokenResponse: function(res) {
                                res.send(400, 'Custom bad token response');
                            }
                        }
                    });

                    registerUser(existingUserEmail, existingUserPassword, function(err) {
                        if (err) {
                            return done(err);
                        }
                        requestPasswordReset(existingUserEmail, function (err) {
                            if (err) {
                                return done(err);
                            }

                            var expiredToken = setupExpiredPasswordResetToken();

                            request(app)
                                .get('/forgotpassword/callback?token=' + expiredToken)
                                .expect(400, 'Custom bad token response')
                                .end(done);
                        });
                    });
                });

                it('can render custom password reset page', function(done) {
                    configure({
                        responses: {
                            resetPasswordPage: function(res) {
                                res.send(200, 'Custom update password response');
                            }
                        }
                    });

                    registerUser(existingUserEmail, existingUserPassword, function(err) {
                        if (err) {
                            return done(err);
                        }
                        requestPasswordReset(existingUserEmail, function (err) {
                            if (err) {
                                return done(err);
                            }

                            assert.lengthOf(passwordResetTokenStore.tokens, 1);
                            var token = passwordResetTokenStore.tokens[0].token;

                            request(app)
                                .get('/forgotpassword/callback?token=' + token)
                                .expect(200, 'Custom update password response')
                                .end(done);
                        });
                    });
                });
            });

            function setupExpiredPasswordResetToken() {

                // Make sure only 1 token in store and that it looks legit
                assert.lengthOf(passwordResetTokenStore.tokens, 1);
                var tokenObj = passwordResetTokenStore.tokens[0];
                assert.isNotNull(tokenObj.expiry);
                assert.typeOf(tokenObj.expiry, 'date');

                // expire token:
                tokenObj.expiry = new Date(Date.now() - 1);

                return tokenObj.token;
            }
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
            .end(cb);
    }

    function requestPasswordReset(email, cb) {
        request(app)
            .post('/forgotpassword')
            .send({ email: email })
            .expect(200)
            .end(cb);
    }
});
