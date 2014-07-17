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

describe('Forgot Password', function() {

    var app, userStore, passwordResetTokenStore;
    var configureApp, configureSentry, configureStandardRoutes;
    var existingUserEmail, existingUserPassword;

    beforeEach(function() {
        existingUserEmail = 'foo@example.com';
        existingUserPassword = 'bar';

        userStore = new FakeUserStore();
        passwordResetTokenStore = new FakeTokenStore();

        configureSentry = function(app, options) {
            utils.configureSentry(app, userStore, passwordResetTokenStore, fakeEmailService, fakeAuthService, options);
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

    describe('Step 1 - Requesting Reset', function() {

        var forgotPasswordValidationErrors;

        beforeEach(function() {
            configureApp();

            app.post('/forgotpassword', sentry.forgotPassword(), function(req, res) {
                var email = req.body.email;
                res.send(200, 'Password reset email sent to: ' + email);
            });
            app.get('/forgotpassword', function(req, res) {
                forgotPasswordValidationErrors = req.session.flash.validationErrors;
                res.send(200, 'Dummy forgot password page');
            });
        });

        it('requires valid email', function(done) {
            var postData = { email: '' };

            utils.verifyPostRedirectGet(app, '/forgotpassword', postData, done, function verifyAfterGet() {
                assert.deepEqual(forgotPasswordValidationErrors, [{
                    email: {
                        param: 'email',
                        msg: 'Valid email address required',
                        value: ''
                    }
                }]);
            });
        });

        it('sends password reset email for existing account on entering matching email', function(done) {
            fakeEmailService.sendPasswordResetEmail = sinon.stub().yields(null);

            registerUser(existingUserEmail, existingUserPassword, function(err) {
                if (err) {
                    return done(err);
                }

                request(app)
                    .post('/forgotpassword')
                    .send({ email: existingUserEmail })
                    .expect(200)
                    .expect(function() {
                        var emailSentOk = fakeEmailService.sendPasswordResetEmail.calledWith(
                            sinon.match.has("email", existingUserEmail)
                        );
                        assert.isTrue(emailSentOk, 'Sends email');
                    })
                    .end(done);
            });
        });

        it('sends reset attempt notification email on entering unknown email', function(done) {
            fakeEmailService.sendPasswordResetNotificationForUnregisteredEmail = sinon.stub().yields(null);

            var unknownEmail = 'unknown_email@example.com';

            request(app)
                .post('/forgotpassword')
                .send({ email: unknownEmail })
                .expect(200)
                .expect(function() {
                    var called = fakeEmailService.sendPasswordResetNotificationForUnregisteredEmail.calledWith(unknownEmail);
                    assert.isTrue(called, 'Sends notification email');
                })
                .end(done);
        });

        it('stores new password reset token for email', function(done) {
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
                    assert.equal(tokenDetails.userId, "User#1");
                    assert.isNotNull(tokenDetails.token);
                    assert.isNotNull(tokenDetails.expiry);

                    done();
                });
            });
        });

        it('ensures password reset token does not contain any user identifiers to prevent guessing', function(done) {
            var email = 'user@example.com';
            var expectedUserId = 'User#1';

            fakeEmailService.sendPasswordResetEmail = sinon.stub().yields(null);

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
                    assert.equal(userStore.users[0].id, expectedUserId);

                    var emailSentOk = fakeEmailService.sendPasswordResetEmail.calledWith(
                        sinon.match.has("email", email),
                        // param no. 2 is reset token
                        sinon.match(/^((?!user).)*$/i) // makes sure 'user' not present - which covers email address and user id
                    );
                    assert.isTrue(emailSentOk, 'Password reset URL does not contain any user identifier');

                    done();
                });
            });
        });

        it('deletes any pending reset tokens for same email on receipt of a new password reset request', function(done) {

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
    });

    describe('Step 2 - Visiting Reset URL', function() {

        var changePasswordValidationErrors, changePasswordError;

        beforeEach(function() {
            configureApp();

            app.post('/forgotpassword', sentry.forgotPassword(), function(req, res) {
                var email = req.body.email;
                res.send(200, 'Password reset email sent to: ' + email);
            });

            app.get('/changepassword', sentry.changePasswordView(), function(req, res) {
                changePasswordValidationErrors = req.session.flash ? req.session.flash.validationErrors : null;
                changePasswordError = req.session.flash ? req.session.flash.error : null;
                res.send(200, 'Dummy change password page with token: ' + req.query.token);
            });
        });

        it('ensures token is required', function(done) {
            var token = '';

            verifyChangePasswordErrors(token, done, function() {
                assert.deepEqual(changePasswordValidationErrors, [{
                    token: {
                        param: 'token',
                        msg: 'Password reset token required',
                        value: ''
                    }
                }]);
            });
        });

        it('ensures invalid password request tokens are ignored', function(done) {
            var token = 'unknown';

            verifyChangePasswordErrors(token, done, function() {
                assert.equal(changePasswordError, 'Unknown or expired token');
            });
        });

        it('ensures that password reset request is only valid for limited period of time', function(done) {
            registerUser(existingUserEmail, existingUserPassword, function(err) {
                if (err) {
                    return done(err);
                }
                requestPasswordReset(existingUserEmail, function (err) {
                    if (err) {
                        return done(err);
                    }

                    var expiredToken = setupExpiredPasswordResetToken();

                    verifyChangePasswordErrors(expiredToken, done, function() {
                        assert.equal(changePasswordError, 'Unknown or expired token');
                    });
                });
            });
        });

        it('renders password reset response if password reset token is valid', function(done) {
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
                    assert.ok(token);

                    request(app)
                        .get('/changepassword?token=' + token)
                        .expect(200, 'Dummy change password page with token: ' + token)
                        .end(done);
                });
            });
        });

        function verifyChangePasswordErrors(token, done, verifyAfterGetFn) {
            request(app)
                .get('/changepassword?token=' + token)
                .expect(302)
                .expect('location', '/changepassword')
                .end(function(err, res) {
                    if (err) {
                        return done(err);
                    }
                    request(app)
                        .get('/changepassword')
                        .set('cookie', res.headers['set-cookie'])
                        .expect(200)
                        .expect(function() {
                            verifyAfterGetFn();
                        })
                        .end(done);
                });
        }
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