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
            var verifyEmailTokenStore = new FakeTokenStore();
            utils.configureSentry(app, userStore, passwordResetTokenStore, verifyEmailTokenStore, fakeEmailService, fakeAuthService, options);
        };

        configureStandardRoutes = function(app) {
            app.post('/register', sentry.register(), function(req, res) {
                res.send(201);
            });
            app.post('/unregister', sentry.unregister(), function(req, res) {
                res.send('unregistered');
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
                res.send('Password reset email sent to: ' + email);
            });
            app.get('/forgotpassword', function(req, res) {
                forgotPasswordValidationErrors = req.session.flash.validationErrors;
                res.send('Dummy forgot password page');
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

        it('sends forgot password email for existing account on entering matching email', function(done) {
            fakeEmailService.sendForgotPasswordEmail = sinon.stub().yields(null);

            registerUser(existingUserEmail, existingUserPassword, function(err) {
                if (err) {
                    return done(err);
                }

                request(app)
                    .post('/forgotpassword')
                    .send({ email: existingUserEmail })
                    .expect(200)
                    .expect(function() {
                        var emailSentOk = fakeEmailService.sendForgotPasswordEmail.calledWith(
                            sinon.match.has("email", existingUserEmail)
                        );
                        assert.isTrue(emailSentOk, 'Sends email');
                    })
                    .end(done);
            });
        });

        it('sends forgot password attempt notification email on entering unknown email', function(done) {
            fakeEmailService.sendForgotPasswordNotificationForUnregisteredEmail = sinon.stub().yields(null);

            var unknownEmail = 'unknown_email@example.com';

            request(app)
                .post('/forgotpassword')
                .send({ email: unknownEmail })
                .expect(200)
                .expect(function() {
                    var called = fakeEmailService.sendForgotPasswordNotificationForUnregisteredEmail.calledWith(unknownEmail);
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

            fakeEmailService.sendForgotPasswordEmail = sinon.stub().yields(null);

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

                    var emailSentOk = fakeEmailService.sendForgotPasswordEmail.calledWith(
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

        var resetPasswordValidationErrors, resetPasswordError;

        beforeEach(function() {
            configureApp();

            app.post('/forgotpassword', sentry.forgotPassword(), function(req, res) {
                var email = req.body.email;
                res.send('Password reset email sent to: ' + email);
            });

            app.get('/resetpassword', sentry.resetPasswordView(), function(req, res) {
                resetPasswordValidationErrors = res.locals.validationErrors;
                resetPasswordError = res.locals.error;
                res.send('Dummy reset password page with token: ' + req.query.token);
            });
        });

        it('ensures token is required', function(done) {
            var token = '';

            request(app)
                .get('/resetpassword?token=' + token)
                .expect(400)
                .expect(function() {
                    assert.deepEqual(resetPasswordValidationErrors, {
                        token: {
                            param: 'token',
                            msg: 'Password reset token required',
                            value: ''
                        }
                    });
                })
                .end(done);
        });

        it('ensures invalid password request tokens are ignored', function(done) {
            var token = 'unknown';

            request(app)
                .get('/resetpassword?token=' + token)
                .expect(400)
                .expect(function() {
                    assert.equal(resetPasswordError, 'Unknown or expired token');
                })
                .end(done);
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

                    request(app)
                        .get('/resetpassword?token=' + expiredToken)
                        .expect(400)
                        .expect(function() {
                            assert.equal(resetPasswordError, 'Unknown or expired token');
                        })
                        .end(done);
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
                        .get('/resetpassword?token=' + token)
                        .expect(200, 'Dummy reset password page with token: ' + token)
                        .end(done);
                });
            });
        });
    });

    describe('Step 3 - Changing Password', function() {

        var passwordResetToken, resetPasswordValidationErrors, resetPasswordError;

        beforeEach(function(done) {
            configureApp();

            app.post('/forgotpassword', sentry.forgotPassword(), function(req, res) {
                var email = req.body.email;
                res.send('Password reset email sent to: ' + email);
            });

            app.get('/resetpassword', sentry.resetPasswordView(), function(req, res) {
                resetPasswordValidationErrors = req.session.flash ? req.session.flash.validationErrors : null;
                resetPasswordError = req.session.flash ? req.session.flash.error : null;
                res.send('Dummy reset password page with token ' + req.query.token);
            });

            app.post('/resetpassword', sentry.resetPassword(), function(req, res) {
                res.send('Password reset');
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
                    passwordResetToken = passwordResetTokenStore.tokens[0].token;
                    assert.ok(passwordResetToken);

                    done();
                });
            });
        });

        it('ensures token is required', function(done) {
            var postData = { password: 'foo', confirmPassword: 'foo', token: '' };

            utils.verifyPostRedirectGet(app, '/resetpassword', postData, done, function verifyAfterGet() {
                assert.deepEqual(resetPasswordValidationErrors, [{
                    token: {
                        param: 'token',
                        msg: 'Password reset token required',
                        value: ''
                    }
                }]);
            });
        });

        it('ensures password is required', function(done) {
            var postData = { password: '', confirmPassword: 'foo', token: passwordResetToken };
            var expectedRedirectPath = '/resetpassword?token=' + passwordResetToken;

            utils.verifyPostRedirectGet(app, '/resetpassword', postData, expectedRedirectPath, done, function verifyAfterGet(res) {
                assert.deepEqual(resetPasswordValidationErrors, [{
                    password: {
                        param: 'password',
                        msg: 'New password required',
                        value: ''
                    }
                }]);

                // Ensure token is preserved during redirect:
                assert.equal(res.text, 'Dummy reset password page with token ' + passwordResetToken)
            });
        });

        it('ensures confirm password is required', function(done) {
            var postData = { password: 'foo', confirmPassword: '', token: passwordResetToken };
            var expectedRedirectPath = '/resetpassword?token=' + passwordResetToken;

            utils.verifyPostRedirectGet(app, '/resetpassword', postData, expectedRedirectPath, done, function verifyAfterGet(res) {
                assert.deepEqual(resetPasswordValidationErrors, [{
                    confirmPassword: {
                        param: 'confirmPassword',
                        msg: 'Password confirmation required',
                        value: ''
                    }
                }]);

                // Ensure token is preserved during redirect:
                assert.equal(res.text, 'Dummy reset password page with token ' + passwordResetToken)
            });
        });

        it('ensures password matches confirm password', function(done) {
            var postData = { password: 'foo', confirmPassword: 'not-foo', token: passwordResetToken };
            var expectedRedirectPath = '/resetpassword?token=' + passwordResetToken;

            utils.verifyPostRedirectGet(app, '/resetpassword', postData, expectedRedirectPath, done, function verifyAfterGet(res) {
                assert.deepEqual(resetPasswordValidationErrors, [{
                    confirmPassword: {
                        param: 'confirmPassword',
                        msg: 'Password and confirm password do not match',
                        value: 'not-foo'
                    }
                }]);

                // Ensure token is preserved during redirect:
                assert.equal(res.text, 'Dummy reset password page with token ' + passwordResetToken)
            });
        });

        it('ensures invalid password request tokens are ignored', function(done) {
            var postData = { password: 'foo', confirmPassword: 'foo', token: 'unknown-token' };
            var expectedRedirectPath = '/resetpassword?token=unknown-token';

            utils.verifyPostRedirectGet(app, '/resetpassword', postData, expectedRedirectPath, done, function verifyAfterGet(res) {
                assert.equal(resetPasswordError, 'Unknown or expired token');
            }, {
                expectedGetStatus: 400
            });
        });

        it('ensures password reset tokens for unknown users are ignored', function(done) {
            var token;
            capturePasswordResetToken(function(_token) {
                token = _token;
            });

            var email = 'anotheruser@foo.com';

            registerUser(email, 'password', function(err) {
                if (err) {
                    return done(err);
                }
                requestPasswordReset(email, function (err) {
                    if (err) {
                        return done(err);
                    }

                    // Make sure the password reset token won't match any user:
                    _.each(userStore.users, function(user, i) {
                        user.id = 'Unknown-User-' + i;
                    });

                    var postData = { password: 'foo', confirmPassword: 'foo', token: token };
                    var expectedRedirectPath = '/resetpassword?token=' + token;

                    utils.verifyPostRedirectGet(app, '/resetpassword', postData, expectedRedirectPath, done, function verifyAfterGet() {
                        assert.equal(resetPasswordError, 'Unknown or expired token');
                    });
                });
            });
        });

        it('allows password to be reset', function(done) {

            var newPassword = existingUserPassword + '-new';

            request(app)
                .post('/resetpassword')
                .send({ password: newPassword, confirmPassword: newPassword, token: passwordResetToken })
                .expect(200, 'Password reset')
                .expect(function() {
                    assert.lengthOf(userStore.users, 1);
                    var user = userStore.users[0];
                    assert.equal(user.hashedPassword, 'hashed-' + newPassword);
                })
                .end(done);
        });

        it('deletes password reset token after password reset', function(done) {
            assert.lengthOf(passwordResetTokenStore.tokens, 1);

            resetPassword(passwordResetToken, 'new-password', function(err) {
                if (err) {
                    return done(err);
                }

                assert.lengthOf(passwordResetTokenStore.tokens, 0);
                done();
            });
        });

        it('emails user confirmation of change after password reset', function(done) {

            fakeEmailService.sendPasswordResetEmail = sinon.stub().yields(null);

            resetPassword(passwordResetToken, 'new-password', function(err) {
                if (err) {
                    return done(err);
                }

                assert.isTrue(fakeEmailService.sendPasswordResetEmail.calledWith(
                    sinon.match.has('email', existingUserEmail)
                ), 'User is emailed password reset confirmation');

                done();
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

    function capturePasswordResetToken(callback) {
        fakeEmailService.sendForgotPasswordEmail = function(user, token, cb) {
            callback(token);
            cb(null);
        };
    }

    function resetPassword(token, newPassword, cb) {
        request(app)
            .post('/resetpassword')
            .send({ password: newPassword, confirmPassword: newPassword, token: token })
            .expect(200, 'Password reset')
            .end(cb);
    }
});