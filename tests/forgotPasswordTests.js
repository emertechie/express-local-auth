var assert = require('chai').assert,
    request = require('supertest'),
    FakeUserStore = require('./fakes/userStore'),
    FakeTokenStore = require('./fakes/tokenStore'),
    fakeEmailService = require('./fakes/fakeEmailService'),
    utils = require('./utils'),
    _ = require('lodash'),
    sinon = require('sinon');

describe('Forgot Password', function() {

    var app, localAuth, userStore, passwordResetTokenStore;
    var configureApp, configureLocalAuth, configureStandardRoutes;
    var existingUserEmail, existingUserPassword;

    beforeEach(function() {
        existingUserEmail = 'foo@example.com';
        existingUserPassword = 'bar';

        userStore = new FakeUserStore();
        passwordResetTokenStore = new FakeTokenStore();

        configureLocalAuth = function(app, options) {
            localAuth = utils.configureLocalAuth(app, {
                userStore: userStore,
                passwordResetTokenStore: passwordResetTokenStore,
                emailService: fakeEmailService
            }, options);
        };

        configureStandardRoutes = function(app) {
            app.post('/register', localAuth.register(), function(req, res) {
                res.send(201);
            });
            app.post('/unregister', localAuth.unregister(), function(req, res) {
                res.send('unregistered');
            });
        };

        configureApp = function(options) {
            options = options || {};
            app = utils.configureExpress();
            configureLocalAuth(app, options);
            configureStandardRoutes(app);
            return app;
        };
    });

    describe('Step 1 - Requesting Reset', function() {

        var forgotPasswordValidationErrors;

        beforeEach(function() {
            configureApp();

            app.post('/forgotpassword', localAuth.forgotPassword(), function(req, res) {
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

            utils.verifyPostRedirectGet(app, '/forgotpassword', postData, function verifyAfterGet() {
                assert.deepEqual(forgotPasswordValidationErrors, [{
                    email: {
                        param: 'email',
                        msg: 'Valid email address required',
                        value: ''
                    }
                }]);
            }, done);
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

        it('ignores case of email when sending forgot password email', function(done) {
            fakeEmailService.sendForgotPasswordEmail = sinon.stub().yields(null);

            registerUser(existingUserEmail, existingUserPassword, function(err) {
                if (err) {
                    return done(err);
                }

                var uppercaseEmail = existingUserEmail.toUpperCase();

                request(app)
                    .post('/forgotpassword')
                    .send({ email: uppercaseEmail })
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
                    assert.isNotNull(tokenDetails.hashedToken);
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
                        // param no. 2 is query string in form: '?email=xxx&token=yyy', so just checking the token param:
                        sinon.match(/.*&((?!user).)*$/i) // makes sure 'user' not present - which covers email address and user id
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

    describe('Step 1 - Requesting Reset (when email verification required)', function() {

        var forgotPasswordErrors;

        beforeEach(function () {
            configureApp({
                verifyEmail: true
            });

            app.post('/forgotpassword', localAuth.forgotPassword(), function (req, res) {
                var email = req.body.email;
                res.send('Password reset email sent to: ' + email);
            });
            app.get('/forgotpassword', function (req, res) {
                forgotPasswordErrors = req.flash('errors');
                res.send('Dummy forgot password page');
            });
        });

        it('forbids resetting password if user email not previously verified', function(done) {
            assert.lengthOf(userStore.users, 0);

            registerUser(existingUserEmail, existingUserPassword, function(err) {
                if (err) {
                    return done(err);
                }

                assert.lengthOf(userStore.users, 1);
                assert.isFalse(userStore.users[0].emailVerified);

                var postData = { email: existingUserEmail };

                utils.verifyPostRedirectGet(app, '/forgotpassword', postData, function verifyAfterGet() {
                    var expectedMsg = 'Please verify your email address first by clicking on the link in the registration email';
                    assert.deepEqual(forgotPasswordErrors, [ expectedMsg ]);
                }, done);
            });
        });

        it('sends forgot password email if user email previously verified', function(done) {
            fakeEmailService.sendForgotPasswordEmail = sinon.stub().yields(null);

            assert.lengthOf(userStore.users, 0);

            registerUser(existingUserEmail, existingUserPassword, function(err) {
                if (err) {
                    return done(err);
                }

                // Mark email verified (this functionality tested elsewhere)
                assert.lengthOf(userStore.users, 1);
                userStore.users[0].emailVerified = true;

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
    });

    describe('Step 2 - Visiting Reset URL', function() {

        var passwordResetToken;
        var resetPasswordValidationErrors, resetPasswordErrors;

        beforeEach(function(done) {
            configureApp();

            app.post('/forgotpassword', localAuth.forgotPassword(), function(req, res) {
                var email = req.body.email;
                res.send('Password reset email sent to: ' + email);
            });

            app.get('/resetpassword', localAuth.resetPasswordView(), function(req, res) {
                resetPasswordValidationErrors = res.locals.validationErrors;
                resetPasswordErrors = res.locals.errors;
                res.send('Dummy reset password page with token: ' + req.query.token);
            });

            // Set up an existing forgot password request:
            assert.lengthOf(passwordResetTokenStore.tokens, 0);
            registerUser(existingUserEmail, existingUserPassword, function(err) {
                if (err) {
                    return done(err);
                }
                requestPasswordReset(existingUserEmail, function (err, unhashedToken) {
                    if (err) {
                        return done(err);
                    }

                    assert.lengthOf(passwordResetTokenStore.tokens, 1);
                    assert.ok(unhashedToken);
                    passwordResetToken = unhashedToken;

                    done();
                });
            });
        });

        it('ensures email is required', function(done) {
            request(app)
                .get('/resetpassword?email=&token=' + passwordResetToken)
                .expect(400)
                .expect(function() {
                    assert.deepEqual(resetPasswordValidationErrors, [{
                        email: {
                            param: 'email',
                            msg: 'Email address required',
                            value: ''
                        }
                    }]);
                })
                .end(done);
        });

        it('ensures token is required', function(done) {
            var token = '';

            request(app)
                .get('/resetpassword?email=' + existingUserEmail + '&token=' + token)
                .expect(400)
                .expect(function() {
                    assert.deepEqual(resetPasswordValidationErrors, [{
                        token: {
                            param: 'token',
                            msg: 'Password reset token required',
                            value: ''
                        }
                    }]);
                })
                .end(done);
        });

        it('ensures invalid password request tokens are ignored', function(done) {
            var token = 'unknown';

            request(app)
                .get('/resetpassword?email=' + existingUserEmail + '&token=' + token)
                .expect(400)
                .expect(function() {
                    assert.deepEqual(resetPasswordErrors, [ 'Unknown or expired token' ]);
                })
                .end(done);
        });

        it('ensures that password reset request is only valid for limited period of time', function(done) {
            // expire the existing token:
            assert.lengthOf(passwordResetTokenStore.tokens, 1);
            passwordResetTokenStore.tokens[0].expiry = new Date(Date.now() - 1);

            request(app)
                .get('/resetpassword?email=' + existingUserEmail + '&token=' + passwordResetToken)
                .expect(400)
                .expect(function() {
                    assert.deepEqual(resetPasswordErrors, [ 'Unknown or expired token' ]);
                })
                .end(done);
        });

        it('renders password reset response if password reset token is valid', function(done) {
            request(app)
                .get('/resetpassword?email=' + existingUserEmail + '&token=' + passwordResetToken)
                .expect(200, 'Dummy reset password page with token: ' + passwordResetToken)
                .end(done);
        });

        it('ignores case of email when rendering password reset response', function(done) {
            var uppercaseEmail = existingUserEmail.toUpperCase();
            request(app)
                .get('/resetpassword?email=' + uppercaseEmail + '&token=' + passwordResetToken)
                .expect(200, 'Dummy reset password page with token: ' + passwordResetToken)
                .end(done);
        });
    });

    describe('Step 3 - Resetting Password', function() {

        var passwordResetToken, resetPasswordValidationErrors, resetPasswordErrors;

        beforeEach(function(done) {
            configureApp();

            app.post('/forgotpassword', localAuth.forgotPassword(), function(req, res) {
                var email = req.body.email;
                res.send('Password reset email sent to: ' + email);
            });

            app.get('/resetpassword', localAuth.resetPasswordView(), function(req, res) {
                resetPasswordValidationErrors = req.flash ? req.flash('validationErrors') : null;
                resetPasswordErrors = req.flash ? req.flash('errors') : null;
                res.send('Dummy reset password page with token ' + req.query.token);
            });

            app.post('/resetpassword', localAuth.resetPassword(), function(req, res) {
                res.send('Password reset');
            });

            // Set up an existing forgot password request:
            assert.lengthOf(passwordResetTokenStore.tokens, 0);
            registerUser(existingUserEmail, existingUserPassword, function(err) {
                if (err) {
                    return done(err);
                }
                requestPasswordReset(existingUserEmail, function (err, unhashedToken) {
                    if (err) {
                        return done(err);
                    }

                    assert.lengthOf(passwordResetTokenStore.tokens, 1);
                    assert.ok(unhashedToken);
                    passwordResetToken = unhashedToken;

                    done();
                });
            });
        });

        it('ensures token is required', function(done) {
            var postData = { token: '', email: existingUserEmail, password: 'foo', confirmPassword: 'foo' };
            var expectedRedirectPath = '/resetpassword?email=' + existingUserEmail + '&token=';

            utils.verifyPostRedirectGet(app, '/resetpassword', postData, expectedRedirectPath, function verifyAfterGet() {
                assert.deepEqual(resetPasswordValidationErrors, [{
                    token: {
                        param: 'token',
                        msg: 'Password reset token required',
                        value: ''
                    }
                }]);
            }, done);
        });

        it('ensures email is required', function(done) {
            var postData = { email: '', token: passwordResetToken, password: 'foo', confirmPassword: 'foo' };
            var expectedRedirectPath = '/resetpassword?email=&token=' + passwordResetToken;

            utils.verifyPostRedirectGet(app, '/resetpassword', postData, expectedRedirectPath, function verifyAfterGet() {
                assert.deepEqual(resetPasswordValidationErrors, [{
                    email: {
                        param: 'email',
                        msg: 'Email address required',
                        value: ''
                    }
                }]);
            }, done);
        });

        it('ensures password is required', function(done) {
            var postData = { password: '', confirmPassword: 'foo', token: passwordResetToken, email: existingUserEmail };
            var expectedRedirectPath = '/resetpassword?email=' + existingUserEmail + '&token=' + passwordResetToken;

            utils.verifyPostRedirectGet(app, '/resetpassword', postData, expectedRedirectPath, function verifyAfterGet(res) {
                assert.deepEqual(resetPasswordValidationErrors, [{
                    password: {
                        param: 'password',
                        msg: 'New password required',
                        value: ''
                    }
                }]);

                // Ensure token is preserved during redirect:
                assert.equal(res.text, 'Dummy reset password page with token ' + passwordResetToken)
            }, done);
        });

        it('ensures confirm password is required', function(done) {
            var postData = { password: 'foo', confirmPassword: '', token: passwordResetToken, email: existingUserEmail };
            var expectedRedirectPath = '/resetpassword?email=' + existingUserEmail + '&token=' + passwordResetToken;

            utils.verifyPostRedirectGet(app, '/resetpassword', postData, expectedRedirectPath, function verifyAfterGet(res) {
                assert.deepEqual(resetPasswordValidationErrors, [{
                    confirmPassword: {
                        param: 'confirmPassword',
                        msg: 'Password confirmation required',
                        value: ''
                    }
                }]);

                // Ensure token is preserved during redirect:
                assert.equal(res.text, 'Dummy reset password page with token ' + passwordResetToken)
            }, done);
        });

        it('ensures password matches confirm password', function(done) {
            var postData = { password: 'foo', confirmPassword: 'not-foo', token: passwordResetToken, email: existingUserEmail };
            var expectedRedirectPath = '/resetpassword?email=' + existingUserEmail + '&token=' + passwordResetToken;

            utils.verifyPostRedirectGet(app, '/resetpassword', postData, expectedRedirectPath, function verifyAfterGet(res) {
                assert.deepEqual(resetPasswordValidationErrors, [{
                    confirmPassword: {
                        param: 'confirmPassword',
                        msg: 'Password and confirm password do not match',
                        value: 'not-foo'
                    }
                }]);

                // Ensure token is preserved during redirect:
                assert.equal(res.text, 'Dummy reset password page with token ' + passwordResetToken)
            }, done);
        });

        it('ensures unknown password request tokens are ignored', function(done) {
            var postData = { token: 'unknown-token', email: existingUserEmail, password: 'foo', confirmPassword: 'foo' };
            var expectedRedirectPath = '/resetpassword?email=' + existingUserEmail + '&token=unknown-token';

            utils.verifyPostRedirectGet(app, '/resetpassword', postData, expectedRedirectPath, function verifyAfterGet(res) {
                assert.deepEqual(resetPasswordErrors, [ 'Unknown or expired token' ]);
            }, done);
        });

        it('ensures that expired tokens are ignored', function(done) {
            // expire the existing token:
            assert.lengthOf(passwordResetTokenStore.tokens, 1);
            passwordResetTokenStore.tokens[0].expiry = new Date(Date.now() - 1);

            var postData = { token: passwordResetToken, email: existingUserEmail, password: 'foo', confirmPassword: 'foo' };
            var expectedRedirectPath = '/resetpassword?email=' + existingUserEmail + '&token=' + passwordResetToken;

            utils.verifyPostRedirectGet(app, '/resetpassword', postData, expectedRedirectPath, function verifyAfterGet(res) {
                assert.deepEqual(resetPasswordErrors, [ 'Unknown or expired token' ]);
            }, done);
        });

        it('ensures unknown password request emails are ignored', function(done) {
            var postData = { email: 'unknown-email@example.com', token: passwordResetToken, password: 'foo', confirmPassword: 'foo' };
            var expectedRedirectPath = '/resetpassword?email=unknown-email@example.com&token=' + passwordResetToken;

            utils.verifyPostRedirectGet(app, '/resetpassword', postData, expectedRedirectPath, function verifyAfterGet(res) {
                assert.deepEqual(resetPasswordErrors, [ 'Unknown or expired token' ]);
            }, done);
        });

        it('ensures password reset tokens for unknown users are ignored', function(done) {

            // Just remove all users so no possibility of a match:
            userStore.users = [];

            var postData = { email: existingUserEmail, token: passwordResetToken, password: 'foo', confirmPassword: 'foo' };
            var expectedRedirectPath = '/resetpassword?email=' + existingUserEmail + '&token=' + passwordResetToken;

            utils.verifyPostRedirectGet(app, '/resetpassword', postData, expectedRedirectPath, function verifyAfterGet() {
                assert.deepEqual(resetPasswordErrors, [ 'Unknown or expired token' ]);
            }, done);
        });

        it('allows password to be reset', function(done) {

            var newPassword = existingUserPassword + '-new';

            request(app)
                .post('/resetpassword')
                .send({ password: newPassword, confirmPassword: newPassword, token: passwordResetToken, email: existingUserEmail })
                .expect(200, 'Password reset')
                .expect(function() {
                    assert.lengthOf(userStore.users, 1);
                    var user = userStore.users[0];
                    assert.equal(user.hashedPassword, 'hashed-' + newPassword);
                })
                .end(done);
        });

        it('ignores case of email when resetting password', function(done) {

            var newPassword = existingUserPassword + '-new';
            var uppercaseEmail = existingUserEmail.toUpperCase();

            request(app)
                .post('/resetpassword')
                .send({ password: newPassword, confirmPassword: newPassword, token: passwordResetToken, email: uppercaseEmail })
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

            resetPassword(existingUserEmail, passwordResetToken, 'new-password', function(err) {
                if (err) {
                    return done(err);
                }

                assert.lengthOf(passwordResetTokenStore.tokens, 0);
                done();
            });
        });

        it('emails user confirmation of change after password reset', function(done) {

            fakeEmailService.sendPasswordResetEmail = sinon.stub().yields(null);

            resetPassword(existingUserEmail, passwordResetToken, 'new-password', function(err) {
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

    function registerUser(email, password, cb) {
        request(app)
            .post('/register')
            .send({ email: email, password: password})
            .expect(201)
            .end(cb);
    }

    function requestPasswordReset(email, callback) {
        var orig = fakeEmailService.sendForgotPasswordEmail;

        var unhashedToken;
        fakeEmailService.sendForgotPasswordEmail = function(user, verifyQueryString, cb) {

            unhashedToken = verifyQueryString.substr(verifyQueryString.lastIndexOf('=') + 1);

            fakeEmailService.sendForgotPasswordEmail = orig;
            orig(user, verifyQueryString, cb);
        };

        request(app)
            .post('/forgotpassword')
            .send({ email: email })
            .expect(200)
            .end(function(err) {
                if (err) {
                    return callback(err);
                }

                callback(null, unhashedToken);
            });
    }

    function capturePasswordResetToken(callback) {
        fakeEmailService.sendForgotPasswordEmail = function(user, verifyQueryString, cb) {
            callback(token);
            cb(null);
        };
    }

    function resetPassword(email, token, newPassword, cb) {
        request(app)
            .post('/resetpassword')
            .send({ password: newPassword, confirmPassword: newPassword, token: token, email: email })
            .expect(200, 'Password reset')
            .end(cb);
    }
});