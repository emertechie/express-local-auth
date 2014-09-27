var assert = require('chai').assert,
    request = require('supertest'),
    FakeUserStore = require('./fakes/userStore'),
    fakeEmailService = require('./fakes/fakeEmailService'),
    fakeAuthService = require('./fakes/fakeAuthService'),
    utils = require('./utils'),
    _ = require('lodash'),
    sinon = require('sinon');

describe('Changing Password', function() {

    var app, localAuth, userStore, services;
    var existingUserEmail, existingUserPassword;
    var changePasswordValidationErrors, changePasswordErrors;
    var setupExistingAuthenticatedUser;

    beforeEach(function(done) {
        userStore = new FakeUserStore();
        services = {
            userStore: userStore,
            emailService: fakeEmailService,
            authService: fakeAuthService
        };

        app = utils.configureExpress();

        // Set up existing user:
        existingUserEmail = 'foo@example.com';
        existingUserPassword = 'bar';

        setupExistingAuthenticatedUser = function(done) {
            assert.lengthOf(userStore.users, 0);
            registerUser(existingUserEmail, existingUserPassword, function(err) {
                if (err) {
                    return done(err);
                }

                assert.lengthOf(userStore.users, 1);
                var user = userStore.users[0];

                // Simulate authenticated user:
                fakeAuthService.isAuthenticated = function (req, cb) {
                    cb(null, user);
                };

                done();
            });
        };

        done();
    });

    describe('With Session', function() {

        beforeEach(function(done) {
            localAuth = utils.configureLocalAuth(app, services, {
                useSessions: true
            });

            // Register routes:
            app.post('/register', localAuth.register(), function(req, res) {
                res.send(201);
            });
            app.get('/changepassword', function(req, res) {
                changePasswordValidationErrors = req.flash ? req.flash('validationErrors') : null;
                changePasswordErrors = req.flash ? req.flash('errors') : null;
                res.send('dummy change password page');
            });
            app.post('/changepassword', localAuth.changePassword(), function(req, res) {
                res.send('password changed');
            });

            setupExistingAuthenticatedUser(done);
        });

        it('ensures user is authenticated', function(done) {
            // Simulate logged out user:
            fakeAuthService.isAuthenticated = function (req, cb) {
                var user = false;
                cb(null, user);
            };

            request(app)
                .post('/changepassword')
                .send({ oldPassword: existingUserPassword, newPassword: 'new-pass', confirmNewPassword: 'new-pass' })
                .expect(302)
                .expect('location', '/login')
                .end(done);
        });

        it('requires existing password', function(done) {
            var postData = { oldPassword: '', newPassword: 'new-pass', confirmNewPassword: 'new-pass' };

            utils.verifyPostRedirectGet(app, '/changepassword', postData, function() {
                assert.deepEqual(changePasswordValidationErrors, [{
                    oldPassword: {
                        param: 'oldPassword',
                        msg: 'Old password required',
                        value: ''
                    }
                }]);
            }, done);
        });

        it('requires new password', function(done) {
            var postData = { oldPassword: existingUserPassword, newPassword: '', confirmNewPassword: 'new-pass' };

            utils.verifyPostRedirectGet(app, '/changepassword', postData, function() {
                assert.deepEqual(changePasswordValidationErrors, [{
                    newPassword: {
                        param: 'newPassword',
                        msg: 'New password required',
                        value: ''
                    }
                }]);
            }, done);
        });

        it('requires new password confirmation', function(done) {
            var postData = { oldPassword: existingUserPassword, newPassword: 'new-pass', confirmNewPassword: '' };

            utils.verifyPostRedirectGet(app, '/changepassword', postData, function() {
                assert.deepEqual(changePasswordValidationErrors, [{
                    confirmNewPassword: {
                        param: 'confirmNewPassword',
                        msg: 'New password confirmation required',
                        value: ''
                    }
                }]);
            }, done);
        });

        it('ensures new password and new password confirmation match', function(done) {
            var postData = { oldPassword: existingUserPassword, newPassword: 'new-pass', confirmNewPassword: 'not-new-pass' };

            utils.verifyPostRedirectGet(app, '/changepassword', postData, function() {
                assert.deepEqual(changePasswordValidationErrors, [{
                    confirmNewPassword: {
                        param: 'confirmNewPassword',
                        msg: 'New password and confirm password do not match',
                        value: 'not-new-pass'
                    }
                }]);
            }, done);
        });

        it('forbids password change given incorrect existing password', function(done) {
            var postData = { oldPassword: 'not-' + existingUserPassword, newPassword: 'new-pass', confirmNewPassword: 'new-pass' };

            utils.verifyPostRedirectGet(app, '/changepassword', postData, function() {
                assert.deepEqual(changePasswordErrors, ['Incorrect password']);
            }, done);
        });

        it('allows changing password given correct existing password', function(done) {
            var postData = { oldPassword: existingUserPassword, newPassword: 'new-pass', confirmNewPassword: 'new-pass' };

            assert.lengthOf(userStore.users, 1);

            request(app)
                .post('/changepassword')
                .send(postData)
                .expect(200)
                .expect(function() {
                    assert.lengthOf(userStore.users, 1);
                    assert.equal(userStore.users[0].hashedPassword, 'hashed-new-pass');
                })
                .end(done);
        });

        it('emails user when password changed', function(done) {
            var postData = { oldPassword: existingUserPassword, newPassword: 'new-pass', confirmNewPassword: 'new-pass' };

            fakeEmailService.sendPasswordSuccessfullyChangedEmail = sinon.stub().yields(null);

            request(app)
                .post('/changepassword')
                .send(postData)
                .expect(200)
                .expect(function() {
                    assert.isTrue(fakeEmailService.sendPasswordSuccessfullyChangedEmail.calledWith(
                        sinon.match.has('email', existingUserEmail)
                    ), 'User is emailed password changed confirmation');
                })
                .end(done);
        });
    });

    describe('Without Session', function() {

        beforeEach(function(done) {
            localAuth = utils.configureLocalAuth(app, services, {
                useSessions: false
            });

            // Register routes:
            app.post('/register', localAuth.register(), function(req, res) {
                res.send(201);
            });
            app.get('/changepassword', function(req, res) {
                // changePasswordValidationErrors = req.flash ? req.flash('validationErrors') : null;
                // changePasswordErrors = req.flash ? req.flash('errors') : null;
                res.send('dummy change password page');
            });
            app.post('/changepassword', localAuth.changePassword(), function(req, res) {
                if (res.statusCode === 401) {
                    res.redirect('/login');
                } else {
                    res.send('password changed');
                }
            });

            setupExistingAuthenticatedUser(done);
        });

        it('ensures user is authenticated', function(done) {
            // Simulate logged out user:
            fakeAuthService.isAuthenticated = function (req, cb) {
                var user = false;
                cb(null, user);
            };

            request(app)
                .post('/changepassword')
                .send({ oldPassword: existingUserPassword, newPassword: 'new-pass', confirmNewPassword: 'new-pass' })
                .expect(302)
                .expect('location', '/login')
                .end(done);
        });
    });

    describe('Without Session (API mode)', function() {

        beforeEach(function(done) {
            localAuth = utils.configureLocalAuth(app, services, {
                useSessions: false,
                autoSendErrors: true
            });

            // Register routes:
            app.post('/register', localAuth.register(), function(req, res) {
                res.send(201);
            });
            app.get('/changepassword', function(req, res) {
                // changePasswordValidationErrors = req.flash ? req.flash('validationErrors') : null;
                // changePasswordErrors = req.flash ? req.flash('errors') : null;
                res.send('dummy change password page');
            });
            app.post('/changepassword', localAuth.changePassword(), function(req, res) {
                res.send('password changed');
            });

            setupExistingAuthenticatedUser(done);
        });

        it('ensures user is authenticated', function(done) {
            // Simulate logged out user:
            fakeAuthService.isAuthenticated = function (req, cb) {
                var user = false;
                cb(null, user);
            };

            request(app)
                .post('/changepassword')
                .send({ oldPassword: existingUserPassword, newPassword: 'new-pass', confirmNewPassword: 'new-pass' })
                .expect(401)
                .expect(function(res) {
                    assert.equal(res.text, 'Unauthenticated');
                })
                .end(done);
        });
    });

    function registerUser(email, password, cb) {
        request(app)
            .post('/register')
            .send({ email: email, password: password})
            .expect(201)
            .end(cb);
    }
});