var assert = require('chai').assert,
    request = require('supertest'),
    FakeUserStore = require('./fakes/userStore'),
    FakeTokenStore = require('./fakes/tokenStore'),
    fakeEmailService = require('./fakes/fakeEmailService'),
    fakeAuthService = require('./fakes/fakeAuthService'),
    utils = require('./utils'),
    _ = require('lodash'),
    sinon = require('sinon');

describe('Changing Password', function() {

    var app, sentry, userStore;
    var existingUserEmail, existingUserPassword;
    var changePasswordValidationErrors, changePasswordErrors;

    beforeEach(function(done) {
        // Set up app and sentry:
        userStore = new FakeUserStore();
        app = utils.configureExpress();

        // TODO
        var results = utils.configureSentry(app, {
            userStore: userStore,
            emailService: fakeEmailService,
            authService: fakeAuthService
        });
        sentry = results.routeHandlers;

        // Register routes:
        app.post('/register', sentry.register(), function(req, res) {
            res.send(201);
        });
        app.get('/changepassword', function(req, res) {
            changePasswordValidationErrors = req.flash ? req.flash('validationErrors') : null;
            changePasswordErrors = req.flash ? req.flash('errors') : null;
            res.send('dummy change password page');
        });
        app.post('/changepassword', sentry.changePassword(), function(req, res) {
            res.send('password changed');
        });

        // Set up existing user:
        existingUserEmail = 'foo@example.com';
        existingUserPassword = 'bar';

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

        fakeEmailService.sendPasswordChangedEmail = sinon.stub().yields(null);

        request(app)
            .post('/changepassword')
            .send(postData)
            .expect(200)
            .expect(function() {
                assert.isTrue(fakeEmailService.sendPasswordChangedEmail.calledWith(
                    sinon.match.has('email', existingUserEmail)
                ), 'User is emailed password changed confirmation');
            })
            .end(done);
    });

    function registerUser(email, password, cb) {
        request(app)
            .post('/register')
            .send({ email: email, password: password})
            .expect(201)
            .end(cb);
    }
});