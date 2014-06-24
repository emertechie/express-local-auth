var assert = require('chai').assert,
    express = require('express'),
    bodyParser = require('body-parser'),
    request = require('supertest'),
    registration = require('../src/index');

function FakeUserStore() {
}
FakeUserStore.prototype.add = function(userDetails, callback) {
    this.userDetailsSeen = clone(userDetails);
    if (this.simulatedError) {
        callback(simulatedError, null);
    } else {
        var user = clone(userDetails);
        user.userId = this.fakeUserId;
        callback(null, user);
    }
};
function clone(obj) {
    return JSON.parse(JSON.stringify(obj));
}

describe('Registration', function() {

    var app, userStore, configure, loggedInUserId, simlulatedLogInErr, userDetailsSeenForRegEmail, config;

    beforeEach(function() {
        loggedInUserId = null;
        simlulatedLogInErr = null;
        userDetailsSeenForRegEmail = null;

        // todo: this is horrible. do something better
        config = {
            userIdGetter: function(user) {
                return user.userId
            },
            hashedPasswordGetter: function(user) {
                return user.hashedPassword
            }
        };

        userStore = new FakeUserStore();

        var fakeAuthService = {
            hashPassword: function(password, cb) {
                cb(null, 'HASHED-' + password);
            },
            markLoggedInAfterAuthentication: function(req, user, callback) {
                loggedInUserId = config.userIdGetter(user);
                callback(simlulatedLogInErr || null);
            }
        };

        var fakeEmailService = {
            sendRegistrationEmail: function(userDetails, callback) {
                userDetailsSeenForRegEmail = userDetails;
                callback(null);
            }
        };

        app = express();
        app.use(bodyParser());

        configure = function(options) {
            options = options || {};
            options.logger = { error: function(){} };

            var componentFactory = registration(options);
            var component = componentFactory(userStore, fakeAuthService, fakeEmailService, config);
            app.use(component.router);
        };
    });

    it('should allow registration with username and password', function(done) {
        configure();

        request(app)
            .post('/register')
            .send({ username: 'foo', password: 'bar'})
            .expect(201)
            .expect(function() {
                assert.deepEqual(userStore.userDetailsSeen, {
                    username: 'foo',
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
                assert.isUndefined(userStore.userDetailsSeen.password);
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

    it('should return new user ID after registration', function(done) {
        configure();

        var userId = 99;
        userStore.fakeUserId = userId;

        request(app)
            .post('/register')
            .send({ username: 'foo', password: 'bar'})
            .expect(201, userId.toString())
            .end(done);
    });

    it('should return transformed user ID after registration if transformer provided', function(done) {
        var userId = 99;
        userStore.fakeUserId = userId;

        configure({
            registrationOkResponse: function(user, res) {
                res.send(201, JSON.stringify({
                    transformed: config.userIdGetter(user)
                }));
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
});