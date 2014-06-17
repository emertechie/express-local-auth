var assert = require('chai').assert,
    express = require('express'),
    bodyParser = require('body-parser'),
    request = require('supertest'),
    bcrypt = require('bcrypt'),
    registration = require('../src/index');

function FakeUserStore() {
}
FakeUserStore.prototype.add = function(userDetails, callback) {
    this.userDetailsSeen = userDetails;
    if (this.simulatedError) {
        callback(simulatedError, null);
    } else {
        callback(null, this.fakeUserId);
    }
};

describe('Registration', function() {

    var app, fakeUserStore, configure, loggedInUserId, simlulatedLogInErr, userDetailsSeenForRegEmail;

    beforeEach(function() {
        loggedInUserId = null;
        simlulatedLogInErr = null;
        userDetailsSeenForRegEmail = null;

        fakeUserStore = new FakeUserStore();

        var fakeAuthService = {
            logIn: function(userId, callback) {
                loggedInUserId = userId;
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
            var component = componentFactory(fakeUserStore, fakeAuthService, fakeEmailService);
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
                assert.equal(fakeUserStore.userDetailsSeen.username, 'foo');
                assert.isTrue(bcrypt.compareSync('bar', fakeUserStore.userDetailsSeen.hashedPassword));
            })
            .end(done);
    });

    it('should use auth service to log user in after registration', function(done) {
        configure();

        var USER_ID = 99;
        fakeUserStore.fakeUserId = USER_ID;

        request(app)
            .post('/register')
            .send({ username: 'foo', password: 'bar'})
            .expect(function() {
                assert.equal(USER_ID, loggedInUserId);
            })
            .end(done);
    });

    it('should return error if user cannot be logged in', function(done) {
        configure();

        fakeUserStore.fakeUserId = 99;
        simlulatedLogInErr = 'it blows up';

        request(app)
            .post('/register')
            .send({ username: 'foo', password: 'bar'})
            .expect(500, simlulatedLogInErr)
            .end(done);
    });

    it('should use email service to send registration email', function(done) {
        configure();

        fakeUserStore.fakeUserId = 99;

        request(app)
            .post('/register')
            .send({ username: 'foo', password: 'bar'})
            .expect(function() {
                assert.deepEqual(userDetailsSeenForRegEmail, {
                    userId: 99,
                    username: 'foo'
                });
            })
            .end(done);
    });

    it('should return new user ID after registration', function(done) {
        configure();

        var USER_ID = 99;
        fakeUserStore.fakeUserId = USER_ID;

        request(app)
            .post('/register')
            .send({ username: 'foo', password: 'bar'})
            .expect(201, USER_ID.toString())
            .end(done);
    });

    it('should return transformed user ID after registration if transformer provided', function(done) {
        var USER_ID = 99;
        fakeUserStore.fakeUserId = USER_ID;

        configure({
            resultTransformer: function(userId) {
                return {
                    transformed: userId
                };
            }
        });

        var expectedResponseBody = JSON.stringify({
            transformed: USER_ID
        });

        request(app)
            .post('/register')
            .send({ username: 'foo', password: 'bar'})
            .expect(201, expectedResponseBody)
            .end(done);
    });
});