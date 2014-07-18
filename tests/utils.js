var express = require('express'),
    session = require('express-session'),
    request = require('supertest'),
    flash = require('connect-flash'),
    bodyParser = require('body-parser'),
    cookieParser = require('cookie-parser'),
    _ = require('lodash'),
    sentry = require('sentry'),
    sentryRegistration = require('../src/index');

module.exports = {
    configureExpress: function(options) {
        options = options || {
            useSession: true
        };

        var app = express();
        app.use(express.static(__dirname + '/public'));
        app.set('views', __dirname + '/views');
        app.set('view engine', 'jade');
        app.use(bodyParser.json());

        if (options.useSession) {
            app.use(cookieParser());
            // Note: In a real app running with HTTPS, you should use following to limit cookie access:
            // session({..., cookie: { httpOnly: true, secure: true } })
            app.use(session({ secret: 'keyboard cat', resave: false, saveUninitialized: false } ));
            app.use(flash());
        }

        app.use(function(err, req, res, next) {
            console.error(err);
            res.send(500, err);
        });

        return app;
    },
    configureSentry: function(app, userStore, passwordResetTokenStore, verifyEmailTokenStore, emailService, authService, options) {
        options = options || {};

        var sentryOptions = _.defaults(options.sentry || {}, {
            userStore: userStore,
            passwordResetTokenStore: passwordResetTokenStore,
            verifyEmailTokenStore: verifyEmailTokenStore,
            emailService: emailService,
            auth: function() {
                return {
                    service: authService,
                    routeHandlers: {}
                }
            },
            registration: sentryRegistration(options.registration)
        });

        sentry.initialize(app, sentryOptions);
    },
    verifyPostRedirectGet: function(app, path, sendData, redirectPath, done, verifyAfterGetFn) {
        // Allow for optional redirectPath:
        if (arguments.length === 5) {
            verifyAfterGetFn = done;
            done = redirectPath;
            redirectPath = path;
        }

        request(app)
            .post(path)
            .send(sendData)
            .expect(302)
            .expect('location', redirectPath)
            .end(function(err, res) {
                if (err) {
                    return done(err);
                }

                var redirectPath = res.headers['location'];

                request(app)
                    .get(redirectPath)
                    .set('cookie', res.headers['set-cookie'])
                    .expect(200)
                    .expect(function(res) {
                        verifyAfterGetFn(res);
                    })
                    .end(done);
            });
    }
};