var express = require('express'),
    session = require('express-session'),
    flash = require('connect-flash'),
    cookieParser = require('cookie-parser'),
    bodyParser = require('body-parser'),
    winston = require('winston'),
    // Services:
    UserStore = require('../../tests/fakes/userStore'),
    TokenStore = require('../../tests/fakes/tokenStore'),
    emailService = require('../fakes/emailService'),
    // Main lib:
    localAuthFactory = require('../../src/index');

var logger = new (winston.Logger)({
    transports: [
        new (winston.transports.Console)({ level: 'debug' })
    ]
});

var app = express(),
    port = process.env.PORT || 3000;

app.use(express.static(__dirname + '/public'));
app.set('views', __dirname + '/views');
app.set('view engine', 'jade');
app.use(bodyParser.urlencoded({
    extended: false
}));
app.use(cookieParser());
// TODO: Use proper security settings with HTTPS
app.use(session({
    secret: 'keyboard cat',
    resave: false,
    saveUninitialized: false
}));
app.use(flash());

var services = {
    emailService: emailService,
    userStore: new UserStore(),
    passwordResetTokenStore: new TokenStore(),
    verifyEmailTokenStore: new TokenStore(),
    logger: logger
};

var localAuth = localAuthFactory(app, services, {
    failedLoginsBeforeLockout: 3,
    accountLockedMs: 1000 * 20, // 20 seconds for sample app
    verifyEmail: true
});

app.use(function(req, res, next) {
    // Transfer flash state, if present, to locals so views can access:
    res.locals.errors = (res.locals.errors || []).concat(req.flash('errors'));
    res.locals.validationErrors = (res.locals.validationErrors || []).concat(req.flash('validationErrors'));
    res.locals.successMsgs = (res.locals.successMsgs || []).concat(req.flash('successMsgs'));
    next();
});

// ------------------------------------------------------------

app.get('/login', function(req, res) {
    res.render('login');
});
app.post('/login', localAuth.login(), function(req, res) {
    res.redirect('/home');
});

app.get('/logout', localAuth.logout(), function(req, res) {
    res.redirect('/login');
});

app.get('/register', function(req, res) {
    res.render('register');
});
app.post('/register', localAuth.register(), function(req, res) {
    req.flash('successMsgs', 'Registered successfully');
    res.redirect('/home');
});
app.get('/verifyemail', localAuth.verifyEmailView(), function(req, res) {
    res.render('email_verification', { emailVerified: res.statusCode == 200 });
});
app.post('/unregister', localAuth.unregister(), function(req, res) {
    req.flash('successMsgs', 'Unregistered successfully');
    res.redirect('/register');
});

app.get('/forgotpassword', function(req, res) {
    res.render('forgot_password');
});
app.post('/forgotpassword', localAuth.forgotPassword(), function(req, res) {
    res.render('password_reset_requested', { email: res.locals.email });
});
app.get('/resetpassword', localAuth.resetPasswordView(), function(req, res) {
    res.render('reset_password');
});
app.post('/resetpassword', localAuth.resetPassword(), function(req, res) {
    req.flash('successMsgs', 'Your password has been reset');
    res.redirect('/login');
});

app.get('/changepassword', function(req, res) {
    res.render('change_password');
});
app.post('/changepassword', localAuth.changePassword(), function(req, res) {
    req.flash('successMsgs', 'Your password has been changed');
    res.redirect('/home');
});

// ------------------------------------------------------------
// App Specific Routes:

app.get('/', function(req, res) {
    res.redirect('/home');
});

app.get('/home', localAuth.ensureAuthenticated(), function(req, res) {
    res.render('home', { user: req.user, newUser: req.param('newUser') });
});

// ------------------------------------------------------------

app.use(function(err, req, res, next) {
    logger.error(err);
    res.status(500).render('error');
});

app.listen(port);
console.info('Running on port', port);