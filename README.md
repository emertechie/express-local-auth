express-local-auth
==================

[![Build Status](https://travis-ci.org/emertechie/express-local-auth.svg?branch=master)](https://travis-ci.org/emertechie/express-local-auth)

Express middleware that provides secure username/email and password authentication along with commonly needed supporting features such as user registration and password management.

# Install

`npm install express-local-auth`

# Features Overview

* Uses a secure, [slow](http://codahale.com/how-to-safely-store-a-password/) hashing algoritm - [bcrypt](https://github.com/ncb000gt/node.bcrypt.js)
* Supports session-based and session-less authentication models
* Locks out accounts after number of invalid login attempts
* Supports email verification via a callback
* Can ensure that password reset only allowed after email verified
* Password reset tokens have an expiry
* Only stores a hashed version of password reset tokens (so if someone can read your DB through SQL injection for instance, they can't reset passwords using unhashed tokens)
* Recognises if someone attempts to reset a password for an unknown account and can email the account holder
* Requires original password before allowing a password change
* Not tied to any database or email provider - you implement simple service abstractions
* Logs extensively so if something fishy is going on, you have all the info you need
* Extensive unit-tests included

Features are implemented in a modular fashion and provided as simple route handlers for you to wire up as you see fit.

Uses the excellent [Passport](passportjs.org) library under the hood.

# Quick Example Usage

``` js

var express = require('express'),
    // ...
    localAuthFactory = require('express-local-auth');

// 1. Configure standard express app:
var app = express();
app.use(express.static(__dirname + '/public'));
// ...

// 2. Configure express-local-auth

// Define service dependencies. See below for details
var services = {
    emailService: myEmailService,
    userStore: myUserStore,
    passwordResetTokenStore: myPasswordResetTokenStore,
    verifyEmailTokenStore: myVerifyEmailTokenStore,
    logger: logger
};

// More options available. See below
var options = {
  failedLoginsBeforeLockout: 5,
  verifyEmail: true
};

var localAuth = localAuthFactory(app, services, options);

// 3. Define your app routes and use those provided by localAuth object where appropriate. See guide below

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

app.get('/changepassword', function(req, res) {
    res.render('change_password');
});
app.post('/changepassword', localAuth.changePassword(), function(req, res) {
    req.flash('successMsgs', 'Your password has been changed');
    res.redirect('/home');
});

// More route handlers available! See below

```
# Routes

## First, a word about sessions

This library is built to support session and session-less auth (see [options](#options)). How errors are handled is different depending on which you choose as detailed below.

### Session based
If an error occurs during a route (validation or otherwise) you are redirected via a GET back to the original path and the error will be added to the session flash (via [connect-flash](https://github.com/jaredhanson/connect-flash)).

For example, if you do a POST to `/login` and an error occurs, you'll be redirected via a GET to `/login` and the flash will be populated as follows:
* `req.flash('errors')` - will be an array of strings detailing any non-validation related errors.
* `req.flash('validationErrors')` - will be an array of validation error objects as returned by the `req.validationErrors()` function of the [express-validator](https://github.com/ctavan/express-validator) library

### Session-less
If an error occurs during a route (validation or otherwise) the following happens:
* `res.status(statusCode)` is called with an appropriate, non-200 status code
* `res.locals.errors` will be populated with any non-validation error strings. Same format as `req.flash('errors')` above.
* `res.locals.validationErrors` will be populated with any validation error object. Same format as `req.flash('validationErrors')` above.
* `next()` will be called to invoke the next middleware handler.

So if not using sessions, use a middleware handler at the end of the chain that checks for non-200 status code and examines `res.locals.errors/validationErrors` in those cases.

Hope to get a sample together soon showing that usage.

## Login

|# | Method | Suggested Path | Provided Middleware      |
|--|--------|----------------|--------------------------|
|1 | GET    | /login         |                          |
|2 | POST   | /login         | localAuth.login(options) |

### #1 - Render login view

Implement this as normal to render a login view. For example:

```js
app.get('/login', function(req, res) {
    res.render('login');
});
```


### #2 - Perform login

Call `localAuth.login()` middleware to perform the login before your own final middleware handler. The final handler will

```js
app.post('/login', localAuth.login(), function(req, res) {
    res.redirect('/home');
});
```

# Configuration

The object returned by `require('express-local-auth')` is a factory function expecting the following parameters:

``` js
var localAuth = localAuthFactory(expressApp, services, options);
```
* `expressApp` - a standard express app object, configured for sessions etc as appropriate. See [examples](#TODO) for more details.
* `services` - Services configuration object. See [below](#services).
* `options` - Options object. See [below](#options).

## Services

This middleware depends on some simple abstractions over external services. You are free to provide whatever implementations you like.

The `services` object passed into middleware factory should have the following properties:

* `emailService` - An object implementing the [Email Service](#email-service) API
* `userStore` - An object implementing the [User Store](#user-store) API
* `passwordResetTokenStore` - An object implementing the [Token Store](#token-store) API
* `verifyEmailTokenStore` - An object implementing the [Token Store](#token-store) API. Only required if the `verifyEmail` flag set to true in the `options`. This object can be the same instance as that passed to `passwordResetTokenStore` if you really want, but recommend having separate stores.
* `logger` - An object with a standard logger interface. For instance you can assign a [Winston](https://github.com/flatiron/winston) logger instance.
* `userIdGetter` - Optional function that takes a user object and returns the ID for that user. The system assumes that the [User Store](#user-store) service will set an `id` property when adding a user, so this function returns `user.id` by default.

## Options

```js
// The default options:
var options = _.defaults(options || {}, {
  loginPath: '/login',
  useSession: true,
  normalizeCase: true,
  failedLoginsBeforeLockout: 10,
  accountLockedMs: 20 * minuteInMs,
  tokenExpirationMins: 60,
  verifyEmail: false
});
```

Details:
* `loginPath` - The path where the login route is hosted. Needed for redirecting back to login page when unauthenticated for instance. Defaults to `'/login'`
* `useSessions` - Whether to use sessions or not. See [Session-less authentication](#session-less-authentication) section below for more details
* `normalizeCase` - Whether to lowercase the user's email address when registering or when using it verify credentials.
* `failedLoginsBeforeLockout` - Self-explanatory I hope. A successful login will always reset a user's failed login count
* `accountLockedMs` - How long to lock the account out for, in milliseconds, after `failedLoginsBeforeLockout` unsuccessful attempts
* `tokenExpirationMins` - How long a password reset token is valid for. Note: A verify email token never expires
* `verifyEmail` - Whether to expect users to verify their email addresses. If this is true, an `emailVerified` property will be added to user object which will only be set to true if user hits the verify email callback with correct token. Also, if this is true then user must verify email address before a password reset is allowed.

## Session-less authentication

Todo

# Service APIs

## Email Service

See the [fake email service](samples/fakes/emailService.js) in the samples folder to get a quick idea of how to implement.

The expected API for this service is:

#### sendRegistrationEmail(user, verifyQueryString, callback)
* `user` - user object. See below for more details
* `verifyQueryString` - the query string part of the URL (including leading '?' character) that user visits to verify email. For instance, if you host the callback route at `http://example.com/verifyemail`, then the link included in email should be `"http://example.com/verifyemail" + verifyQueryString`. This will be null if the `verifyEmail` [option](#options) is false.
* `callback(err)` - standard node callback when operation complete

#### sendForgotPasswordEmail(user, verifyQueryString, callback)
* `user` - user object. See below for more details
* `verifyQueryString` - the query string part of the URL (including leading '?' character) that user visits to initiate password reset process. For instance, if you host the callback route at `http://example.com/resetpassword`, then the link included in email should be `"http://example.com/resetpassword" + verifyQueryString`
* `callback(err)` - standard node callback when operation complete

#### sendForgotPasswordNotificationForUnregisteredEmail(email, callback)
* `email` - the unregistered email address
* `callback(err)` - standard node callback when operation complete

Called if a user attempts to reset a password for an unknown email address. You are free to leave the implementation empty (well, invoke the `callback` at least) or you can send a nice email to that address saying someone tried to reset your password.

#### sendPasswordSuccessfullyResetEmail(user, callback)
* `user` - user object. See below for more details
* `callback(err)` - standard node callback when operation complete

Invoked after user has followed the password reset process. Email user and let them know they can now log in with new password.

#### sendPasswordSuccessfullyChangedEmail(user, callback)
* `user` - user object. See below for more details
* `callback(err)` - standard node callback when operation complete

Invoked after password changed via normal change password process. Email them a confirmation email.

## User Store

See the [fake User Store](tests/fakes/userStore) used in tests to get a quick idea of how to implement.

The expected API for this service is:

#### add(userDetails, callback)
* `user` - user object. See below for more details
* `callback(err, userAlreadyExists, user)` - The `userAlreadyExists` param should be set to `true` if this is a duplicate registration, false otherwise. The `user` param should be an object containing the same `userDetails` passed in **plus** an ID property. By default it's assumed the ID property is called `id`. If it's something else, provide a custom [services.userIdGetter](#services) function.

#### get(userId, callback)
* `userId` - The ID of the user as extracted by the [services.userIdGetter](#services) function.
* `callback(err, user)` - The `user` param should be a similarly shaped object to the one returned from the `add` function - i.e. it includes an ID property.

#### update(user, callback)
* `user` - The user object to update in the store.
* `callback(err, wasUpdated)` - The `wasUpdated` param should be set to true if user was updated successfully, false otherwise.

#### remove(userId, callback)
* `userId` - The ID of the user as extracted by the [services.userIdGetter](#services) function.
* `callback(err)` - call when operation completes

#### findByEmail(email, callback)
* `email` - The email to lookup
* `callback(err, user)` - The `user` param should be the user object if found, falsy otherwise. Note: don't set the `err` parameter just because user isn't found - they are two separate concerns.

# User object
Any `user` object mentioned in APIs will have `email` and `username` properties along with other properties that the `UserStore` might add such as an `id`.

The `username` will default to email address if only `email` provided.
