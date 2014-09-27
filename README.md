express-local-auth
==================

[![Build Status](https://travis-ci.org/emertechie/express-local-auth.svg?branch=master)](https://travis-ci.org/emertechie/express-local-auth)

Express middleware that provides secure username/email and password authentication along with commonly needed supporting features such as user registration and password management.

# Install

```
npm install express-local-auth
```

# Overview

* Uses a secure, [slow](http://codahale.com/how-to-safely-store-a-password/) hashing algoritm - [bcrypt](https://github.com/ncb000gt/node.bcrypt.js)
* Locks out accounts after number of invalid login attempts
* Supports email verification via a callback
* Password reset only allowed after email verified
* Password reset tokens have an expiry
* Only stores a hashed version of password reset tokens (so if someone can read your DB through SQL injection for instance, they can't reset passwords using unhashed tokens)
* Recognises if someone attempts to reset a password for an unknown account and can email the account holder
* Requires original password before allowing a password change
* Not tied to any database or email provider - you implement simple service abstractions
* Logs extensively so if something fishy is going on, you have all the info you need
* Supports session-based and session-less operation
* Extensive unit-tests included

Features are implemented in a modular fashion and provided as simple route handlers for you to wire up as you see fit.

Uses the excellent [Passport](passportjs.org) library under the hood.

# Quick Example Usage

For full configuration sample, see [here](samples/server-side-views/index.js)

``` js

var express = require('express'),
    // ...
    localAuthFactory = require('express-local-auth');

// 1. Configure standard express app:
var app = express();
app.use(express.static(__dirname + '/public'));
// ...

// 2. Configure express-local-auth
var services = {
    emailService: myEmailService,
    userStore: myUserStore,
    passwordResetTokenStore: myPasswordResetTokenStore,
    verifyEmailTokenStore: myVerifyEmailTokenStore,
    logger: logger
};
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

// ... more route handlers

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
* `verifyEmailTokenStore` - An object implementing the [Token Store](#token-store) API. Only required if the `verifyEmail` flag set to true in the `options`. **Note**: don't use the same instance as `passwordResetTokenStore` - use separate stores for each.
* `logger` - An object with a standard logger interface. For instance you can assign a [Winston](https://github.com/flatiron/winston) logger instance.
* `userIdGetter` - Optional function that takes a user object and returns the ID for that user. The system assumes that the [User Store](#user-store) service will set an `id` property when adding a user, so this function returns `user.id` by default.

## Options

```js
// The default options:
var options = _.defaults(options || {}, {
  loginPath: '/login',
  useSessions: true,
  autoSendErrors: false,
  normalizeCase: true,
  failedLoginsBeforeLockout: 10,
  accountLockedMs: 20 * minuteInMs,
  tokenExpirationMins: 60,
  verifyEmail: false
});
```

* `loginPath` - The path where the login route is hosted. Needed for redirecting back to login page when unauthenticated for instance. Defaults to `'/login'`
* `useSessions` - Whether to use sessions or not. If sessions are used (the default), it's expected that you have configured your app to use `express-session` etc. See samples for example usage. Also, errors are handled differently based on this setting. See [Error Handling](#error-handling) section.
* `autoSendErrors` - Only applies if not using sessions. If `true`, any provided middleware will automatically call `res.send(error)` on an error and end the request there - i.e. it will not call `next()` so any following middleware functions won't get invoked. If `false`, will set `res.locals['errors']` or `res.locals['validationErrors']` before calling `next()` to invoke any following middleware functions.
* `normalizeCase` - Whether to lowercase the user's email address when registering or when using it to verify credentials.
* `failedLoginsBeforeLockout` - Self-explanatory I hope. A successful login will always reset a user's failed login count
* `accountLockedMs` - How long to lock the account out for, in milliseconds, after `failedLoginsBeforeLockout` unsuccessful attempts
* `tokenExpirationMins` - How long a password reset token is valid for. Note: A verify email token never expires
* `verifyEmail` - Whether to expect users to verify their email addresses. If this is true, an `emailVerified` property will be added to user object which will only be set to true if user hits the verify email callback with correct token. Also, if this is true then user must verify email address before a password reset is allowed.

# Usage Modes

There are three potential ways to use this library which affects how any custom middleware following a library-provided middleware function is invoked (Also see [Error Handling](#error-handling) for more details)

```js
app.post('/login', localAuth.login(), function(req, res) {
    // If, and how, this function gets invoked depends
    // on how you configure the options. See below
});
```
### 1. In a web app using sessions
The default mode. If there's an error then library-provided middleware will:
* Set errors in flash (available via `req.flash('errors')` and `req.flash('validationErrors')`)
* Will do a redirect back to original path (See [Error Handling](#error-handling))

So following middleware will only get called if there were no errors.

### 2. In a web app not using sessions
If you set `options.useSessions = false`, if there's an error then library-provided middleware will:
* Set an appropriate `res.status_code`
* Assign errors to either `res.locals.errors` or `res.locals.validationErrors`
* Will *always* call `next()` to invoke following middleware

So following middleware will always get called and it's up to you to check `res.locals` for errors and render an appropriate response.

### 3. In an API
If you set `options.useSessions = false` and `options.autoSendErrors = true`, if there's an error then library-provided middleware will:
* Set an appropriate `res.status_code`
* Will automatically call `res.send(errors)`  to return the error response - i.e. it will *not* call `next()`

So following middleware will only get called if there were no errors.

In this mode you normally don't need custom middleware invoked on an error because you don't have views to render.

# Routes

**NOTE**: The examples below assume you are using sessions. If not,
see the [Error Handling](#error-handling) section below for how to handle errors correctly.

Details of individual routes below. Also, take a look at the working [sample](samples/server-side-views/index.js) provided.

## Login

|Operation              | Method | Suggested Path | Provided Middleware      |
|-----------------------|--------|----------------|--------------------------|
|Render login view      | GET    | /login         |                          |
|Perform login          | POST   | /login         | localAuth.login() |
|Perform logout         | POST   | /logout        | localAuth.logout()        |

### Render login view

Implement this as normal to render a login view with `email` and `password` input fields that get posted to the next route.

```js
app.get('/login', function(req, res) {
    res.render('login');
});
```

### Perform login

Call `localAuth.login()` middleware to perform the login before your own final middleware handler.

```js
app.post('/login', localAuth.login(), function(req, res) {
  res.redirect('/home');
});
```

### Perform logout

Call `localAuth.logout()` middleware to log the user out before your own final middleware handler.

```js
app.get('/logout', localAuth.logout(), function(req, res) {
    res.redirect('/login');
});
```

## User Registration

|Operation                   | Method | Suggested Path | Provided Middleware          |
|----------------------------|--------|----------------|------------------------------|
|Render registration view    | GET    | /register      |                              |
|Perform user registration   | POST   | /register      | localAuth.register()  |
|Verify email callback       | GET    | /verifyemail   | localAuth.verifyEmailView()  |
|Delete user                 | POST   | /unregister    | localAuth.unregister()       |

### Render registration view

Implement this as normal to render a registration view with `username` (optional), `email` and `password` fields that get posted to the next route.

If username not provided, it will default to `email`.

```js
app.get('/register', function(req, res) {
    res.render('register');
});
```

### Perform user registration

Call `localAuth.register()` middleware to register the user before your own final middleware handler.

```js
app.post('/register', localAuth.register(), function(req, res) {
    req.flash('successMsgs', 'Registered successfully');
    res.redirect('/home');
});
```

### Verify email callback

The route that will be invoked when user clicks on link in the registration email.
The provided handler will verify the supplied token and remove it from the [Token Store](#token-store) if successful.

The route handler will not do a redirect on error, so you must check the `res.statusCode` value to see if an error occurred:

```js
app.get('/verifyemail', localAuth.verifyEmailView(), function(req, res) {
    res.render('email_verification', { emailVerified: res.statusCode == 200 });
});
```

### Delete user

Call `localAuth.unregister()` middleware to delete the user before your own final middleware handler.

```js
app.post('/unregister', localAuth.unregister(), function(req, res) {
    req.flash('successMsgs', 'Successfully deleted user');
    res.redirect('/register');
});
```

## Change Password

|Operation                           | Method | Suggested Path  | Provided Middleware          |
|------------------------------------|--------|-----------------|------------------------------|
|Render change password view         | GET    | /changepassword |                              |
|Change password                     | POST   | /changePassword | localAuth.changePassword()   |

### Render change password view

Implement this as normal to render a view which posts `oldPassword`, `newPassword` and `confirmNewPassword` to the next route.

```js
app.get('/changepassword', function(req, res) {
    res.render('change_password');
});
```

### Change password

Call `localAuth.changePassword()` middleware to verify the old password and change user's password before invoking your own final middleware handler.

```js
app.post('/changepassword', localAuth.changePassword(), function(req, res) {
    req.flash('successMsgs', 'Your password has been changed');
    res.redirect('/home');
});
```

## Password reset

|Operation                           | Method | Suggested Path  | Provided Middleware          |
|------------------------------------|--------|-----------------|------------------------------|
|Render forgot password view         | GET    | /forgotpassword |                              |
|Start password reset process        | POST   | /forgotpassword | localAuth.forgotPassword()   |
|Render reset password callback view | GET    | /resetpassword  | localAuth.resetPasswordView()|
|Perform password reset              | POST   | /resetpassword  | localAuth.resetPassword()    |

### Render forgot password view

Implement this as normal to render a view with an `email` input field that gets posted to the next route.

```js
app.get('/forgotpassword', function(req, res) {
    res.render('forgot_password');
});
```

### Start password reset process

Call `localAuth.forgotPassword()` middleware to start the password reset process:

```js
app.post('/forgotpassword', localAuth.forgotPassword(), function(req, res) {
    res.render('password_reset_requested', { email: res.locals.email });
});
```

If a user is found with the posted email, the [Email Service](#email-service)
is used to send an email to the user with a link to the next /resetpassword route.

If no user found, the [Email Service](#email-service) can choose to notify the email address owner anyway
to make them aware of a possible hack attempt.

### Render reset password callback view

The route that gets invoked when a user clicks on link in a password reset email.
You should call the supplied `localAuth.resetPasswordView()` handler first to
verify the supplied token exists and is still valid.

After that, render a view which will POST `password` and `confirmPassword` fields
and hidden `email` and `token` fields to the next /resetpassword route.

```js
app.get('/resetpassword', localAuth.resetPasswordView(), function(req, res) {
    res.render('reset_password');
});
```

### Perform password reset

Call `localAuth.resetPassword()` middleware to reset the user's password before your own final middleware handler.

The supplied handler will:
- verify the password reset token exists and is still valid
- update the user with new password
- delete the token from the [Token Store](#token-store)
- use the [Email Service](#email-service) to notify user that password was reset

```js
app.post('/resetpassword', localAuth.resetPassword(), function(req, res) {
    req.flash('successMsgs', 'Your password has been reset');
    res.redirect('/login');
});
```

# Error Handling

This library is built to support session and session-less operation (see [options](#options.useSessions)).
How errors are handled is different depending on which mode you choose as detailed below.

### Using Sessions
If an error occurs during a route you are redirected via a GET back to the original path and the error will be added to the session flash (via [connect-flash](https://github.com/jaredhanson/connect-flash)).

For example, if you do a POST to `/login` and an error occurs, you'll be redirected via a GET to `/login` and the flash will be populated as follows:
* `req.flash('errors')` - will be an array of strings detailing any non-validation related errors.
* `req.flash('validationErrors')` - will be an array of validation error objects as returned by the `req.validationErrors()` function of the [express-validator](https://github.com/ctavan/express-validator) library

So when using sessions, unless otherwise noted, you don't need to do any explicit error handling in your own middleware handler after calling a `localAuth` handler as the `localAuth` handler will do a redirect on an error. E.g:

```js
app.post('/login', localAuth.login(), function(req, res) {

  // No explicit error-handling needed here

  res.redirect('/home');
});
```

But you will need to check for errors in the session flash and make them available for display in views:
```js
app.use(function(req, res, next) {
    // Transfer flash state, if present, to locals so views can access:
    res.locals.errors = (res.locals.errors || []).concat(req.flash('errors'));
    res.locals.validationErrors = (res.locals.validationErrors || []).concat(req.flash('validationErrors'));
    res.locals.successMsgs = (res.locals.successMsgs || []).concat(req.flash('successMsgs'));
    next();
});
```

### Not Using Sessions, Not Auto-Sending Errors
Options: `{ useSessions: false }`

If an error occurs during a route the following happens:
* `res.status(statusCode)` is called with an appropriate, non-200 status code
* `res.locals.errors` will be populated with any non-validation error strings. Same format as `req.flash('errors')` above.
* `res.locals.validationErrors` will be populated with any validation error object. Same format as `req.flash('validationErrors')` above.
* `next()` will be called to invoke the next middleware handler.

So to take the example above, you would need:

```js
app.post('/login', localAuth.login(), function(req, res) {

  // Need to check res.locals.errors and res.locals.validationErrors here

  res.redirect('/home');
});
```

### Not Using Sessions, Auto-Sending Errors
Options: `{ useSessions: false, autoSendErrors: true }`

If an error occurs during a route the following happens:
* `res.status(statusCode)` is called with an appropriate, non-200 status code
* `res.send(<error>)` is called, where `<error>` is either a validation or non-validation error as described above
* Note: `next()` is **not** called, so any following middleware is not invoked

```js
app.post('/login', localAuth.login(), function(req, res) {

  // This will only get invoked if no errors

  res.send(200, { success: much });
});
```

### Unexpected errors

If a node callback returns an error, this is immediately used to call `next(err)` so you will also need an overall error handler for your application as usual. For example:

```js
app.use(function(err, req, res, next) {
    logger.error(err);
    res.status(500).render('error');
});
```

# Per-route Configuration

Route handlers provided by this middleware will generally take an `options` object which can have the following properties:
* `shouldRedirect` - override whether this route will do a redirect on error or not
* `errorRedirect` - override where this route will redirect to on an error
* `autoSendErrors` - override the `options.autoSendErrors` value for this route

For example:

```js
app.post('/login', localAuth.login({ errorRedirect: false }), function(req, res) {

  // Handle errors yourself here by checking  
  // res.locals.errors and res.locals.validationErrors
  // ...

  res.redirect('/home');
});
```

# Service APIs

## Email Service

See the [fake email service](samples/fakes/emailService.js) in the samples folder to get a quick idea of how to implement.

The expected API for this service is:

#### sendRegistrationEmail(user, verifyQueryString, callback)
* `user` - [user object](#user-object)
* `verifyQueryString` - the query string part of the URL (including leading '?' character) that user visits to verify email. For instance, if you host the callback route at `http://example.com/verifyemail`, then the link included in email should be `"http://example.com/verifyemail" + verifyQueryString`. This will be null if the `verifyEmail` [option](#options) is false.
* `callback(err)` - standard node callback when operation complete

#### sendForgotPasswordEmail(user, verifyQueryString, callback)
* `user` - [user object](#user-object)
* `verifyQueryString` - the query string part of the URL (including leading '?' character) that user visits to initiate password reset process. For instance, if you host the callback route at `http://example.com/resetpassword`, then the link included in email should be `"http://example.com/resetpassword" + verifyQueryString`
* `callback(err)` - standard node callback when operation complete

#### sendForgotPasswordNotificationForUnregisteredEmail(email, callback)
* `email` - the unregistered email address
* `callback(err)` - standard node callback when operation complete

Called if a user attempts to reset a password for an unknown email address. You are free to leave the implementation empty (well, invoke the `callback` at least) or you can send a nice email to that address saying someone tried to reset your password.

#### sendPasswordSuccessfullyResetEmail(user, callback)
* `user` - [user object](#user-object)
* `callback(err)` - standard node callback when operation complete

Invoked after user has followed the password reset process. Email user and let them know they can now log in with new password.

#### sendPasswordSuccessfullyChangedEmail(user, callback)
* `user` - [user object](#user-object)
* `callback(err)` - standard node callback when operation complete

Invoked after password changed via normal change password process. Email them a confirmation email.

## User Store

See the [fake User Store](tests/fakes/userStore) used in tests to get a quick idea of how to implement.

The expected API for this service is:

#### add(userDetails, callback)
* `userDetails` - A user object containing `username`, `email` and `hashedPassword`
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

## Token Store

The same Token Store service API is used for email verification tokens as well as password reset tokens.

See the [fake Token Store](tests/fakes/tokenStore) used in tests to get a quick idea of how to implement.

The expected API for this service is:

#### add(tokenDetails, callback)
* `tokenDetails` - object containing `email`, `userId` properties and for password reset tokens an `expiry` also.
* `callback(err)` - standard node callback when operation complete

### removeAllByEmail(email, callback)
* `email` - email address to remove tokens for
* `callback(err)` - standard node callback when operation complete

### findByEmail(email, callback)
* `email` - email address to find tokens for
* `callback(err)` - standard node callback when operation complete

# User object
Any `user` object mentioned in APIs will have `email` and `username` properties along with other properties that the `UserStore` might add such as an `id`.
