module.exports = {
    getErrorConfig: function(options, routeOptions) {
        routeOptions = routeOptions || {};
        return {
            shouldRedirect: routeOptions.shouldRedirect === false ? false : routeOptions.shouldRedirect || options.useSessions,
            customRedirect: routeOptions.errorRedirect,
            autoSendErrors: routeOptions.autoSendErrors || options.autoSendErrors || false
        };
    },
    handleValidationErrors: function(errorCfg, redirectQueryParams) {
        return function(req, res, next) {
            var validationErrors = req.validationErrors(true);
            if (validationErrors) {
                this.errorHandler('validationErrors', validationErrors, errorCfg, redirectQueryParams, 400)(req, res, next);
                return true;
            }
        }.bind(this);
    },
    handleError: function(error, errorCfg, redirectQueryParams, nonRedirectStatusCode) {
        return this.errorHandler('errors', error, errorCfg, redirectQueryParams, nonRedirectStatusCode);
    },
    errorHandler: function(errorName, error, errorCfg, /* opt: */ redirectQueryParams, nonRedirectStatusCode) {
        // Supports session-based error handling (redirects with flash) and session-less error handling (status code and errors in locals)

        if (typeof redirectQueryParams === 'number') {
            nonRedirectStatusCode = redirectQueryParams;
            redirectQueryParams = null;
        }
        nonRedirectStatusCode = nonRedirectStatusCode || 400;

        return function(req, res, next) {
            if (errorCfg.shouldRedirect) {
                req.flash(errorName, error);
                var redirectPath = this.getErrorRedirectPath(req, errorCfg.customRedirect, redirectQueryParams);
                res.redirect(redirectPath);
            } else {
                res.status(nonRedirectStatusCode);

                if (errorCfg.autoSendErrors) {
                    res.send(error);
                } else {
                    // Note: Assigning an error array to match the format you get if using flash (so view logic stays the same either way)
                    res.locals[errorName] = [ error ];
                    next();
                }
            }
        }.bind(this);
    },
    getErrorRedirectPath: function(req, customRedirect, redirectQueryParams) {
        // If no customRedirect, then things like POST /register will redirect to GET /register with errors in flash
        var path = customRedirect || req.path;
        return path + (redirectQueryParams || '');
    }
};