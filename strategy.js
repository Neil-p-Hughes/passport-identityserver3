var passport = require('passport'),
    jwt = require('jsonwebtoken'),
    extend = require('json-extend'),
    common = require('./common'),
    Client = require('./client');

function Strategy(identifier, config) {
    if(typeof(identifier) === 'object') {
        config = identifier;
        identifier = 'passport-IDSRV3';
    }

    if(!config || !config.client_id || !config.client_secret || !config.callback_url) {
        throw new Error('The require config settings are not present [client_id, client_secret, callback_url]');
    }
    if(!(config.useCookie === true))
    {
        config.useCookie = false;
    }

    passport.Strategy.call(this);

    this.name = identifier;
    this.config = config;
    this.client = new Client(config);

    if(config.configuration_endpoint) {
        this.discover(config);
    }
}

require('util').inherits(Strategy, passport.Strategy);

/*********** Passport Strategy Impl ***********/

Strategy.prototype.authenticate = function(req, options) {

        var self = this,
            config = self.config;
    if(req.query.error) {
        return this.error(new Error(req.query.error));
    } else if(req.query.code) {
        


        if(config.useCookie === true)
        {
            if(!req.cookies.IDSRV3 || !req.cookies.IDSRV3.tokens || req.query.state !== req.cookies.IDSRV3.tokens.state) {
                return this.error(new Error('State does not match session.'));
            }            
        }
        else
        {
            if(!req._passport.session.tokens || req.query.state !== req._passport.session.tokens.state) {
                return this.error(new Error('State does not match session.'));
            }
        }
        this.client.getTokens(req, function(err, data) {
            var user;

            if(err) {
                self.error(err);
            } else if(user = self.validateToken(data.id_token)) {
                if(config.transformIdentity) {
                    user = config.transformIdentity(user);
                }

                self.success(user);
            } else {
                
                if(config.useCookie === true){
                    if(!req.cookies.IDSRV3){
                        req.cookies.IDSRV3 = {};
                    }
                    req.cookies.IDSRV3.tokens = null;
                }
                else{
                    req._passport.session.tokens = null;
                }
            }
        });
    } else {
        var state = common.randomHex(16);
        if(config.useCookie === true){
            if(!req.cookies.IDSRV3){
                req.cookies.IDSRV3 = {};
            }
            req.cookies.IDSRV3.tokens = {
                state: state
            };
        }
        else{
            req._passport.session.tokens = {
                state: state
            };
        }

        this.redirect(this.client.authorizationUrl(req, state));
    }
};

/*********** End Passport Strategy Impl ***********/

// 5.3.  UserInfo Endpoint [http://openid.net/specs/openid-connect-core-1_0.html#UserInfo]
Strategy.prototype.profile = function(req, scopes, claims, callback) {
    this.client.getProfile(req, scopes, claims, callback);
};

// 5.  RP-Initiated Logout [http://openid.net/specs/openid-connect-session-1_0.html#RPLogout]
Strategy.prototype.endSession = function(req, res) {
    var endSessionUrl = this.client.getEndSessionUrl(req);

    var self = this,
        config = self.config;
        
    if(config.useCookie === true)
    {
        // Clean up session for passport just in case express session is not being used.
        req.logout();
        if(!req.cookies.IDSRV3){
            req.cookies.IDSRV3 = {};
        }        
        req.cookies.IDSRV3.tokens = null;
        res.cookie('IDSRV3', req.cookies.IDSRV3);
    }
    else
    {
        // Clean up session for passport just in case express session is not being used.
        req.logout();
        req._passport.session.tokens = null;
    
        // Destroy express session if possible
        if(req.session && req.session.destroy) {
            req.session.destroy();
        }
    }

    res.redirect(endSessionUrl);
};

// 3.1.3.7.  ID Token Validation [http://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation]
Strategy.prototype.validateToken = function(token) {
    try {
        var cert;

        if(!this.config.keys || !this.config.keys.length) {
            this.error(new Error('No keys configured for verifying tokens'));
        }

        cert = common.formatCert(this.config.keys[0].x5c[0]);

        return jwt.verify(token, cert);
    } catch (e) {
        this.error(e);
    }
};

// 4.  Obtaining OpenID Provider Configuration Information [http://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig]
Strategy.prototype.discover = function(config) {
    var self = this,
        origAuth = self.authenticate,
        pendingAuth = [];

    // overwrite authentication to pause the auth requests while we are discovering.
    self.authenticate = function(req, options) {
        pendingAuth.push([this, req, options]);
    };

    common.json('GET', config.configuration_endpoint, null, null, function(err, data) {
        if(err) { throw err; }

        extend(config, data);

        common.json('GET', data.jwks_uri, null, null, function(err, data) {
            if(err) { throw err; }

            extend(config, data);

            self.authenticate = origAuth;

            pendingAuth.forEach(function(pending) {
                var self = pending.shift();
                
                origAuth.apply(self, pending);
            });
        });
    });
};

module.exports = Strategy;