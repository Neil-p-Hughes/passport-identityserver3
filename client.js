var common = require('./common'),
    extend = require('json-extend');

function Client(config) {
    this.config = config;
}

Client.prototype.scope = function() {
    return (['openid']).concat(this.config.scopes || []).join(' ');
};

Client.prototype.getTokens = function(req, callback) {
    var config = this.config,
        params = {
            grant_type: 'authorization_code',
            code: req.query.code,
            redirect_uri: this.callbackUrl(req)
        };
        if(config.useCookie === true)
        {
            getAccessToken(req.cookies.IDSRV3, config, params, callback, req);
        }
        else
        {
            getAccessToken(req._passport.session, config, params, callback);
        }

};

Client.prototype.getProfile = function(req, scopes, claims, callback) {
    var config = this.config,
        params = {
            scope: (scopes || []).concat(['openid']).join(' ')
        };

    if(claims) {
        params.claims = JSON.stringify(claims);
    }

    this.ensureActiveToken(req, function(err, bearerToken) {
        if(err) { return callback(err); }

        common.json('GET', common.addQuery(config.userinfo_endpoint, params), null, {
            Authorization: bearerToken
        }, callback);
    });
}

Client.prototype.ensureActiveToken = function(req, callback) {
    var config = this.config,
        params, tokens;
    
    if(config.useCookie === true)
    {
        tokens = req.cookies.IDSRV3.tokens;
    }
    else
    {
        tokens = req._passport.session.tokens;
    }

    function tokenHandle(err, tokens) {
        if(err) {
            callback(err);
        } else {
            callback(null, 'Bearer ' + tokens.access_token);
        }
    }

    if(tokens && Date.now() < tokens.expires_at) {
        tokenHandle(null, tokens);
    } else if(!tokens.refresh_token) {
        tokenHandle(new Error('No refresh token is present'));
    } else {
        params = {
            grant_type: 'refresh_token',
            refresh_token: tokens.refresh_token,
            scope: this.scope()
        };

        if(config.useCookie === true)
        {
            getAccessToken(req.cookies.IDSRV3, config, params, tokenHandle, req);
            
        }
        else
        {
            getAccessToken(req._passport.session, config, params, tokenHandle);
        }
        
    }
};

Client.prototype.callbackUrl = function(req) {
    return common.resolveUrl(req, this.config.callback_url);
};
Client.prototype.callbackUrlWithQueryParams = function(req) {
    return common.resolveUrl(req, common.addQuery(this.config.callback_url, extend( {} ,req.query) ));
};

Client.prototype.authorizationUrl = function(req, state) {
    var config = this.config,
        params = extend({}, config.authorize_params, {
            state: state,
            response_type: 'code',
            client_id: config.client_id,
            redirect_uri: this.callbackUrlWithQueryParams(req),
            scope: this.scope()
        });

    return common.addQuery(config.authorization_endpoint, params);
};

Client.prototype.getEndSessionUrl = function(req) {
    var config = this.config;
    var session;
    if(config.useCookie === true)
    {
        session = req.cookies.IDSRV3;
    }
    else
    {
        session = req._passport.session;
    }

     
    var params = {
            id_token_hint: session.tokens.id_token,
            post_logout_redirect_uri: this.config.post_logout_redirect_uri || common.resolveUrl(req, '/')
        };

    return common.addQuery(this.config.end_session_endpoint, params);
};

function getAccessToken(session, config, params, callback, req) {
    extend(params, {
        client_id: config.client_id,
        client_secret: config.client_secret
    });

    common.form('POST', config.token_endpoint, params, null, function(err, data) {
        if(err) { return callback(err) }

        data = JSON.parse(data);
        data.expires_at = Date.now() + (data.expires_in * 1000) - common.timeout; // Take off a buffer so token won't expire mid call

        session.tokens = data;
        
        if(config.useCookie === true)
        {
            req.res.cookie('IDSRV3', req.cookies.IDSRV3);            
        }
        callback(null, data);
    });
}

module.exports = Client;