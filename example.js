var express = require('express'),
    session = require('express-session'),
    passport = require('passport'),
    Identity3Strategy = require('./strategy'),
    Client = require('./client');

// Don't leave this in your production app
process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = '0';

var app = express();

app.use(express.cookieParser());
app.use(session({ secret: 'keyboard mouse' }));
app.use(passport.initialize());
app.use(passport.session());
app.use(function(req, res, next) {
    if(!req.isAuthenticated() && !req.url.match(/^\/login/)) {
        res.redirect('/login');
    } else {
        next();
    }
});

app.get('/', function(req, res) {
    res.writeHead(200, {
        'Content-Type': 'text/html'
    });

    passport._strategy('custom_name').profile(req, ['profile'], null, function(err, profile) {
        res.end('<html><body>Logged in, <a href="/logout">Logout</a><pre>' + JSON.stringify(profile, null, 2) + '</pre></body></html>');
    });
});

app.get('/login', 
    passport.authenticate('custom_name', { failureRedirect: '/login' }),
    function(req, res) { // Successful login handler, just redirect to homepage
        res.redirect('/');
    });

app.get('/logout', function(req, res) {
    passport._strategy('custom_name').endSession(req, res);
});

passport.use(new Identity3Strategy('custom_name', {
    configuration_endpoint: 'https://localhost:44333/.well-known/openid-configuration',
    client_id: 'your_client_id',
    client_secret: 'your_client_secret',
    callback_url: '/login',
    scopes: ['profile', 'offline_access'],
    transformIdentity: function(identity) {
        return identity;
    }
}));

passport.serializeUser(function(user, done) {
    done(null, user);
});

passport.deserializeUser(function(user, done) {
    done(null, user);
});

app.listen(8001);