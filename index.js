var util = require('util');
var uri = require('url');
var crypto = require('crypto');
var OAuth2Strategy = require('passport-oauth2');
var InternalOAuthError = require('passport-oauth2').InternalOAuthError;

util.inherits(GoogleAuthCodeStrategy, OAuth2Strategy);

/**
 * `GoogleAuthCodeStrategy` constructor.
 *
 * The Google authentication strategy authenticates requests by delegating to
 * Google using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occurred, `error` should be set.
 *
 * Options:
 *   - `clientID`      your Google application's App ID
 *   - `clientSecret`  your Google application's App Secret
 *
 * Examples:
 *
 *     passport.use(new GoogleAuthCodeStrategy({
 *         clientID: '123-456-789',
 *         clientSecret: 'shhh-its-a-secret'
 *       },
 *       function(accessToken, refreshToken, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function GoogleAuthCodeStrategy(options, verify) {
  options = options || {};
  options.authorizationURL = options.authorizationURL || 'https://accounts.google.com/o/oauth2/auth';
  options.tokenURL = options.tokenURL || 'https://accounts.google.com/o/oauth2/token';
  options.scopeSeparator = options.scopeSeparator || ',';

  OAuth2Strategy.call(this, options, verify);

  this.name = 'google-authcode';
  this._authCodeField = options.authCodeField || 'code';
  this._redirectUriField = options.redirectUriField || 'redirectUri';
  this._passReqToCallback = options.passReqToCallback;
  this._profileURL = options.profileURL || 'https://www.googleapis.com/oauth2/v1/userinfo';
  this._clientSecret = options.clientSecret;
  this._enableProof = options.enableProof;
  this._profileFields = options.profileFields || null;
  this._oauth2._useAuthorizationHeaderForGET = false;
}

/**
 * Authenticate request by delegating to a service provider using OAuth 2.0.
 * @param {Object} req
 * @param {Object} options
 * @api protected
 */
GoogleAuthCodeStrategy.prototype.authenticate = function(req, options) {
  var self = this;
  authCode = (req.body && req.body[self._authCodeField]) || (req.query && req.query[self._authCodeField]) || (req.headers && req.headers[self._accessTokenField]),
  redirectUri = (req.body && req.body[self._redirectUriField]) || (req.query && req.query[self._redirectUriField]) || (req.headers && req.headers[self._refreshTokenField]);

  if (!authCode) {
    return this.fail({
      message: 'You should provide auth code'
    });
  }

  self._exchangeAuthCode(authCode, redirectUri, function(error, accessToken, refreshToken, resultsJson) {
    if (error) return self.fail(error);

    self._loadUserProfile(accessToken, function(error, profile) {
      if (error) return self.fail(error);

      function verified(error, user, info) {
        if (error) return self.error(error);
        if (!user) return self.fail(info);

        return self.success(user, info);
      }

      if (self._passReqToCallback) {
        self._verify(req, accessToken, refreshToken, profile, verified);
      } else {
        self._verify(accessToken, refreshToken, profile, verified);
      }
    });
  });
};


/**
 * Exchange authorization code for tokens
 *
 * @param {String} authCode
 * @param {Function} done
 * @api private
 */
GoogleAuthCodeStrategy.prototype._exchangeAuthCode = function(authCode, redirectUri, done) {
  var params = {
    'grant_type': 'authorization_code',
    'redirect_uri': redirectUri
  };
  this._oauth2.getOAuthAccessToken(authCode, params, done);
}


/**
 * Return extra Google-specific parameters to be included in the authorization
 * request.
 *
 * Options:
 *  - `display`  Display mode to render dialog, { `page`, `popup`, `touch` }.
 *
 * @param {Object} options
 * @return {Object}
 * @api protected
 */
GoogleAuthCodeStrategy.prototype.authorizationParams = function(options) {
  return options.display ? {
    display: options.display
  } : {};
};

/**
 * Retrieve user profile from Google.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `provider`         always set to `google`
 *   - `id`               the user's Google ID
 *   - `username`         the user's Google username
 *   - `displayName`      the user's full name
 *   - `name.familyName`  the user's last name
 *   - `name.givenName`   the user's first name
 *   - `name.middleName`  the user's middle name
 *   - `gender`           the user's gender: `male` or `female`
 *   - `profileUrl`       the URL of the profile for the user on Google
 *   - `emails`           the proxied or contact email address granted by the user
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */
GoogleAuthCodeStrategy.prototype.userProfile = function(accessToken, done) {
  var url = uri.parse(this._profileURL);

  if (this._enableProof) {
    var proof = crypto.createHmac('sha256', this._clientSecret).update(accessToken).digest('hex');
    url.search = (url.search ? url.search + '&' : '') + 'appsecret_proof=' + encodeURIComponent(proof);
  }

  url = uri.format(url);

  this._oauth2.get(url, accessToken, function(error, body, res) {
    if (error) return done(new InternalOAuthError('Failed to fetch user profile', error));

    try {
      var json = JSON.parse(body),
        profile = {
          provider: 'google',
          id: json.id,
          displayName: json.name || '',
          name: {
            familyName: json.family_name || '',
            givenName: json.given_name || '',
            middleName: json.middle_name || ''
          },
          gender: json.gender || '',
          locale: json.locale || '',
          emails: [{
            value: json.email || ''
          }],
          photos: [{
            value: json.picture || ''
          }],
          _raw: body,
          _json: json
        };

      done(null, profile);
    } catch (e) {
      done(e);
    }
  });
};

/**
 * Expose `GoogleAuthCodeStrategy`.
 */
module.exports = GoogleAuthCodeStrategy;
module.exports.Strategy = GoogleAuthCodeStrategy;
