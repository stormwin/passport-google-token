'use strict';

const { OAuth2Strategy, InternalOAuthError } = require('passport-oauth');

module.exports = class GoogleTokenStrategy extends OAuth2Strategy {
	/**
	 * `Strategy` constructor.
	 *
	 * The Google authentication strategy authenticates requests by delegating to
	 * Google using the OAuth 2.0 protocol.
	 *
	 * Applications must supply a `verify` callback which accepts an `accessToken`,
	 * `refreshToken` and service-specific `profile`, and then calls the `done`
	 * callback supplying a `user`, which should be set to `false` if the
	 * credentials are not valid.  If an exception occured, `err` should be set.
	 *
	 * Options:
	 *   - `clientID`      your Google application's client id
	 *   - `clientSecret`  your Google application's client secret
	 *   - `callbackURL`   URL to which Google will redirect the user after granting authorization
	 *
	 * Examples:
	 *
	 *     passport.use(new GoogleStrategy({
	 *         clientID: '123-456-789',
	 *         clientSecret: 'shhh-its-a-secret'
	 *         callbackURL: 'https://www.example.net/auth/google/callback'
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
	constructor(options, verify) {
		const _options = options || {};
		_options.authorizationURL = options.authorizationURL || 'https://accounts.google.com/o/oauth2/auth';
		_options.tokenURL = options.tokenURL || 'https://accounts.google.com/o/oauth2/token';

		super(_options, verify);
		this.options = _options;
		this.verify = verify;
		this.name = 'google-token';
	}

	/**
	 * Authenticate request by delegating to a service provider using OAuth 2.0.
	 *
	 * @param {Object} req
	 * @api protected
	 */
	authenticate(req) {
		if (req.query && req.query.error) {
			// TODO: Error information pertaining to OAuth 2.0 flows is encoded in the
			//       query parameters, and should be propagated to the application.
			return this.fail();
		}

		if (!req.body) {
			return this.fail();
		}

		const accessToken = req.body.access_token || req.query.access_token || req.headers.access_token;
		const refreshToken = req.body.refresh_token || req.query.refresh_token || req.headers.refresh_token;

		this.loadUserProfile(accessToken, function (err, profile) {
			if (err) {
				return this.fail(err);
			}

			function verified(err, user, info) {
				if (err) {
					return this.error(err);
				}

				if (!user) {
					return this.fail(info);
				}

				this.success(user, info);
			}

			if (this._passReqToCallback) {
				this.verify(req, accessToken, refreshToken, profile, verified);
			} else {
				this.verify(accessToken, refreshToken, profile, verified);
			}
		});
	}

	/**
	 * Retrieve user profile from Google.
	 *
	 * This function constructs a normalized profile, with the following properties:
	 *
	 *   - `provider`         always set to `google`
	 *   - `id`
	 *   - `username`
	 *   - `displayName`
	 *
	 * @param {String} accessToken
	 * @param {Function} done
	 * @api protected
	 */
	userProfile(accessToken, done) {
		this._oauth2.get('https://www.googleapis.com/oauth2/v2/userinfo', accessToken, (err, body) => {
			if (err) {
				return done(new InternalOAuthError('failed to fetch user profile', err));
			}

			try {
				const json = JSON.parse(body);

				const profile = {
					provider: 'google',
					id: json.id,
					displayName: json.name,
					name: {
						familyName: json.family_name,
						givenName: json.given_name,
						middleName: json.middle_name,
					},
					gender: json.gender,
					emails: [{value: json.email}],
					photos: [{value: json.picture }],
					_json: json,
					_raw: body
				};

				done(null, profile);
			} catch (e) {
				done(e);
			}
		});
	}

	/**
	 * Load user profile, contingent upon options.
	 *
	 * @param {String} accessToken
	 * @param {Function} done
	 * @api private
	 */
	loadUserProfile(accessToken, done) {
		if (typeof this._skipUserProfile === 'function' && this._skipUserProfile.length > 1) {
			this._skipUserProfile(accessToken, (err, skip) => {
				if (err) {
					return done(err);
				}

				if (!skip) {
					return this.userProfile(accessToken, done);
				}

				return done(null);
			});
		} else {
			const skip = typeof this._skipUserProfile === 'function' ? this._skipUserProfile() : this._skipUserProfile;
			if (!skip) {
				return this.userProfile(accessToken, done);
			}
			return done(null);
		}
	}
};
