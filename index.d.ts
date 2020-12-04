import * as express from 'express';
import * as passport from 'passport';

declare namespace GoogleTokenStrategy {
	interface StrategyStatic {
		new (options: StrategyOptionsWithRequest, verify: VerifyFunctionWithRequest): StrategyInstance;
		new (options: StrategyOptions, verify: VerifyFunction): StrategyInstance;
	}

	interface StrategyInstance {
		name: string;
		authenticate: (req: express.Request, options?: any) => void;
    }

    interface ValueObject {
        value: string;
    }
    
    interface Profile extends passport.Profile {
        provider: string;
        id: string;
        displayName: string;
        name: {
            familyName: string;
            givenName: string;
            middleName: string;
        };
        gender: string;
        emails: ValueObject[];
        photos: ValueObject[];
        _raw: string;
        _json: any;
    }

	interface StrategyOptions {
		clientID: string;
		clientSecret: string;
		callbackURL?: string;
		authorizationURL?: string;
		tokenURL?: string;
	}

	interface StrategyOptionsWithRequest extends StrategyOptions {
		passReqToCallback: true;
	}

	type VerifyFunction = (
		accessToken: string,
		refreshToken: string,
		profile: Profile,
		done: (error: any, user?: any, info?: any) => void,
	) => void;

	type VerifyFunctionWithRequest = (
		req: express.Request,
		accessToken: string,
		refreshToken: string,
		profile: Profile,
		done: (error: any, user?: any, info?: any) => void,
	) => void;
}

declare const GoogleTokenStrategy: GoogleTokenStrategy.StrategyStatic;
export = GoogleTokenStrategy;
