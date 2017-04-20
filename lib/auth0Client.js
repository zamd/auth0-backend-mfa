
var rp = require('request-promise');
var WebAuth = require('auth0-js').WebAuth;
class Auth0Client {

    constructor(options){
        this.options = options;
        this.options.clientID = this.options.clientId;
        this.webAuth = new WebAuth(options);
    }



    login(msisdn, pin, scope){

        let clientId =  this.options.clientId, 
        clientSecret = this.options.clientSecret;

        // append 'openid profile' 
        scope = "openid profile".concat(' ',scope || '');

        return new Promise((resolve,reject)=>{
            console.log(`getting token...`);
            rp.post({
                uri: `https://${this.options.domain}/oauth/token`,
                json: {
                    client_id: clientId,
                    client_secret: clientSecret,
                    grant_type: 'password',
                    scope: scope,
                    username: msisdn,
                    password: pin
                }
            })
            .then(r=>resolve(r))
            .catch(err=>{
                if (err.error.error && err.error.error && err.error.error==="mfa_required")
                    reject({mfa_token:err.error.mfa_token});
                else this.handleError('failed to get token',err,reject);
            });
        });
    }


    startMFAChallenge(mfa_token){

        let clientId =  this.options.clientId, 
        clientSecret = this.options.clientSecret;

        return new Promise((resolve,reject)=>{
            console.log(`mfa challenge...`);
            rp.post({
                uri: `https://${this.options.domain}/mfa/challenge`,
                json: {
                    client_id: clientId,
                    client_secret: clientSecret,
                    mfa_token: mfa_token
                }
            })
            .then(r=>resolve(r))
            .catch(err=>{
                this.handleError('failed to strat mfa challenge',err,reject);
            });
        });
    }

    completeOTPChallenge(otp, mfa_token, scope){

        let clientId =  this.options.clientId, 
        clientSecret = this.options.clientSecret;

        scope = scope || "openid profile"

        return new Promise((resolve,reject)=>{
            console.log(`mfa challenge response...`);
            rp.post({
                uri: `https://${this.options.domain}/oauth/token`,
                json: {
                    grant_type: "http://auth0.com/oauth/grant-type/mfa-otp",
                    client_id: clientId,
                    client_secret: clientSecret,
                    scope: scope, 
                    mfa_token: mfa_token,
                    otp: otp
                }
            })
            .then(r=>resolve(r))
            .catch(err=>{
                this.handleError('failed to complete mfa challenge',err,reject);
            });
        });
    }


    getTokenAsync(clientId, clientSecret){

        clientId = clientId || this.options.clientId;
        clientSecret = clientSecret || this.options.clientSecret;

        return new Promise((resolve,reject)=>{
            console.log(`getting token...`);
            rp.post({
                uri: `https://${this.options.domain}/oauth/token`,
                json: {
                    client_id: clientId,
                    client_secret: clientSecret,
                    grant_type: 'client_credentials',
                    audience: `https://${this.options.domain}/api/v2/`,
                    scope: 'create:users'
                }
            })
            .then(r=>resolve(r))
            .catch(err=>this.handleError('failed to get token',err,reject));
        });
    }

    handleError(message, err, handler) {
        console.log(err);
        handler(new Error(message));
    }

    startPasswordless(user) {
        return new Promise( (resolve, reject) => {
            console.log(`starting passwordless...`);
            rp.post({
                uri: `https://${this.options.domain}/passwordless/start`,
                json: {
                    connection: 'sms',
                    phone_number: user.phone,
                    send: 'code'
                }
            })
            .then(r=>resolve(r))
            .catch(err=>this.handleError('failed to start passwordless', err,reject));
            });       
    }

    verifyOTP(phone, otp){

        let clientId = this.options.clientId;
        let clientSecret = this.options.clientSecret;

        return new Promise((resolve,reject)=>{
            rp.post({
                uri: `https://${this.options.domain}/oauth/ro`,
                json: {
                    client_id: clientId,
                    client_secret: clientSecret,
                    connection: 'sms',
                    grant_type: 'password',
                    username: phone,
                    password: otp
                }
            })
            .then(r=>resolve(r))
            .catch(err=>this.handleError('failed to get token',err,reject));
        });
    }

    createUserAsync(user){
        return new Promise( (resolve, reject) => {
            this.getTokenAsync()
            .then(res=>{
                console.log(`creating user...`);
                rp.post({
                    uri: `https://${this.options.domain}/api/v2/users`,
                    headers: {
                        'Authorization': `Bearer ${res.access_token}`
                    },
                    json: {
                        connection: this.options.connection,
                        username: user.phone,
                        email: user.email,
                        password: user.password,
                        user_metadata: {
                            phone_verified: false
                        }
                    }
                })
                .then(r=>resolve(r))
                .catch(err=>this.handleError('failed to create user', err,reject));
            })
        });
    }

    buildAuthorizationCodeUrl(state){
        return this.webAuth.client.buildAuthorizeUrl({responseType: "code", state:state});
    }

    exchangeCodeForToken(code) {
        return new Promise((resolve,reject)=>{
            this.webAuth.client.oauthToken({
                clientID: this.options.clientId,
                clientSecret: this.options.clientSecret,
                grantType: "authorization_code",
                code: code,
                redirectUri: this.options.redirectUri
            }, (err,result)=> err ? 
                                this.handleError('code exchanged failed',err,reject) : 
                                resolve(result));
        });
    }
}

module.exports = new Auth0Client({
    domain: process.env.Domain,
    clientId:process.env.ClientID,
    clientSecret: process.env.ClientSecret,
    redirectUri: process.env.CallbackURL
});