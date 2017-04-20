const express = require('express'),
      router = express.Router(),
      jwt = require('jsonwebtoken'),
      jsonFormat = require('json-format'),
      a0 = require('../lib/auth0Client');

router.get('/', function(req, res, next) {
  res.render('index', { title: 'Web Phone' });
});

router.get('/pin', function(req, res, next) {
  res.render('pin', { title: 'Web Phone' });
});

router.get('/tasks', function(req, res, next) {
  res.render('tasks', { title: 'Web Phone' });
});

router.get('/challenge', function(req, res, next) {
  let challenge_type = req.query.challenge_type || "otp";
  if (challenge_type==="otp")
    res.redirect(`/challenge/otp`);
  else if (challenge_type==="oob")
    res.redirect(`/challenge/oob`);
  else next();
});

router.get('/challenge/otp', function(req, res, next) {
  res.render('otp-challenge', { title: 'Web Phone'});
});

router.get('/summary', function(req, res, next) {
    let auth = req.session.auth;
    let atClaims, idClaims = "{}";
    if (auth && auth.access_token) {
      atClaims = jsonFormat(jwt.decode(auth.access_token));
    }
    if (auth && auth.id_token) {
      idClaims = jsonFormat(jwt.decode(auth.id_token));
    }

    res.render('summary', { title: 'Web Phone', auth: {idClaims, atClaims} });
});


router.post('/', function(req, res, next) {

  let msisdn = req.body.msisdn; 
  req.session.msisdn = msisdn;
  if (!process.env.TwilioMode)
  { 
    res.redirect('pin');
  }
});

router.post('/pin', function(req, res, next) {
  let pin = req.body.pin;

  if (!process.env.TwilioMode)
  {
    req.session.pin = pin;
    res.redirect('/tasks');
  }

});

router.post('/tasks', function(req, res, next) {
  let msisdn = req.session.msisdn,
      pin = req.session.pin,
      scope = req.body.tasks;

    if (Array.isArray(scope))
      scope = scope.join(' ');

  a0.login(msisdn,pin,scope)
  .then(r=>{
    req.session.auth = r;
    if (!process.env.TwilioMode){
      res.redirect('/summary');
    }
  })
  .catch(err=>{
    let mfa_token = err.mfa_token;
    if (mfa_token) {

      req.session.scope = scope; 
      req.session.mfa_token = mfa_token;

      a0.startMFAChallenge(mfa_token)
      .then(r=>{
        if (!process.env.TwilioMode) {
          if (r.challenge_type==="otp")
            res.redirect(`/challenge/otp`);
          else if (r.challenge_type==="oob")
            res.redirect(`/challenge/oob`);
        }
      });
    }
    else next(err);
  });  
});

router.post('/challenge/otp', function(req, res, next) {
  let otp = req.body.otp,
    mfa_token = req.session.mfa_token,
    scope = req.session.scope;

  a0.completeOTPChallenge(otp,mfa_token,scope)
  .then(r=>{
    req.session.auth = r;
    if (!process.env.TwilioMode){
      res.redirect('/summary');
    }
  })
  .catch(err=>next(err));
});


module.exports = router;