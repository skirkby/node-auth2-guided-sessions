const router = require('express').Router();

const Users = require('./users-model.js');
const restricted = require('../auth/restricted-middleware.js');

//----------------------------------------------------------------------------//
// This method is protected by our restricted middleware. If the browser did not
// include a cookie with a valid session ID, then req.session will not include a
// .loggedin : true property, and restricted will end the request with a 4xx
// result code. 
// 
// The only way to get access to this API handler is to 1) successfully log in
// (which causes a session record to be created, together with our custom data),
// and 2) have the browser send a cookie with the right name and value (which it
// will, as long as the cookie hasn't expired - which would mean that the
// session has expired.) By the way, we expire sessions to prevent people from
// accidentally staying logged in for a long time, such taht someone else can
// access their data by using the same browser that they did. 
//----------------------------------------------------------------------------//
router.get('/', restricted, (req, res) => {
  Users.find()
    .then(users => {
      res.json(users);
    })
    .catch(err => res.send(err));
});

module.exports = router;
