const router = require('express').Router();
const bcrypt = require('bcryptjs');

const Users = require('../users/users-model.js');

// for endpoints beginning with /api/auth

//----------------------------------------------------------------------------//
// this method just gets a user into our DB, so /login attempts have a
// username/hash to compare to.
//----------------------------------------------------------------------------//
router.post('/register', (req, res) => {
  let user = req.body;
  const hash = bcrypt.hashSync(user.password, 10); // 2 ^ n
  user.password = hash;

  Users.add(user)
    .then(saved => {
      res.status(201).json(saved);
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

//----------------------------------------------------------------------------//
// Here we pull the username/password from the body, and use them to validate
// the password "guess", just like in webauth-i-guided. 
//
// NOTE: In the last class, we demonstrated using restricted middleware to
// retrieve username/password from headers, and validating the password using
// bcrypt. This was the same logic as the /login handler, so we could simplify
// the /login handler to just use the restricted middleware, and all of that
// logic would be handled by the middleware. 
//
// But in this guided project, we want to look for the presence of data on the
// req.session object that indicates that a valid cookie (unexpired, with a
// valid session ID) was included. We know that the cookie is valid because it
// points to a session record in the store, which contains a property that could
// only have been set by a successful login. 
//
// One thing that I discovered in my testing is that the req.session object is
// ALWAYS created by express-session, whether there is a cookie or not, and
// whether or not the cookie has a valid session ID for an unexpired session. It
// always creates a req.session object. What's more, req.session.id (and
// req.sessionID, which are the same value) ALWAYS has a value. That value will
// be the value that came in a cookie header, if one was sent (and if it is
// valid). Otherwise, it will be a randomized identifier created by
// express-session. Express-session will automatically create a session record
// in the store IFF the req.session object has been modified. The identifier in
// the session record will be the randomly-generated value. The session record
// is saved when the HTTP request is ended, and a response is sent (again, only
// if it has been modified - based on the sessionOptions property
// "saveUninitialized".) So the act of setting req.session.loggedin will result
// in a session object being created, and a set-cookie header being added to the
// response. This is true even if req.session.loggedin is set to false! We must
// NOT modify req.session *unless* we are certain that we want a session record
// created. Reason out what would happen if we set req.session.loggedin = false,
// and the user then failed to authenticate... and then tried to authenticate
// again (and did so successfully.) What would happen? (Good thought
// exercise...)
//
// We don't want our "restricted" middleware looking for credentials in headers,
// we want it looking for validation information in req.session (which came from
// the database because a cookie with a valid ID was sent...). So, the logic of
// looking for username/password (either in headers or in the request body -
// this is a POST, so the request body will work fine) needs to remain in /login
// handler.
//
// On successful login, we not only send a 200 back, but we also store something
// on the req.session object, so that other middleware methods (like our
// restricted() function) can tell that this handler validated the credentials.
// Essentially, adding this value to the req.session object indicates to the
// rest of our middleware methods that the session is "valid" or "active". In
// addition, modifying req.session will cause it to be saved as a session record
// (together with any data we added to it), which will be stored in our store.
// AND, doing that will cause express-session to add a set-cookie header on our
// response, causing the browser to 1) store the cookie value (which is an
// encrypted form of the session ID), and 2) include it in a cookie header in
// subsequent requests (until the cookie expires). That way, every subsequent
// request has a value that express-session can attempt to decrypt, and if it
// succeeds, it can then check the session store to see if it is for a valid
// session, and if it is, it can add the session record from the store to the
// req.session object. That way, our restricted middleware can check to see if
// the req.session object is the default vanilla one, or if it came from our
// store, which means that a valid session ID was sent in by the browser. Phew.
// Taking a nap now. 
//----------------------------------------------------------------------------//
router.post('/login', (req, res) => {
  let { username, password } = req.body;


  Users.findBy({ username })
    .first()
    .then(user => {
      if (user && bcrypt.compareSync(password, user.password)) {
        // add something to req.session to indicate success here... one option
        // is:
        //
        //    req.session.user = user
        //
        // HOWEVER, the user object (which is the full user object that came
        // back from the DB) contains the password hash, and the username... and
        // if we are storing session info in a database, it's just another
        // attack vector with data that we really would rather not distribute...
        // 
        // The hash is pretty useless, but we should not be cavalier with data
        // like that, just to be uber-safe. 
        //
        // You can put whatever you want in req.session, just so that you know
        // what to look for in other middleware functions so they know that this
        // login succeeded.
        //
        // Another option could be:
        //
        //    req.session.loggedin = true;
        //
        // Good job /login grasshopper. You have passed the test.
        // 
        // Remember that this will force a session record to be created, and a
        // set-cookie header to be sent back to the browser. Exactly what we
        // want. 
        req.session.loggedin = true;
        res.status(200).json({ message: `Welcome ${user.username}! have a... biscuit.`, });
      } else {
        // req.session.loggedin will not exist if we end up here... see above...
        // so we are not in danger of a session being created - we just don't
        // modify req.session, and we are good.
        res.status(401).json({ message: 'Nice try. But, no. Try. Try again.' });
      }
    })
    .catch(error => {
      // req.session.loggedin will not exist if we end up here... see above...
      // so we are not in danger of a session being created - we just don't
      // modify req.session, and we are good.     
      res.status(500).json(error);
    });
});

//----------------------------------------------------------------------------//
// logging out could be done with the GET or POST or PUT or any HTTP method...
// but in the end, to "log out", we are going to .destroy() the session, and
// destroying things is part of CRUD, the part that lines up with the DELETE
// HTTP method. So, we will implement /logout as a DELETE request...
//----------------------------------------------------------------------------//
router.delete('/logout', (req, res) => {
  if (req.session) {
    // check out the documentation for this method at
    // https://www.npmjs.com/package/express-session, under Session.destroy().
    req.session.destroy((err) => {
      if (err) {
        res.status(400).send('queue the groundhog day trope... you can never leave...');
      } else {
        res.send('you made it out! good job!');
      }
    });
  } else {
    res.end();
  }
});

module.exports = router;
