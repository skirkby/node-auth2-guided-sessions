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
// here we pull the username/password from the body, and use them to validate
// the password "guess", just like in webauth-i-guided.
//
// BUT, on successful login, we not only send a 200 back, but we also store
// something on the req.session object, so that other middleware methods (like
// our restricted() function) can tell that this handler validated the
// credentials. Essentially, adding this value to the req.session object
// indicates to the rest of our middleware methods that the session is "valid"
// or "active".
//----------------------------------------------------------------------------//
router.post('/login', (req, res) => {
  let { username, password } = req.body;

  // we will assume that the login is going to fail... make login WORK FOR IT,
  // baby! setting this value to false is better than adding the full user
  // object (which includes the user hash). and defaulting it to false here
  // prevents accidental "truthiness", and also makes your meaning clear.
  //
  // there are 2 potential error conditions below... if we end up in either one,
  // we are already covered. req.session.loggedin will only be true if we pass
  // the bcrypt test.
  req.session.loggedin = false;

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
        // attack vector with valuable data that we really want to keep safe...
        //
        // you can put whatever you want in req.session, just so that you know
        // what to look for in other middleware functions so they know that this
        // login succeeded.
        //
        // another option could be:
        //
        //    req.session.loggedin = true;
        //
        // we defaulted this to "false" above, and can change it to true here.
        // Good job /login grasshopper. You have passed the test.
        req.session.loggedin = true;
        res.status(200).json({ message: `Welcome ${user.username}! have a... biscuit.`, });
      } else {
        // req.session.loggedin will already be false if we end up here... see
        // above..
        res.status(401).json({ message: 'Nice try. But, no. Try. Try again.' });
      }
    })
    .catch(error => {
      // req.session.loggedin will already be false if we end up here... see
      // above..      
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
    console.log(req.session);
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
