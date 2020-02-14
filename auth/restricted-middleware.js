// const bcrypt = require('bcryptjs');

// const Users = require('../users/users-model.js');

module.exports = (req, res, next) => {


  //----------------------------------------------------------------------------//
  // In a previous version of this project, I had a check to see if the
  // req.session object existed at all. This is pointless, since it will ALWAYS
  // exist, even if no cookie is sent by the browser. express-session seems to
  // always create req.session. This is because the method for actually causing
  // a session record to be saved to the store is modifying req.session (based
  // on the saveUniniialized sessionOption setting in server.js). Kinda hard to
  // do that if it doesn't exist (actually, you could create your own, if it
  // didn't exist, but hookups that allow express-session to know it was
  // modified, and some critical data that express-session needs to know about
  // the session and the cookie could be left off - such as the expiration date.
  // This is express-session's way of ensuring that all of this stuff is there
  // when it saves the session.)
  //
  // In this version, all we do is check to see if req.session.loggedin exists,
  // and if so, if it is true. 
  //
  // if that's all cool, then... NEXT!
  //----------------------------------------------------------------------------//
  // if (req.session && (req.session.loggedin === true)) {
  if (req.session.loggedin && (req.session.loggedin === true)) {
    next();
  } else {
    res.status(400).json({ message: "Stop! Who approaches the Bridge of Death must answer me these questions three, 'ere the other side he see." });
  }
};
