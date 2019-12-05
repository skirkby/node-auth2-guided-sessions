const bcrypt = require('bcryptjs');

const Users = require('../users/users-model.js');

module.exports = (req, res, next) => {

  //----------------------------------------------------------------------------//
  // simply check to see if the session object exists (in case SOMEONE
  // configured things wrong...), and if it does, check for the .loggedin ===
  // true condition.
  //
  // if that's all cool, then... NEXT!
  //----------------------------------------------------------------------------//
  if (req.session && (req.session.loggedin === true)) {
    next();
  } else {
    res.status(400).json({ message: "Stop! Who approaches the Bridge of Death must answer me these questions three, 'ere the other side he see." });
  }
};
