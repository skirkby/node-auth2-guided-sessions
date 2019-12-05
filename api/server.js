//----------------------------------------------------------------------------//
// the two new modules for this topic... express-session basically manages
// session data in a store of some kind, and manages the processing of inbound
// cookies, and outbound cookies, related to the session.
//
// connect-session-knex is a module that allows express-session to use knex to
// store session/cookie data
//----------------------------------------------------------------------------//
const session = require('express-session');
const knexSessionStore = require('connect-session-knex')(session);

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');

const authRouter = require('../auth/auth-router.js');
const usersRouter = require('../users/users-router.js');

//----------------------------------------------------------------------------//
// the options for express-session. Most of these options have to do with how
// the cookies are managed, and how session data is stored.
//
// see express-session documentation at npmjs.org for info on these and other
// options.
//
// note that the options under "store:" are for connect-session-knex. You can
// read about them under that module at npmjs.org.
//----------------------------------------------------------------------------//
const sessionOptions = {
  name: 'mycookie',
  secret: 'cookiesareyumyummewantcookies',
  cookie: {
    maxAge: 1000 * 60 * 60,
    secure: false,
    httpOnly: true
  },
  resave: false,
  saveUninitialized: false,

  store: new knexSessionStore({
    knex: require('../database/dbConfig.js'),
    tablename: 'sessions',
    sidfieldname: 'sid',
    createtable: true,
    clearInterval: 1000 * 60 * 60
  })
};

const server = express();


server.use(helmet());
server.use(express.json());
server.use(cors());

//----------------------------------------------------------------------------//
// the session object is a middleware method. by server.use()'ing it here,
// without a METHOD or url, we ensure that it is called for *every* request.
//
// this middleware will basically manage cookie processing and sending, and
// related session data in the store.
//
// Also, this middleware method will create an object on req called "session".
// It's just an object that contains info about the cookie that came from the
// browser, as well as the cookie that needs to be sent to the browser, info
// about the session store, and any other data that we choose to add to it. See
// the /login handler to see how we add something to req.session so that our
// restricted() middleware can tell if the request came with a valid cookie.
//----------------------------------------------------------------------------//
server.use(session(sessionOptions));

server.use('/api/auth', authRouter);
server.use('/api/users', usersRouter);

server.get('/', (req, res) => {
  res.json({ api: 'up' });
});

module.exports = server;
