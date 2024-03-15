const jwt = require("jsonwebtoken");
const Router = require("express").Router;
const router = new Router();
const app = require("../app");
const User = require("../models/user");
const { SECRET_KEY } = require("../config");
const ExpressError = require("../expressError");

/** POST /login - login: {username, password} => {token}
 *
 * Make sure to update their last-login!
 *
 **/

router.post("/login", async function (req, res, next) {
  try {
    const { username, password } = req.body;
    const can_authenticate = await User.authenticate(username, password);
    if (can_authenticate) {
      let login_timestamp = await User.updateLoginTimestamp(username);
      let token = jwt.sign({ username, login_timestamp }, SECRET_KEY);
      return res.json({ token });
    } else {
      throw new ExpressError("Invalid Username/password", 400);
    }
  } catch (e) {
    return next(e);
  }
});
/** POST /register - register user: registers, logs in, and returns token.
 *
 * {username, password, first_name, last_name, phone} => {token}.
 *
 *  Make sure to update their last-login!
 */
router.post("/register", async (req, res, next) => {
  try {
    let { username } = req.body;
    let token = jwt.sign({ username }, SECRET_KEY);
    User.updateLoginTimestamp(username);
    return res.json({ token });
  } catch (e) {
    return next(e);
  }
});

module.exports = router;
