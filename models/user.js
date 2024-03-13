const bcrypt = require("bcrypt");
const { BCRYPT_WORK_FACTOR, SECRET_KEY } = require("../config");
const db = require("../db");
const jwt = require("jsonwebtoken");
const ExpressError = require("../expressError");
/** User class for message.ly */

/** User of the site. */

class User {
  /** register new user -- returns
   *    {username, password, first_name, last_name, phone}
   */

  static async register({ username, password, first_name, last_name, phone }) {
    const hashedPassword = await bcrypt.hash(password, BCRYPT_WORK_FACTOR);
    const result = await db.query(
      `INSERT INTO users (username, password, first_name, last_name, phone)
      VALUES($1, $2, $3, $4, $5)
      RETURNING username, password, first_name, last_name, phone`,
      [username, hashedPassword, first_name, last_name, phone]
    );
    let user = result.rows[0];
    if (!user) {
      throw new ExpressError(`There was an error`, 404);
    }
    return {
      username: user.username,
      password: user.hashedPassword,
      first_name: user.first_name,
      last_name: user.last_name,
      phone: user.phone,
    };
  }

  /** Authenticate: is this username/password valid? Returns boolean. */

  static async authenticate(username, password) {
    const result = await db.query(
      `SELECT password FROM users WHERE username = $1`,
      [username]
    );
    const user = result.rows[0];
    if (!user) {
      throw new ExpressError("Invalid username", 404);
    }
    return await bcrypt.compare(password, user.password);
  }

  /** Update last_login_at for user */

  static async updateLoginTimestamp(username) {
    const result = await db.query(
      `UPDATE users SET last_login_at = current_timestamp
        WHERE username=$1
        RETURNING username, last_login_at`,
      [username]
    );

    if (!result.rows[0]) {
      throw new ExpressError(`No such user: ${username}`, 404);
    }
    return result.rows[0];
  }

  /** All: basic info on all users:
   * [{username, first_name, last_name, phone}, ...] */

  static async all() {
    const result = await db.query(
      `SELECT username, first_name, last_name, phone FROM users`
    );
    if (!result.rows) {
      throw new ExpressError(`No users were found`, 404);
    }
    return result.rows;
  }

  /** Get: get user by username
   *
   * returns {username,
   *          first_name,
   *          last_name,
   *          phone,
   *          join_at,
   *          last_login_at } */

  static async get(username) {
    const result = await db.query(
      `SELECT username, first_name, last_name, phone, join_at, last_login_at FROM users WHERE username = $1`,
      [username]
    );
    const user = result.rows[0];
    if (!user) {
      throw new ExpressError(`No such user: ${username}`, 404);
    }
    return user;
  }

  /** Return messages from this user.
   *
   * [{id, to_user, body, sent_at, read_at}]
   *
   * where to_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesFrom(username) {
    const result = await db.query(
      `SELECT m.id, m.to_username, t.first_name AS to_first_name, t.last_name AS to_last_name, t.phone AS to_phone, m.body, m.sent_at, m.read_at 
    FROM messages AS m
    JOIN users AS t on m.to_username = t.username
    WHERE m.from_username=$1`,
      [username]
    );
    let messages = result.rows;
    if (!messages) {
      throw new ExpressError(`No messages were sent from ${username}`, 404);
    }
    return {
      id: messages.id,
      body: messages.body,
      sent_at: messages.sent_at,
      read_at: messages.read_at,
      to_user: {
        username: messages.to_username,
        first_name: messages.to_first_name,
        last_name: messages.to_last_name,
        phone: messages.to_phone,
      },
    };
  }

  /** Return messages to this user.
   *
   * [{id, from_user, body, sent_at, read_at}]
   *
   * where from_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesTo(username) {
    const result = await db.query(
      `SELECT m.id, m.from_username, f.first_name AS from_first_name, f.last_name AS from_last_name, f.phone AS from_phone, m.body, m.sent_at, m.read_at 
    FROM messages AS m
    JOIN users AS f on m.from_username = f.username
    WHERE m.to_username=$1`,
      [username]
    );
    let messages = result.rows;
    if (!messages) {
      throw new ExpressError(`No messages were sent to ${username}`, 404);
    }
    return {
      id: messages.id,
      body: messages.body,
      sent_at: messages.sent_at,
      read_at: messages.read_at,
      from_user: {
        username: messages.from_username,
        first_name: messages.from_first_name,
        last_name: messages.from_last_name,
        phone: messages.from_phone,
      },
    };
  }
}

module.exports = User;
