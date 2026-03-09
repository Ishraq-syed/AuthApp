const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../models/userModel");

const cookieOptions = {
  expires: new Date(
    Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 60 * 60 * 1000,
  ),
  httpOnly: true,
  sameSite: process.env.NODE_ENV === "production" ? "None" : "Lax",
  secure: process.env.NODE_ENV === "production",
};

exports.signup = async (req, res) => {
  try {
    const { firstName, lastName, email, password } = req.body;
    if (!firstName || !lastName || !email || !password) {
      return res.status(400).json({ message: "Missing required fields" });
    }

    const existing = await User.findOne({ email });
    if (existing)
      return res.status(409).json({ message: "User already exists" });

    const hashed = await bcrypt.hash(password, 12);
    const user = await User.create({
      firstName,
      lastName,
      email,
      password: hashed,
    });

    const userObj = user.toObject();
    delete userObj.password;
    const token = jwt.sign(
      { id: user._id, email: user.email },
      process.env.JWT_SECRET || "secret",
      {
        expiresIn: process.env.JWT_EXPIRES_IN,
      },
    );
    res.cookie("jwt", token, cookieOptions);
    res.status(201).json({ message: "User created", user: userObj });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
};

exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ message: "Missing credentials" });

    const user = await User.findOne({ email }).select("+password");
    if (!user) return res.status(401).json({ message: "Invalid credentials" });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ message: "Invalid credentials" });

    const token = jwt.sign(
      { id: user._id, email: user.email },
      process.env.JWT_SECRET || "secret",
      {
        expiresIn: process.env.JWT_EXPIRES_IN,
      },
    );
    res.cookie("jwt", token, cookieOptions);
    res.json({ message: "Login successful", token });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
};

exports.protect = async (req, res, next) => {
  try {
    let token;

    if (
      req.headers.authorization &&
      req.headers.authorization.startsWith("Bearer")
    ) {
      token = req.headers.authorization.split(" ")[1];
    } else if (req.cookies && req.cookies.jwt) {
      token = req.cookies.jwt;
    }

    if (!token) return res.status(401).json({ message: "Not logged in" });

    const decoded = jwt.verify(token, process.env.JWT_SECRET || "secret");
    const userId = decoded.id || decoded._id;
    const currentUser = await User.findById(userId);
    if (!currentUser)
      return res.status(401).json({ message: "User no longer exists" });

    req.user = currentUser;
    next();
  } catch (err) {
    res.status(401).json({ message: "Invalid token" });
  }
};

exports.restrictTo = (...roles) => {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({
        status: "fail",
        message: "Forbidden: insufficient privileges",
      });
    }
    next();
  };
};

// Logout: clear the jwt cookie to end the session
exports.logout = (req, res) => {
  try {
    // Clear the cookie using the same options (except expires which will be set by clearCookie)
    const clearOptions = {
      httpOnly: cookieOptions.httpOnly,
      sameSite: cookieOptions.sameSite,
      secure: cookieOptions.secure,
    };
    res.clearCookie("jwt", clearOptions);
    res.status(200).json({ message: "Logged out" });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
};
