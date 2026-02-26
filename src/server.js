const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const path = require("path");
require("dotenv").config({ path: path.resolve(__dirname, "config.env") });

const authRouter = require("./routes/auth");
const usersRouter = require("./routes/users");
const cookieparser = require("cookie-parser");
const DB = process.env.DATABASE.replace(
  "<PASSWORD>",
  process.env.PASSWORD,
).replace("<USER_NAME>", process.env.USER_NAME);

//const DB = process.env.DATABASE_LOCAL;

mongoose.connect(DB).then(() => {
  console.log("Database connection Successful!");
});

const app = express();
// Allow requests from the frontend dev server at localhost:5173
const corsOptions = {
  origin: function (origin, callback) {
    // allow requests with no origin (like mobile apps, curl, or server-to-server)
    if (!origin) return callback(null, true);
    const allowed = ["http://localhost:5173"];
    if (allowed.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error("Not allowed by CORS"));
    }
  },
  credentials: true,
};

app.use(cors(corsOptions));
app.use(express.json());

app.use(cookieparser());

app.use("/api/auth", authRouter);
app.use("/api/users", usersRouter);

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
