import express from "express";
import path from "path";
import mongoose from "mongoose";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";

mongoose
  .connect("mongodb://localhost:27017", {
    dbName: "backend",
  })
  .then(() => console.log("Database connected"))
  .catch((e) => console.log(e));

const userSchema = new mongoose.Schema({
  name: "String",
  email: "String",
  password: "String",
});

const User = mongoose.model("User", userSchema);

const server = express();

//using middleware
server.use(express.static(path.join(path.resolve(), "public")));
server.use(express.urlencoded({ extended: true }));
server.use(cookieParser());

server.set("view engine", "ejs");

const isAuthenticated = (req, res, next) => {
  const { token } = req.cookies;
  if (token) {
    const decode = jwt.verify(token, "abcdmno");
    req.user = User.findById(decode._id);

    next();
  } else {
    res.redirect("/login");
  }
};

server.get("/", isAuthenticated, (req, res) => {
  res.render("logout", { name: req.user.name });
});

server.get("/login", (req, res) => {
  res.render("login");
});

server.get("/register", (req, res) => {
  res.render("register");
});

server.post("/login", async (req, res) => {
  const { email, password } = req.body;
  let user = await User.findOne({ email });

  if (!user) return res.redirect("/register");

  const isMatch = await bcrypt.compare(password, user.password);

  if (!isMatch)
    return res.render("login", { email, message: "Incorrect Password" });
  const token = jwt.sign({ _id: user._id }, "abcdmno");

  res.cookie("token", token, {
    httponly: true,
    expires: new Date(Date.now() + 60 * 1000),
  });
  res.redirect("/");
});

server.post("/register", async (req, res) => {
  const { name, email, password } = req.body;

  let user = await User.findOne({ email });
  if (user) {
    return res.redirect("/login");
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  user = await User.create({
    name,
    email,
    password: hashedPassword,
  });

  const token = jwt.sign({ _id: user._id }, "abcdmno");

  res.cookie("token", token, {
    httponly: true,
    expires: new Date(Date.now() + 60 * 1000),
  });
  res.redirect("/");
});

server.post("/logout", (req, res) => {
  res.cookie("token", null, {
    expires: new Date(Date.now()),
  });
  res.redirect("/");
});

server.listen(5000, () => {
  console.log("Server is started");
});
