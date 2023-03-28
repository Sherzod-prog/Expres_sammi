import { Router } from "express";
import User from "../models/User.js";
import bcrypt from "bcrypt";
import { generateJWToken } from "../services/token.js";

const router = Router();

router.get("/login", (req, res) => {
  if (req.cookies.token) {
    res.redirect("/");
    return;
  }

  res.render("login", {
    title: "login | Sherz",
    isLogin: true,
    loginError: req.flash("loginError"),
  });
});
router.get("/register", (req, res) => {
  if (req.cookies.token) {
    res.redirect("/");
    return;
  }

  res.render("register", {
    title: "Register | Sherz ",
    isRegister: true,
    registerError: req.flash("registerError"),
  });
});

router.get("/logout", (req, res) => {
  res.clearCookie("token");
  res.redirect("/");
});

router.post("/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    req.flash("loginError", "All fields is requared");
    res.redirect("/login");
    return;
  }

  const existUser = await User.findOne({ email });
  if (!existUser) {
    req.flash("loginError", "User not found");
    res.redirect("/login");
    return;
  }

  const isPassEqual = await bcrypt.compare(password, existUser.password);
  if (!isPassEqual) {
    req.flash("loginError", "Password wrong");
    res.redirect("/login");
    return;
  }

  const token = generateJWToken(existUser._id);
  res.cookie("token", token, { httpOnly: true, secure: true });
  res.redirect("/");
});

router.post("/register", async (req, res) => {
  const { firstname, lastname, email, password } = req.body;

  if (!firstname || !lastname || !email || !password) {
    req.flash("registerError", "All fields is requared");
    res.redirect("/register");
    return;
  }

  const canditate = await User.findOne({ email });
  if (canditate) {
    req.flash("registerError", "User already exist");
    res.redirect("/register");
    return;
  }

  const hashedPassword = await bcrypt.hash(req.body.password, 10);
  const userData = {
    firstName: req.body.firstname,
    lastName: req.body.lastname,
    email: req.body.email,
    password: hashedPassword,
  };
  const user = await User.create(userData);
  const token = generateJWToken(user._id);
  res.cookie("token", token, { httpOnly: true, secure: true });
  res.redirect("/");
});

export default router;
