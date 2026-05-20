import bcrypt from "bcryptjs";
import crypto from "crypto";
import dotenv from "dotenv";
import express from "express";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";

import authMiddleware from "../middleware/authMiddleware.js";

import User from "../models/User.js";

dotenv.config();

const router = express.Router();

/* ================= EMAIL ================= */

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

/* ================= REGISTER ================= */

router.post("/register", async (req, res) => {
  try {
    const existingUser = await User.findOne({
      email: req.body.email,
    });

    const hashedPassword = await bcrypt.hash(req.body.password, 10);

    const name = req.body.name;

    if (existingUser && existingUser.isVerified) {
      return res.status(400).json({
        success: false,
        message: "User already exists",
      });
    }

    const token = crypto.randomBytes(32).toString("hex");

    if (existingUser && !existingUser.isVerified) {
      await User.findByIdAndUpdate(existingUser._id, {
        name,
        password: hashedPassword,
        isVerified: false,
        verificationToken: token,
      });

      const verifyLink = `https://globlelms.vercel.app/verify-email/${token}`;

      await transporter.sendMail({
        from: process.env.EMAIL_USER,
        to: req.body.email,
        subject: "Verify your account",
        html: `
          <h1>Welcome to Globle Academy</h1>

          <p>Hello ${name}, verify your account below:</p>

          <a href="${verifyLink}">
            Verify Email
          </a>
        `,
      });

      return res.status(200).json({
        success: true,
        message: "Verification email sent",
      });
    }

    await User.create({
      name,
      email: req.body.email,
      password: hashedPassword,
      isVerified: false,
      verificationToken: token,
    });

    const verifyLink = `https://globlelms.vercel.app/verify-email/${token}`;

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: req.body.email,
      subject: "Verify your account",
      html: `
        <h1>Welcome to Globle Academy</h1>

        <p>Hello ${name}, verify your account below:</p>

        <a href="${verifyLink}">
          Verify Email
        </a>
      `,
    });

    return res.status(201).json({
      success: true,
      message: "Registered successfully, check your email",
    });
  } catch (error) {
    console.log(error);

    return res.status(500).json({
      success: false,
      message: "Registration failed",
    });
  }
});

/* ================= VERIFY EMAIL ================= */

router.get("/verify-email/:token", async (req, res) => {
  try {
    const token = req.params.token;

    const user = await User.findOne({
      verificationToken: token,
    });

    if (!user) {
      return res.status(400).json({
        success: false,
        message: "Invalid token",
      });
    }

    await User.findByIdAndUpdate(user._id, {
      isVerified: true,
      verificationToken: null,
    });

    return res.status(200).json({
      success: true,
      message: "Email verified successfully",
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: "Verification failed",
    });
  }
});

/* ================= LOGIN ================= */

router.post("/login", async (req, res) => {
  try {
    const user = await User.findOne({
      email: req.body.email,
    });

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password",
      });
    }

    if (user.isSuspended) {
      return res.status(403).json({
        success: false,
        message: "Account suspended",
      });
    }

    const isMatch = await bcrypt.compare(req.body.password, user.password);

    if (!isMatch) {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password",
      });
    }

    const token = jwt.sign(
      {
        id: user._id,
        role: user.role,
      },
      process.env.JWT_SECRET,
      {
        expiresIn: "7d",
      }
    );

    res.cookie("token", token, {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      path: "/",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return res.status(200).json({
      success: true,
      token,
    });
  } catch (error) {
    console.log(error);

    return res.status(500).json({
      success: false,
      message: "Login failed",
    });
  }
});

/* ================= FORGOT PASSWORD ================= */

router.post("/forgot-password", async (req, res) => {
  try {
    const user = await User.findOne({
      email: req.body.email,
    });

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "Email invalid",
      });
    }

    const token = crypto.randomBytes(32).toString("hex");

    await User.findByIdAndUpdate(user._id, {
      verificationToken: token,
    });

    const fpLink = `https://globlelms.vercel.app/reset-password/${token}`;

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: req.body.email,
      subject: "Reset Password",
      html: `
          <h1>Reset Password</h1>

          <p>Hello ${user.name}, reset your password below:</p>

          <a href="${fpLink}">
            Reset Password
          </a>
        `,
    });

    return res.status(200).json({
      success: true,
      message: "Continue the next step from your email",
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: "Process failed",
    });
  }
});

/* ================= RESET PASSWORD ================= */

router.post("/reset-password/:token", async (req, res) => {
  try {
    const token = req.params.token;

    const newPassword = req.body.password;

    const user = await User.findOne({
      verificationToken: token,
    });

    if (!user) {
      return res.status(403).json({
        success: false,
        message: "Invalid token",
      });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    await User.findByIdAndUpdate(user._id, {
      password: hashedPassword,
      verificationToken: null,
    });

    return res.status(200).json({
      success: true,
      message: "Password updated",
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: "Process failed",
    });
  }
});

/* ================= ME ================= */

router.get("/me", authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);

    return res.status(200).json({
      name: user.name,
      email: user.email,
      role: user.role,
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: "Failed to fetch user",
    });
  }
});

/* ================= LOGOUT ================= */

router.post("/logout", (req, res) => {
  res.clearCookie("token", {
    httpOnly: true,
    secure: true,
    sameSite: "none",
    path: "/",
  });

  return res.status(200).json({
    success: true,
    message: "Logged out",
  });
});

export default router;
