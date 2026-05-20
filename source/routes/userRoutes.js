import bcrypt from "bcryptjs";
import crypto from "crypto";
import dotenv from "dotenv";
import express from "express";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import authMiddleware from "../middleware/authMiddleware.js";
import roleMiddleware from "../middleware/roleMiddleware.js";
import Course from "../models/Courses.js";
import Enrollment from "../models/Enrollment.js";
import Lesson from "../models/Lesson.js";
import User from "../models/User.js";
dotenv.config();
const router = express.Router();

const email_user = process.env.EMAIL_USER;
const email_pass = process.env.EMAIL_PASS;
//nodemailer setup
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

router.post("/register", async (req, res) => {
  try {
    const existingUser = await User.findOne({ email: req.body.email });
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const name = req.body.name;
    if (existingUser && existingUser.isVerified) {
      return res.status(400).send("this user already exists");
    }
    const token = crypto.randomBytes(32).toString("hex");
    if (existingUser && !existingUser.isVerified) {
      const verifyLink = `http://localhost:5000/api/users/verify-email/${token}`;
      const user = await User.findByIdAndUpdate(existingUser._id, {
        name: name,
        password: hashedPassword,
        isVerified: false,
        verificationToken: token,
      });
      await transporter.sendMail({
        from: email_user,
        to: req.body.email,
        subject: "Verify your Account",
        html: `
      <h1>Welcome to Globle Academy</h1>
      <p>Hello ${name}, Below is the link for the verification of your email for the registration</p>
      <a href="${verifyLink}">
      Verify Email
      </a>`,
      });
      return res.send("Verification Email Sent");
    } else {
      const user = await User.create({
        name: name,
        email: req.body.email,
        password: hashedPassword,
        isVerified: false,
        verificationToken: token,
      });
      const verifyLink = `http://localhost:5000/api/users/verify-email/${token}`;

      await transporter.sendMail({
        from: email_user,
        to: req.body.email,
        subject: "verify your globle student account",
        html: `
      <h1>Welcome to Globle Academy</h1>
      <p>Hello ${name},Below is the link for the verification of your email for the registration</p>
      <a href="${verifyLink}">
      Verify Email
      </a>
      
      `,
      });
      return res.send({
        message: "registered succesfully, check email",
      });
    }
  } catch (error) {
    return res.status(500).send(error.message);
  }
});
router.get("/verify-email/:token", async (req, res) => {
  const token = req.params.token;
  const checkToken = await User.findOne({ verificationToken: token });
  if (!checkToken) {
    res.send("token wrong");
  }
  const userId = checkToken._id;
  const updatedUser = await User.findByIdAndUpdate(
    userId,
    {
      isVerified: true,
      verificationToken: null,
    },
    { new: true }
  );
  res.send("email verified succesfully");
});

router.post("/login", async (req, res) => {
  try {
    const user = await User.findOne({ email: req.body.email });

    if (!user) {
      res.json({ message: "Invalid email or password", success: false });
      return;
    }
    if (user.isSuspended) {
      return res.json({ message: "account suspended", success: false });
    }
    const isMatch = await bcrypt.compare(req.body.password, user.password);
    if (!isMatch) {
      res.json({ message: "Invalid email or password", success: false });
      return;
    } else {
      const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, {
        expiresIn: "7d",
      });
      res.cookie("token", token, {
        httpOnly: true,
        secure: false,
        sameSite: "lax",
      });

      return res.status(200).json({
        success: true,
        token,
      });
    }
  } catch {
    return res.send("Login Failed");
  }
});
router.post("/forgot-password", async (req, res) => {
  const user = await User.findOne({ email: req.body.email });

  if (!user) {
    return res.status(403).send("email invalid");
  }
  const name = user.name;
  const email = user.email;
  //token generation
  const token = crypto.randomBytes(32).toString("hex");

  const fpLink = `http://localhost:3000/reset-password/${token}`;
  const updatedUser = await User.findByIdAndUpdate(
    user._id,
    {
      verificationToken: token,
    },
    { new: true }
  );
  //email sending procedure
  await transporter.sendMail({
    from: email_user,
    to: req.body.email,
    subject: "verify your globle lms account",
    html: `
      <h1>Welcome to Globle Academy</h1>
      <br/>
      <p>This is designed for the purpose of expository profeciency</p>
      <br/>
      <p>Hello ${name},Below is the link for the verification link for you to change your password for the email account: ${email} <br/> <br/>
      Below is the link
      </p>
      <a href="${fpLink}">
        Forgot Password
      </a>
      
      `,
  });
  return res.status(201).send({
    message: "continue the next step from your email",
  });
});
router.post("/reset-password/:token", async (req, res) => {
  try {
    const token = req.params.token;
    const newPassword = req.body.password;

    const user = await User.findOne({
      verificationToken: token,
    });

    if (!user) {
      return res.status(403).send("token invalid");
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    await User.findByIdAndUpdate(user._id, {
      password: hashedPassword,
      verificationToken: null,
    });

    return res.status(200).send("Password updated");
  } catch (error) {
    return res.status(500).send("process failed");
  }
});

//me
router.get("/me", authMiddleware, async (req, res) => {
  const user = await User.findById(req.user.id);
  res.send({
    name: user.name,
    email: user.email,
    role: user.role,
  });
});

router.get("/admin", authMiddleware, roleMiddleware("admin"), (req, res) => {
  res.send("welcome admin");
});
router.get("/all-users", authMiddleware, roleMiddleware("admin"), async (req, res) => {
  const users = await User.find();
  res.send(users);
});

router.patch("/:id/role", authMiddleware, roleMiddleware("admin"), async (req, res) => {
  const userId = req.params.id;
  const newRole = req.body.role;
  const updatedUser = await User.findByIdAndUpdate(
    userId,
    { role: newRole },
    { new: true }
  );
  res.send(updatedUser);
});

router.patch(
  "/:id/suspension",
  authMiddleware,
  roleMiddleware("admin"),
  async (req, res) => {
    const userId = req.params.id;
    const suspension = req.body.isSuspended;

    const updatedUser = await User.findByIdAndUpdate(
      userId,
      { isSuspended: suspension },
      { new: true }
    );
    res.send(updatedUser);
  }
);

router.post("/courses", authMiddleware, roleMiddleware("admin"), async (req, res) => {
  const course = await Course.findOne({ title: req.body.title });
  if (course) {
    return res.send("course exists already");
  } else {
    const newCourse = await Course.create({
      title: req.body.title,
      price: req.body.price,
      description: req.body.description,
      thumbnail: req.body.thumbnail,
      enrolled: 0,
    });
    res.send(newCourse);
  }
});

router.patch(
  "/courses/:id",
  authMiddleware,
  roleMiddleware("admin"),
  async (req, res) => {
    const courseId = req.params.id;
    const newValues = req.body;
    const updatedCourse = await Course.findByIdAndUpdate(courseId, newValues, {
      new: true,
    });
    res.send(updatedCourse);
  }
);
router.get("/courses", authMiddleware, async (req, res) => {
  const courses = await Course.find();
  res.send(courses);
});
router.get("/courses/:id", authMiddleware, async (req, res) => {
  const courseId = req.params.id;
  const course = await Course.findById(courseId);
  res.status(200).json({ course: course, success: true });
});
router.delete(
  "/courses/:id",
  authMiddleware,
  roleMiddleware("admin"),
  async (req, res) => {
    const courseId = req.params.id;
    const deletedCourse = await Course.findByIdAndDelete(courseId);
    res.status(200).send(deletedCourse);
  }
);
router.post("/:id/enroll", authMiddleware, async (req, res) => {
  const courseId = req.params.id;
  const course = await Course.findById(courseId);
  if (!course) {
    return res.send("course not found");
  }
  if (!course.isFree) {
    return res.send("This is a premium course");
  } else {
    const userId = req.user.id;
    const enrollment = await Enrollment.findOne({ userId, courseId });

    if (enrollment) {
      return res.send("the course already exists");
    } else {
      const days = req.body.days;
      const enrolledAt = new Date();
      const expiresAt = new Date();
      expiresAt.setDate(expiresAt.getDate() + Number(days));

      const newEnrollment = await Enrollment.create({
        userId: userId,
        courseId: courseId,
        enrolledAt: enrolledAt,
        expiresAt: expiresAt,
      });
      res.send(newEnrollment);
    }
  }
});

router.get("/my-courses", authMiddleware, async (req, res) => {
  const userId = req.user.id;
  const enrollment = await Enrollment.find({ userId });
  if (!enrollment.length) {
    return res.send("you haven't enrolled in any course");
  }
  const courseIds = enrollment.map((item) => item.courseId);
  const courses = await Course.find({
    _id: { $in: courseIds },
  });
  const results = courses.map((course) => {
    const match = enrollment.find((item) => {
      return item.courseId.toString() === course._id.toString();
    });
    return {
      ...course._doc,
      enrolledAt: match.enrolledAt,
      expiresAt: match.expiresAt,
    };
  });
  res.send(results);
});

router.get("/courses/:id/access", authMiddleware, async (req, res) => {
  const courseId = req.params.id;
  const userId = req.user.id;
  const enrollment = await Enrollment.findOne({ courseId, userId });
  if (!enrollment) {
    return res.send("invalid request");
  }
  const expiresAt = enrollment.expiresAt;
  const currentdate = new Date();
  const difference = expiresAt - currentdate;
  if (difference <= 0) {
    return res.send("course expired");
  }
  const course = await Course.findById(courseId);
  const lessons = await Lesson.find({ courseId }).sort({ order: 1 });

  res.send({ course, lessons });
});

router.post(
  "/courses/:id/lessons",
  authMiddleware,
  roleMiddleware("admin"),
  async (req, res) => {
    const courseId = req.params.id;
    const courseExists = await Course.findById(courseId);

    if (!courseExists) {
      return res.send("this course doesn't exist");
    }
    const lessonTitle = req.body.title;
    const lessonExists = await Lesson.findOne({ courseId, title: lessonTitle });
    if (lessonExists) {
      return res.send("this lesson already exists");
    }
    const newLesson = await Lesson.create({ courseId, ...req.body });
    return res.send(newLesson);
  }
);
router.patch(
  "/lessons/:id",
  authMiddleware,
  roleMiddleware("admin"),
  async (req, res) => {
    const lessonId = req.params.id;
    const newValues = req.body;
    const updatedLesson = await Lesson.findByIdAndUpdate(lessonId, newValues, {
      new: true,
    });
    res.send(updatedLesson);
  }
);

router.get(
  "/courses/:id/lessons",
  authMiddleware,
  roleMiddleware("admin"),
  async (req, res) => {
    const courseId = req.params.id;
    const lessons = await Lesson.find({ courseId }).sort({ order: 1 });
    res.status(200).json({ lesson: lessons, success: true });
  }
);

router.get("/courses/:id/preview-lessons", authMiddleware, async (req, res) => {
  const courseId = req.params.id;
  const lessons = await Lesson.find({ courseId, isPreview: true }).sort({ order: 1 });
  res.status(200).json({ lesson: lessons, success: true });
});
router.get("/lessons/:id", authMiddleware, roleMiddleware("admin"), async (req, res) => {
  const lessonId = req.params.id;
  const lesson = await Lesson.findById(lessonId);
  res.send(lesson);
});
router.delete(
  "/lessons/:id",
  authMiddleware,
  roleMiddleware("admin"),
  async (req, res) => {
    const lessonId = req.params.id;
    const deletedLesson = await Lesson.findByIdAndDelete(lessonId);
    res.send(deletedLesson);
  }
);

router.post(
  "/courses/:id/grant",
  authMiddleware,
  roleMiddleware("admin"),
  async (req, res) => {
    const courseId = req.params.id;
    const course = await Course.findById(courseId);
    if (!course) {
      return res.send("course not found");
    }
    const userId = req.body.userId;
    const enrollment = await Enrollment.findOne({ userId, courseId });

    if (enrollment) {
      return res.send("the course already exists");
    } else {
      const days = req.body.days;
      const enrolledAt = new Date();
      const expiresAt = new Date();
      expiresAt.setDate(expiresAt.getDate() + Number(days));

      const newEnrollment = await Enrollment.create({
        userId: userId,
        courseId: courseId,
        enrolledAt: enrolledAt,
        expiresAt: expiresAt,
      });
      res.send(newEnrollment);
    }
  }
);
router.patch(
  "/courses/:id/grant",
  authMiddleware,
  roleMiddleware("admin"),
  async (req, res) => {
    const courseId = req.params.id;
    const course = await Course.findById(courseId);
    if (!course) {
      return res.send("course not found");
    }
    const userId = req.body.userId;
    const enrollment = await Enrollment.findOne({ userId, courseId });

    if (!enrollment) {
      return res.send("the enrollment doesn't exist");
    } else {
      const mode = req.body.mode;
      const enrollmentId = enrollment._id;
      let expiresAt = enrollment.expiresAt;
      if (mode === "addDays") {
        const days = req.body.days;

        expiresAt.setDate(expiresAt.getDate() + Number(days));
        //
      } else if (mode === "setDate") {
        //
        expiresAt = new Date(req.body.expiresAt);
      }

      const updatedEnrollment = await Enrollment.findByIdAndUpdate(
        enrollmentId,
        { expiresAt: expiresAt },
        { new: true }
      );
      res.send(updatedEnrollment);
    }
  }
);
router.post("/logout", (req, res) => {
  res.clearCookie("token");

  res.json({
    success: true,
    message: "Logged out",
  });
});
export default router;
