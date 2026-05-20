import mongoose from "mongoose";

const enrollmentSchema = new mongoose.Schema({
  userId: mongoose.Schema.Types.ObjectId,
  courseId: mongoose.Schema.Types.ObjectId,
  enrolledAt: {
    type: Date,
    default: Date.now,
  },
  expiresAt: Date,
});

const Enrollment = mongoose.model("Enrollment", enrollmentSchema);
export default Enrollment;
