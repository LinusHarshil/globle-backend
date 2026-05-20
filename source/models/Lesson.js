import mongoose from "mongoose";

const lessonSchema = new mongoose.Schema({
  courseId: mongoose.Schema.Types.ObjectId,
  title: String,
  videoUrl: String,
  description: String,
  isPreview: Boolean,
  order: Number,
});

const Lesson = mongoose.model("Lesson", lessonSchema);
export default Lesson;
