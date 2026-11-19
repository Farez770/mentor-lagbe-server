// Load the .env file first so process.env.MONGODB_URI / PORT work
import "dotenv/config";

import express from "express";
import cors from "cors";
import { MongoClient } from "mongodb";

const app = express();
const port = process.env.PORT || 5000;

app.use(express.json());
app.use(cors());
const client = new MongoClient(process.env.MONGODB_URI);
export async function connectToMongoDB() {
  try {
    await client.connect();
    console.log("You successfully connected to MongoDB!");
    return client;
  } catch (err) {
    console.dir(err);
  }
}

const mongoClient = await connectToMongoDB();
const db = mongoClient.db("mentor-lagbe");

app.get("/", (req, res) => {
  res.send("Hello World!");
});

// ============================================================
// verifyToken — our login check (middleware)
//
// The browser sends every protected request with this header:
//     Authorization:  Bearer <session token>
//
// BetterAuth saves that exact token in MongoDB, inside the
// "session" collection. So here we simply:
//   1. take the token from the header
//   2. find it in the "session" collection
//   3. make sure it is not expired
//   4. load the user behind the session ("users" collection)
//   5. attach that user to the request (req.user)
// ============================================================
async function verifyToken(req, res, next) {
  try {
    // --- 1) read the token from the header ---
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ message: "You are not signed in" });
    }
    const token = authHeader.slice(7); // remove "Bearer "

    // --- 2) find the session in MongoDB ---
    const session = await db.collection("session").findOne({ token });
    if (!session) {
      return res
        .status(401)
        .json({ message: "Session expired. Please sign in again" });
    }

    // --- 3) is the session still valid? ---
    if (new Date(session.expiresAt) < new Date()) {
      return res
        .status(401)
        .json({ message: "Session expired. Please sign in again" });
    }

    // --- 4) load the user behind this session ---
    const user = await db.collection("users").findOne({ _id: session.userId });
    if (!user) {
      return res.status(401).json({ message: "User not found" });
    }

    // --- 5) every route below can now read req.user ---
    req.user = {
      id: String(user._id),
      name: user.name,
      email: user.email,
      image: user.image || "",
      role: user.role || "student", // "student" | "tutor"
      plan: user.plan || "free", // "free" | "pro"
    };

    next();
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Something went wrong on the server" });
  }
}

// ============================================================
// POST /api/tuitions — a tutor posts a new tuition
//
// Project rules:
//   - saved with approvalStatus: "pending" (admin approves later)
//   - Free plan  -> max 2 tuition posts
//   - Pro plan   -> unlimited posts
// ============================================================
app.post("/api/tuitions", verifyToken, async (req, res) => {
  try {
    // Only tutors may post
    if (req.user.role !== "tutor") {
      return res
        .status(403)
        .json({ message: "Only tutors can post a tuition" });
    }

    // --- read the form body ---
    const {
      title,
      subject,
      classLevel,
      mode, // "Online" | "Offline"
      location,
      fee, // monthly fee (number)
      days, // days per week (number)
      description,
      image, // banner URL (uploaded to ImgBB by the browser)
    } = req.body || {};

    // --- validate every field ---
    const errors = [];

    if (typeof title !== "string" || title.trim().length < 5) {
      errors.push("Title must be at least 5 characters");
    }
    if (typeof subject !== "string" || !subject.trim()) {
      errors.push("Subject is required");
    }
    if (typeof classLevel !== "string" || !classLevel.trim()) {
      errors.push("Class level is required");
    }
    if (mode !== "Online" && mode !== "Offline") {
      errors.push("Mode must be Online or Offline");
    }
    // Location is only required for offline tuitions
    if (mode === "Offline" && (!location || !location.trim())) {
      errors.push("Location is required for offline tuitions");
    }
    if (typeof fee !== "number" || Number.isNaN(fee) || fee < 0) {
      errors.push("Monthly fee must be a valid number");
    }
    if (typeof days !== "number" || days < 1 || days > 7) {
      errors.push("Days per week must be between 1 and 7");
    }
    if (typeof description !== "string" || description.trim().length < 20) {
      errors.push("Description must be at least 20 characters");
    }
    if (typeof image !== "string" || !image.startsWith("http")) {
      errors.push("A banner image is required");
    }

    if (errors.length > 0) {
      return res.status(400).json({ message: errors[0], errors });
    }

    // --- FREE PLAN LIMIT: free = 2 tuitions, pro = unlimited ---
    const isPro = String(req.user.plan).toLowerCase() === "pro";

    if (!isPro) {
      const myCount = await db
        .collection("tuitions")
        .countDocuments({ postedBy: req.user.id });

      if (myCount >= 2) {
        return res.status(403).json({
          message:
            "Free plan allows up to 2 tuitions. Upgrade to Pro for unlimited posts",
        });
      }
    }

    // --- save to MongoDB ---
    const newTuition = {
      title: title.trim(),
      subject: subject.trim(),
      classLevel: classLevel.trim(),
      mode, // "Online" | "Offline"
      location: location && location.trim() ? location.trim() : "Online",
      fee,
      days,
      description: description.trim(),
      image,

      // requirement: every new post waits for admin approval
      approvalStatus: "pending",
      isActive: true,

      // tutor info (so cards can show it without a join)
      postedBy: req.user.id,
      tutorName: req.user.name,
      tutorImage: req.user.image,

      createdAt: new Date(),
    };

    const result = await db.collection("tuitions").insertOne(newTuition);

    // 201 = "created" ✅
    return res.status(201).json({
      message: "Tuition posted! It will be visible after admin approval",
      tuition: { ...newTuition, id: String(result.insertedId) },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Something went wrong on the server" });
  }
});

// ============================================================
// GET /api/tuitions/mine — the logged-in tutor's own tuitions
// (the form uses it for the "X of 2 posts used" counter)
// ============================================================
app.get("/api/tuitions/mine", verifyToken, async (req, res) => {
  try {
    if (req.user.role !== "tutor") {
      return res
        .status(403)
        .json({ message: "Only tutors can view their tuitions" });
    }

    const list = await db
      .collection("tuitions")
      .find({ postedBy: req.user.id })
      .sort({ createdAt: -1 }) // newest first
      .toArray();

    // turn MongoDB's _id into a normal "id" field
    const tuitions = list.map((doc) => {
      const { _id, ...rest } = doc;
      return { id: String(_id), ...rest };
    });

    return res.json({ tuitions });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Something went wrong on the server" });
  }
});

// ============================================================
// GET /api/tuitions — PUBLIC list for the Browse Tuitions page
// (no login needed — anyone can browse)
//
// TODO (Phase 5 — admin approval): once the admin can approve
// listings, add approvalStatus: "approved" to the filter so
// students only ever see approved tuitions. Until then every
// ACTIVE post shows, so a tutor can find their own new post.
// ============================================================
app.get("/api/tuitions", async (req, res) => {
  try {
    const list = await db
      .collection("tuitions")
      .find({ isActive: true }) // only live listings
      .sort({ createdAt: -1 }) // newest first
      .toArray();

    // turn MongoDB's _id into a normal "id" field
    const tuitions = list.map((doc) => {
      const { _id, ...rest } = doc;
      return { id: String(_id), ...rest };
    });

    return res.json({ tuitions });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Something went wrong on the server" });
  }
});

// ============================================================
// GET /api/tuitions/stats — the REAL numbers on the tutor's
// Overview dashboard (login required, tutors only)
//
//   total      = every tuition this tutor ever posted
//   approved   = approved + live (admin approves in Phase 5)
//   pending    = waiting for admin approval
//   applicants = students who applied (0 until Phase 3)
// ============================================================
app.get("/api/tuitions/stats", verifyToken, async (req, res) => {
  try {
    // Only tutors have a dashboard with these numbers
    if (req.user.role !== "tutor") {
      return res
        .status(403)
        .json({ message: "Only tutors can see tuition stats" });
    }

    const postedBy = req.user.id; // the logged-in tutor

    const total = await db
      .collection("tuitions")
      .countDocuments({ postedBy });

    const approved = await db.collection("tuitions").countDocuments({
      postedBy,
      approvalStatus: "approved",
      isActive: true,
    });

    const pending = await db.collection("tuitions").countDocuments({
      postedBy,
      approvalStatus: "pending",
    });

    // TODO (Phase 3): count real applications from the
    // "applications" collection once students can apply
    const applicants = 0;

    return res.json({ total, approved, pending, applicants });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Something went wrong on the server" });
  }
});

// ============================================================
// Unknown route -> JSON 404 (not an HTML error page)
// ============================================================
app.use((req, res) => {
  res.status(404).json({ message: "Route not found" });
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
