// Load the .env file first so process.env.MONGODB_URI / PORT work
import "dotenv/config";

import express from "express";
import cors from "cors";
import { MongoClient, ObjectId } from "mongodb";

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
// validateTuition — the rules every tuition must pass.
// Shared by POST (create) and PATCH (edit) so the two can
// never disagree. Returns an array of error messages;
// an empty array means "all good".
// ============================================================
function validateTuition(body) {
  const { title, subject, classLevel, mode, location, fee, days, description, image } =
    body || {};
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

  return errors;
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

    // --- validate every field (rules shared with PATCH) ---
    const errors = validateTuition(req.body);

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

    const total = await db.collection("tuitions").countDocuments({ postedBy });

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
// GET /api/tuitions/:id — ONE tuition's full details
// (the /tuitions/[id] page loads this; no login needed)
//
// Route order matters: /mine and /stats are registered above,
// so they still match before Express reaches this ":id" route.
// ============================================================
app.get("/api/tuitions/:id", async (req, res) => {
  try {
    const { id } = req.params; // the id from the URL
    // MongoDB ids are exactly 24 hex characters — anything
    // else cannot exist, so answer 404 without a DB lookup
    if (!/^[0-9a-fA-F]{24}$/.test(id)) {
      return res.status(404).json({ message: "Tuition not found" });
    }

    const doc = await db
      .collection("tuitions")
      .findOne({ _id: new ObjectId(id), isActive: true });

    if (!doc) {
      return res.status(404).json({ message: "Tuition not found" });
    }

    // turn MongoDB's _id into a normal "id" field
    const { _id, ...rest } = doc;
    return res.json({ tuition: { id: String(_id), ...rest } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Something went wrong on the server" });
  }
});

// ============================================================
// getOwnedTuition — shared step for the edit / toggle / delete
// routes below. It:
//   1. checks the id format      -> 404 if broken
//   2. loads the tuition         -> 404 if it does not exist
//   3. checks it belongs to the  -> 403 if not yours
//      logged-in tutor
// Returns the document, or null after sending the response.
// ============================================================
async function getOwnedTuition(req, res) {
  const { id } = req.params;

  if (!/^[0-9a-fA-F]{24}$/.test(id)) {
    res.status(404).json({ message: "Tuition not found" });
    return null;
  }

  const doc = await db
    .collection("tuitions")
    .findOne({ _id: new ObjectId(id) });

  if (!doc) {
    res.status(404).json({ message: "Tuition not found" });
    return null;
  }

  if (doc.postedBy !== req.user.id) {
    res.status(403).json({ message: "You can only change your own tuitions" });
    return null;
  }

  return doc;
}

// ============================================================
// PATCH /api/tuitions/:id — edit a tuition's details
// (My Tuitions page -> Edit button)
//
// Only the form fields change. approvalStatus is NEVER touched
// here — only the admin approves / rejects a post.
// ============================================================
app.patch("/api/tuitions/:id", verifyToken, async (req, res) => {
  try {
    if (req.user.role !== "tutor") {
      return res
        .status(403)
        .json({ message: "Only tutors can edit tuitions" });
    }

    const tuition = await getOwnedTuition(req, res);
    if (!tuition) return; // error response already sent

    // same rules as creating a tuition
    const errors = validateTuition(req.body);
    if (errors.length > 0) {
      return res.status(400).json({ message: errors[0], errors });
    }

    const {
      title,
      subject,
      classLevel,
      mode,
      location,
      fee,
      days,
      description,
      image,
    } = req.body;

    // build the object that will be saved
    const updates = {
      title: title.trim(),
      subject: subject.trim(),
      classLevel: classLevel.trim(),
      mode,
      location: location && location.trim() ? location.trim() : "Online",
      fee,
      days,
      description: description.trim(),
      image,
      // NOTE: approvalStatus stays as it is — the admin changes it
    };

    await db
      .collection("tuitions")
      .updateOne({ _id: new ObjectId(req.params.id) }, { $set: updates });

    // answer with the fresh document (as {"id": ...})
    const { _id, ...rest } = { ...tuition, ...updates };
    return res.json({
      message: "Tuition updated",
      tuition: { ...rest, id: String(_id) },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Something went wrong on the server" });
  }
});

// ============================================================
// PATCH /api/tuitions/:id/toggle — Active <-> Closed
// (My Tuitions page -> Close / Reopen button)
//
// The server simply flips the current isActive value.
// ============================================================
app.patch("/api/tuitions/:id/toggle", verifyToken, async (req, res) => {
  try {
    if (req.user.role !== "tutor") {
      return res
        .status(403)
        .json({ message: "Only tutors can change tuition status" });
    }

    const tuition = await getOwnedTuition(req, res);
    if (!tuition) return; // error response already sent

    const newActive = !tuition.isActive; // flip it

    await db
      .collection("tuitions")
      .updateOne(
        { _id: new ObjectId(req.params.id) },
        { $set: { isActive: newActive } },
      );

    const { _id, ...rest } = { ...tuition, isActive: newActive };
    return res.json({
      message: newActive ? "Tuition is now active" : "Tuition closed",
      tuition: { ...rest, id: String(_id) },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Something went wrong on the server" });
  }
});

// ============================================================
// DELETE /api/tuitions/:id — remove a tuition post forever
// (My Tuitions page -> Delete button)
// ============================================================
app.delete("/api/tuitions/:id", verifyToken, async (req, res) => {
  try {
    if (req.user.role !== "tutor") {
      return res
        .status(403)
        .json({ message: "Only tutors can delete tuitions" });
    }

    const tuition = await getOwnedTuition(req, res);
    if (!tuition) return; // error response already sent

    await db
      .collection("tuitions")
      .deleteOne({ _id: new ObjectId(req.params.id) });

    return res.json({ message: "Tuition deleted" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Something went wrong on the server" });
  }
});

// ============================================================
// APPLICATIONS — a student applies for a tuition, the tutor
// accepts or rejects it. This is the4th collection from the
// project requirement: users, tuitions, applications, payments.
// ============================================================

// POST /api/applications — send an application (login required)
//
// Any signed-in user may apply (kept open for the demo — a real
// platform could restrict this later). Name/email/phone come
// from the form; studentId comes from the session so duplicate
// applications can be detected.
app.post("/api/applications", verifyToken, async (req, res) => {
  try {
    const {
      tuitionId,
      studentName,
      studentEmail,
      studentPhone,
      preferredSchedule,
      note,
    } = req.body || {};

    // ---------- 1) validate the form ----------
    const errors = [];
    if (typeof tuitionId !== "string" || !tuitionId.trim()) {
      errors.push("Tuition id is required");
    }
    if (typeof studentName !== "string" || studentName.trim().length < 2) {
      errors.push("Your name is required");
    }
    if (typeof studentEmail !== "string" || !studentEmail.includes("@")) {
      errors.push("A valid email is required");
    }
    if (typeof studentPhone !== "string" || !studentPhone.trim()) {
      errors.push("Your phone number is required");
    }
    if (typeof preferredSchedule !== "string" || !preferredSchedule.trim()) {
      errors.push("Preferred schedule is required");
    }
    if (note !== undefined && note !== null && typeof note !== "string") {
      errors.push("Note must be text");
    }
    if (errors.length > 0) {
      return res.status(400).json({ message: errors[0], errors });
    }

    // ---------- 2) the tuition must exist and be open ----------
    const cleanTuitionId = tuitionId.trim();
    if (!/^[0-9a-fA-F]{24}$/.test(cleanTuitionId)) {
      return res.status(404).json({ message: "Tuition not found" });
    }
    const tuition = await db
      .collection("tuitions")
      .findOne({ _id: new ObjectId(cleanTuitionId), isActive: true });
    if (!tuition) {
      return res.status(404).json({ message: "Tuition not found" });
    }

    // ---------- 3) one application per student per tuition ----------
    const already = await db.collection("applications").findOne({
      tuitionId: cleanTuitionId,
      studentId: req.user.id,
    });
    if (already) {
      return res
        .status(400)
        .json({ message: "You have already applied to this tuition" });
    }

    // ---------- 4) save ----------
    const application = {
      tuitionId: cleanTuitionId,
      tuitionTitle: tuition.title, // snapshot — shown in the tutor's inbox
      tutorId: String(tuition.postedBy), // saved so the tutor's inbox is ONE query
      studentId: req.user.id, // from the session, not the form
      studentName: studentName.trim(),
      studentEmail: studentEmail.trim(),
      studentPhone: studentPhone.trim(),
      preferredSchedule: preferredSchedule.trim(),
      note: typeof note === "string" ? note.trim() : "",
      status: "pending", // pending -> accepted | rejected
      createdAt: new Date(),
    };

    const result = await db.collection("applications").insertOne(application);

    return res.status(201).json({
      message: "Application sent! The tutor will review it",
      application: { ...application, id: String(result.insertedId) },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Something went wrong on the server" });
  }
});

// ============================================================
// GET /api/applications/tutor — EVERY application that arrived
// on this tutor's tuition posts (newest first).
// Each application stores tutorId, so this is a single query.
// ============================================================
app.get("/api/applications/tutor", verifyToken, async (req, res) => {
  try {
    if (req.user.role !== "tutor") {
      return res
        .status(403)
        .json({ message: "Only tutors can view applicants" });
    }

    const applications = await db
      .collection("applications")
      .find({ tutorId: req.user.id })
      .sort({ createdAt: -1 }) // newest first
      .toArray();

    // turn every _id into a normal "id" field
    const list = applications.map(({ _id, ...rest }) => ({
      ...rest,
      id: String(_id),
    }));

    return res.json({ applications: list });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Something went wrong on the server" });
  }
});

// ============================================================
// PATCH /api/applications/:id — the tutor moves ONE application
// to "accepted" or "rejected" (the status update from the
// requirement). Only the tutor who owns the tuition may decide.
// ============================================================
app.patch("/api/applications/:id", verifyToken, async (req, res) => {
  try {
    if (req.user.role !== "tutor") {
      return res
        .status(403)
        .json({ message: "Only tutors can review applicants" });
    }

    const { id } = req.params;
    if (!/^[0-9a-fA-F]{24}$/.test(id)) {
      return res.status(404).json({ message: "Application not found" });
    }

    const application = await db
      .collection("applications")
      .findOne({ _id: new ObjectId(id) });
    if (!application) {
      return res.status(404).json({ message: "Application not found" });
    }

    // ownership: this application belongs to one of MY tuitions
    if (application.tutorId !== req.user.id) {
      return res.status(403).json({
        message: "You can only review applications to your own tuitions",
      });
    }

    const { status } = req.body || {};
    if (status !== "accepted" && status !== "rejected") {
      return res
        .status(400)
        .json({ message: "Status must be accepted or rejected" });
    }

    await db
      .collection("applications")
      .updateOne({ _id: new ObjectId(id) }, { $set: { status } });

    const { _id, ...rest } = application;
    return res.json({
      message:
        status === "accepted"
          ? "Application accepted"
          : "Application rejected",
      application: { ...rest, status, id: String(_id) },
    });
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
