// Load the .env file first so process.env.MONGODB_URI / PORT work
import express from "express";
import cors from "cors";
import { MongoClient, ObjectId } from "mongodb";
import "dotenv/config";
import Stripe from "stripe"; // official Stripe SDK (only the payments route uses it)
// ★ REQUIREMENT UPDATE (JWT): `jose` verifies the signed JWT issued by
// Better Auth. We fetch the public keys from Better Auth's JWKS endpoint
// and cache them in memory, so we never need the private signing key here.
import { createRemoteJWKSet, jwtVerify } from "jose";

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

// ★ REQUIREMENT UPDATE (JWT):
// The Better Auth server lives in the NEXT.js client repo, so the Express
// API verifies JWTs through its public JWKS URL. `CLIENT_URL` is kept as a
// fallback so older .env files still work.
const CLIENT_URL = (process.env.CLIENT_URL || "http://localhost:3000").replace(
  /\/$/,
  "",
);

const JWKS = createRemoteJWKSet(new URL(`${CLIENT_URL}/api/auth/jwks`));

// ============================================================
// Stripe client — used ONLY by /api/payments/verify.
// The secret key lives in .env (same test key as the client's
// .env.local). If it is missing the route answers with a clear
// 500 instead of crashing the whole server at boot.
// ============================================================
const stripe = process.env.STRIPE_SECRET_KEY
  ? new Stripe(process.env.STRIPE_SECRET_KEY)
  : null;

app.get("/", (req, res) => {
  res.send("Hello World!");
});

// ============================================================
// ★ REQUIREMENT UPDATE (JWT): verifyToken is now a REAL JWT middleware.
//
// The browser sends every protected request with:
//     Authorization:  Bearer <jwt>
//
// We no longer look up a MongoDB `session` token. Instead:
//   1. take the JWT from the header
//   2. verify its signature + expiry against Better Auth's JWKS
//   3. read the user id from the verified `sub` claim
//   4. load the FRESH user from MongoDB (role/plan can change)
//   5. attach that user to the request (req.user)
//
// Loading the user again after verification is deliberate: a JWT might
// contain an old role, but MongoDB always has the current truth.
// ============================================================
async function verifyToken(req, res, next) {
  try {
    // --- 1) read the JWT from the header ---
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).send({ message: "Unauthorized" });
    }
    const token = authHeader.slice(7); // remove "Bearer "

    // --- 2) verify signature, expiry, issuer and audience ---
    const { payload } = await jwtVerify(token, JWKS, {
      issuer: CLIENT_URL,
      audience: CLIENT_URL,
    });

    // --- 3) the user id lives in the standard `sub` claim ---
    if (!payload.sub) {
      return res.status(401).send({ message: "Unauthorized" });
    }

    // --- 4) load the fresh user from MongoDB ---
    const user = await db
      .collection("users")
      .findOne({ _id: new ObjectId(payload.sub) });
    if (!user) {
      return res.status(401).send({ message: "User not found" });
    }

    // --- 5) every route below can now read req.user ---
    req.user = {
      id: String(user._id),
      name: user.name,
      email: user.email,
      image: user.image || "",
      role: user.role || "student", // "student" | "tutor" | "admin"
      plan: user.plan || "free", // "free" | "pro"
    };
    // The verified JWT claims are also available if a route needs them.
    req.jwtPayload = payload;

    next();
  } catch (err) {
    // Bad/expired/forged JWTs are auth failures, not server crashes.
    console.error("JWT verification failed:", err?.message ?? err);
    return res.status(401).send({ message: "Unauthorized" });
  }
}

// ★ REQUIREMENT UPDATE: custom Express role middlewares. They always run
// after verifyToken, so req.user is guaranteed to exist here.
const verifyStudent = async (req, res, next) => {
  if (!req.user || req.user.role !== "student") {
    res.status(403).send({ message: "Forbidden" });
    return;
  }
  next();
};

const verifyTutor = async (req, res, next) => {
  if (!req.user || req.user.role !== "tutor") {
    res.status(403).send({ message: "Forbidden" });
    return;
  }
  next();
};

const verifyAdmin = async (req, res, next) => {
  if (!req.user || req.user.role !== "admin") {
    res.status(403).send({ message: "Forbidden" });
    return;
  }
  next();
};

// ============================================================
// validateTuition — the rules every tuition must pass.
// Shared by POST (create) and PATCH (edit) so the two can
// never disagree. Returns an array of error messages;
// an empty array means "all good".
// ============================================================
function validateTuition(body) {
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
  } = body || {};
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
app.post("/api/tuitions", verifyToken, verifyTutor, async (req, res) => {
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
app.get("/api/tuitions/mine", verifyToken, verifyTutor, async (req, res) => {
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
// CHALLENGE 1: SERVER-SIDE SEARCH + FILTER
//
// The Browse Tuitions page now sends its filters as URL query
// params, e.g. /api/tuitions?q=physics&subject=Physics&mode=Online
//
// Supported params:
//   q           -> searches title / subject / tutorName / classLevel
//   subject     -> exact subject match (case-insensitive)
//   classLevel  -> exact class match (case-insensitive)
//   mode        -> exact Online/Offline match (case-insensitive)
//
// "all" and empty values mean "do not filter". The public rule is
// unchanged: only approved + active tuitions are ever returned.
// ============================================================

// Escape characters that have a special meaning inside a regex so
// a user typing "C++" or "Math (HSC)" cannot break the query.
function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// Build a safe "exact value, ignoring case" MongoDB condition.
function exactIgnoreCase(value) {
  return { $regex: `^${escapeRegex(value)}$`, $options: "i" };
}

// ============================================================
// GET /api/tuitions — PUBLIC list for the Browse Tuitions page
// (no login needed — anyone can browse)
//
// Project requirement: ONLY posts where
//   approvalStatus === "approved" AND isActive === true
// appear on the public Browse Tuitions page. A pending or
// rejected post, or a closed one, is invisible here — and the
// Featured section on the home page uses this same endpoint,
// so it follows the exact same rule.
// ============================================================
app.get("/api/tuitions", async (req, res) => {
  try {
    // --- 1) Read the filters sent by the client ---
    // `search` is accepted as an alias for `q` so older links still work.
    const q = String(req.query.q ?? req.query.search ?? "").trim();
    const subject = String(req.query.subject ?? "all").trim();
    const classLevel = String(req.query.classLevel ?? "all").trim();
    const mode = String(req.query.mode ?? "all").trim();

    // This filter NEVER changes — admins/tutors cannot accidentally
    // expose pending, rejected or closed posts through search params.
    const publicFilter = { approvalStatus: "approved", isActive: true };

    // --- 2) Start from the public filter, then add optional filters ---
    const filter = { ...publicFilter };

    if (q) {
      const safeQ = escapeRegex(q);
      filter.$or = [
        { title: { $regex: safeQ, $options: "i" } },
        { subject: { $regex: safeQ, $options: "i" } },
        { tutorName: { $regex: safeQ, $options: "i" } },
        { classLevel: { $regex: safeQ, $options: "i" } },
      ];
    }
    if (subject && subject.toLowerCase() !== "all") {
      filter.subject = exactIgnoreCase(subject);
    }
    if (classLevel && classLevel.toLowerCase() !== "all") {
      filter.classLevel = exactIgnoreCase(classLevel);
    }
    if (mode && mode.toLowerCase() !== "all") {
      filter.mode = exactIgnoreCase(mode);
    }

    // --- 3) Run the filtered list + facet/count queries together ---
    // Facets come from the UNFILTERED public list so the dropdowns do
    // not shrink after the user picks one option.
    const [list, totalAvailable, subjects, classLevels, modes] =
      await Promise.all([
        db
          .collection("tuitions")
          .find(filter)
          .sort({ createdAt: -1 }) // newest first (featured takes 6)
          .toArray(),
        db.collection("tuitions").countDocuments(publicFilter),
        db.collection("tuitions").distinct("subject", publicFilter),
        db.collection("tuitions").distinct("classLevel", publicFilter),
        db.collection("tuitions").distinct("mode", publicFilter),
      ]);

    // turn MongoDB's _id into a normal "id" field
    const tuitions = list.map((doc) => {
      const { _id, ...rest } = doc;
      return { id: String(_id), ...rest };
    });

    const asStrings = (values) =>
      values.map(String).sort((a, b) => a.localeCompare(b));

    return res.json({
      tuitions,
      total: tuitions.length, // how many matched THIS search/filter
      totalAvailable, // how many public tuitions exist in total
      facets: {
        subjects: asStrings(subjects),
        classLevels: asStrings(classLevels),
        modes: asStrings(modes),
      },
    });
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
//   applicants = REAL count of applications received
//                (FIXED 2026-11-21: this used to be a
//                hardcoded 0 with a TODO — it now counts the
//                "applications" collection for this tutor)
// ============================================================
app.get("/api/tuitions/stats", verifyToken, verifyTutor, async (req, res) => {
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

    // REAL applicant count: every application that arrived on
    // ANY of this tutor's tuition posts. POST /api/applications
    // stores tutorId on each row (a snapshot of the tuition's
    // owner), so ONE countDocuments query answers this — no
    // join needed.
    const applicants = await db
      .collection("applications")
      .countDocuments({ tutorId: postedBy });

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

    // TODO (pro features): join the tutor's plan (users.plan)
    // here so the details page can show the Pro "verified badge"

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
app.patch("/api/tuitions/:id", verifyToken, verifyTutor, async (req, res) => {
  try {
    if (req.user.role !== "tutor") {
      return res.status(403).json({ message: "Only tutors can edit tuitions" });
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
app.patch(
  "/api/tuitions/:id/toggle",
  verifyToken,
  verifyTutor,
  async (req, res) => {
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
  },
);

// ============================================================
// DELETE /api/tuitions/:id — remove a tuition post forever
// (My Tuitions page -> Delete button)
// ============================================================
app.delete("/api/tuitions/:id", verifyToken, verifyTutor, async (req, res) => {
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
app.post("/api/applications", verifyToken, verifyStudent, async (req, res) => {
  // NOTE: the old "PRIORITY BOOKING" comment that lived here was
  // removed because the requirement changed — the Pro Student
  // benefit is now "unlimited bookmarks" (see /api/bookmarks),
  // not application ordering. Applying rules are unchanged.
  try {
    // ==========================================================
    // ROLE RULE (project requirement): ONLY students may apply.
    // Tutors and admins get a 403 here — the details page also
    // disables the button for them, but the API must never
    // trust what the UI shows.
    // ==========================================================
    if (req.user.role !== "student") {
      return res
        .status(403)
        .json({ message: "Only students can apply for tuitions" });
    }

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
//
// ★ REQUIREMENT UPDATE (2026-11-21): the old Pro Student
//   benefit "priority booking" (Pro students' applications
//   listed FIRST) was REPLACED by the new requirement
//   "Free students can bookmark 5 tuitions, Pro students can
//   bookmark unlimited tuitions". Because the benefit changed,
//   the priority-sort code below is COMMENTED OUT — the list
//   is plain newest-first for everyone now. The bookmark
//   system lives in /api/bookmarks further down. If the old
//   requirement ever comes back, uncomment block (a) and
//   delete block (b).
// ============================================================
app.get(
  "/api/applications/tutor",
  verifyToken,
  verifyTutor,
  async (req, res) => {
    try {
      if (req.user.role !== "tutor") {
        return res
          .status(403)
          .json({ message: "Only tutors can view applicants" });
      }

      // ---------- (b) ACTIVE: plain newest-first list ----------
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

      /* ---------- (a) COMMENTED OUT: priority booking ----------
    // PRIORITY BOOKING (old requirement, disabled): join each
    // student's plan so Pro rows can be returned first.
    const studentIds = [
      ...new Set(applications.map((a) => String(a.studentId))),
    ].filter((id) => /^[0-9a-fA-F]{24}$/.test(id));
    const students =
      studentIds.length > 0
        ? await db
            .collection("users")
            .find(
              { _id: { $in: studentIds.map((id) => new ObjectId(id)) } },
              { projection: { plan: 1 } },
            )
            .toArray()
        : [];
    const planById = new Map(students.map((u) => [String(u._id), u.plan]));

    const withPlan = applications.map(({ _id, ...rest }) => ({
      ...rest,
      id: String(_id),
      studentPlan:
        String(planById.get(String(rest.studentId)) || "free").toLowerCase() ===
        "pro"
          ? "pro"
          : "free",
    }));

    // stable partition: Pro rows first, free rows after
    const priority = withPlan.filter((a) => a.studentPlan === "pro");
    const regular = withPlan.filter((a) => a.studentPlan !== "pro");
    return res.json({ applications: [...priority, ...regular] });
    -------------------------------------------------------- */
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: "Something went wrong on the server" });
    }
  },
);

// ============================================================
// GET /api/applications/stats — MY application numbers for
// the student dashboard's Overview cards:
//   Total Applied Tuitions / Accepted / Pending + my plan
// (student role only — mirrors GET /api/tuitions/stats)
// ============================================================
app.get(
  "/api/applications/stats",
  verifyToken,
  verifyStudent,
  async (req, res) => {
    try {
      if (req.user.role !== "student") {
        return res
          .status(403)
          .json({ message: "Only students can view application stats" });
      }

      const studentId = req.user.id; // ★ JWT: comes from the verified token

      // Three simple counting queries (clearer than an aggregation
      // pipeline for beginners — this collection stays small)
      const totalApplied = await db
        .collection("applications")
        .countDocuments({ studentId });
      const accepted = await db
        .collection("applications")
        .countDocuments({ studentId, status: "accepted" });
      const pending = await db
        .collection("applications")
        .countDocuments({ studentId, status: "pending" });

      return res.json({
        stats: {
          totalApplied,
          accepted,
          pending,
          plan: req.user.plan || "free", // "free" | "pro"
        },
      });
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: "Something went wrong on the server" });
    }
  },
);

// ============================================================
// GET /api/applications/mine — EVERY application I have sent
// (student role, newest first) for the "My Applications" page.
//
// Each row also needs the tutor's name + email and the monthly
// fee, but applications only store a tuitionId — so after the
// first query we JOIN the extra data in two more simple queries
// (tuitions, then users). This also survives a deleted tuition.
// ============================================================
app.get(
  "/api/applications/mine",
  verifyToken,
  verifyStudent,
  async (req, res) => {
    try {
      if (req.user.role !== "student") {
        return res
          .status(403)
          .json({ message: "Only students can view their applications" });
      }

      // ---------- 1) my applications, newest first ----------
      const applications = await db
        .collection("applications")
        .find({ studentId: req.user.id })
        .sort({ createdAt: -1 })
        .toArray();

      if (applications.length === 0) {
        return res.json({ applications: [] }); // nothing to join
      }

      // ---------- 2) the tuitions I applied to (ONE query) ----------
      // tuitionId was validated as a 24-hex string when saved
      const tuitionIds = applications.map((a) => a.tuitionId);
      const tuitions = await db
        .collection("tuitions")
        .find({ _id: { $in: tuitionIds.map((id) => new ObjectId(id)) } })
        .toArray();
      const tuitionById = new Map(tuitions.map((t) => [String(t._id), t]));

      // ---------- 3) the tutors' emails (ONE query) ----------
      // tuitions only store postedBy (the user id), not the email
      const tutorIds = [
        ...new Set(tuitions.map((t) => String(t.postedBy))),
      ].filter((id) => /^[0-9a-fA-F]{24}$/.test(id)); // safety first
      const tutors =
        tutorIds.length > 0
          ? await db
              .collection("users")
              .find({ _id: { $in: tutorIds.map((id) => new ObjectId(id)) } })
              .toArray()
          : [];
      const tutorById = new Map(tutors.map((u) => [String(u._id), u]));

      // ---------- 4) merge everything into one flat row ----------
      const list = applications.map((a) => {
        const tuition = tuitionById.get(a.tuitionId); // may be undefined
        const tutor = tuition
          ? tutorById.get(String(tuition.postedBy))
          : undefined;

        return {
          id: String(a._id),
          tuitionId: a.tuitionId,
          // live title/fee when the post still exists, otherwise
          // the snapshot saved on the application / a placeholder
          tuitionTitle: tuition?.title ?? a.tuitionTitle,
          tutorName: tuition?.tutorName ?? "(unknown tutor)",
          tutorEmail: tutor?.email ?? "(unknown email)",
          fee: typeof tuition?.fee === "number" ? tuition.fee : null,
          appliedAt: a.createdAt,
          status: a.status, // pending | accepted | rejected
        };
      });

      return res.json({ applications: list });
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: "Something went wrong on the server" });
    }
  },
);

// ============================================================
// PATCH /api/applications/:id — the tutor moves ONE application
// to "accepted" or "rejected" (the status update from the
// requirement). Only the tutor who owns the tuition may decide.
// ============================================================
app.patch(
  "/api/applications/:id",
  verifyToken,
  verifyTutor,
  async (req, res) => {
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
  },
);

// ============================================================
// DELETE /api/applications/:id — the student CANCELS one of
// their OWN applications, but only while it is still pending
// (once the tutor decided, the row stays as a record).
// ============================================================
app.delete(
  "/api/applications/:id",
  verifyToken,
  verifyStudent,
  async (req, res) => {
    try {
      if (req.user.role !== "student") {
        return res
          .status(403)
          .json({ message: "Only students can cancel applications" });
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

      // ownership: only the student who SENT it may cancel it
      if (application.studentId !== req.user.id) {
        return res.status(403).json({
          message: "You can only cancel your own applications",
        });
      }

      // state rule: accepted / rejected rows can no longer be touched
      if (application.status !== "pending") {
        return res.status(409).json({
          message: `Only pending applications can be cancelled — this one is already ${application.status}`,
        });
      }

      await db.collection("applications").deleteOne({ _id: new ObjectId(id) });

      return res.json({ message: "Application cancelled" });
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: "Something went wrong on the server" });
    }
  },
);

// ============================================================
// BOOKMARKS — NEW requirement (2026-11-21):
//   "Free Students can bookmark 5 tuitions;
//    Pro Students can bookmark unlimited tuitions."
//
// A bookmark is one row in the "bookmarks" collection:
//   { userId, tuitionId, createdAt }
// Only STUDENTS may bookmark (same role rule as applying).
// The limit is enforced HERE on the server — the UI shows a
// friendly toast with this same message, but never trusts
// itself for the count.
// ============================================================

// The free-plan bookmark cap (Pro = no cap at all)
const FREE_BOOKMARK_LIMIT = 5;

// GET /api/bookmarks — MY bookmarked tuitions (student only),
// newest first, each joined with its tuition so the "My
// Bookmarks" page can render cards in ONE request.
// Also returns count + limit so the page can show
// "3 of 5 bookmarks used" (free) or "Unlimited" (pro).
app.get("/api/bookmarks", verifyToken, verifyStudent, async (req, res) => {
  try {
    if (req.user.role !== "student") {
      return res
        .status(403)
        .json({ message: "Only students can view bookmarks" });
    }

    const bookmarks = await db
      .collection("bookmarks")
      .find({ userId: req.user.id })
      .sort({ createdAt: -1 }) // newest first
      .toArray();

    // Join the tuition data (ONE query, same trick as
    // /api/applications/mine). A deleted tuition simply shows
    // as null and the UI hides that row's details.
    const tuitionIds = bookmarks
      .map((b) => b.tuitionId)
      .filter((id) => /^[0-9a-fA-F]{24}$/.test(id));
    const tuitions =
      tuitionIds.length > 0
        ? await db
            .collection("tuitions")
            .find({ _id: { $in: tuitionIds.map((id) => new ObjectId(id)) } })
            .toArray()
        : [];
    const tuitionById = new Map(tuitions.map((t) => [String(t._id), t]));

    const list = bookmarks.map((b) => {
      const t = tuitionById.get(b.tuitionId);
      return {
        id: String(b._id),
        tuitionId: b.tuitionId,
        bookmarkedAt: b.createdAt,
        // the tuition itself (null when it was deleted later)
        tuition: t
          ? {
              id: String(t._id),
              title: t.title,
              subject: t.subject,
              classLevel: t.classLevel,
              mode: t.mode,
              fee: t.fee,
              image: t.image,
              tutorName: t.tutorName,
              approvalStatus: t.approvalStatus,
              isActive: t.isActive,
            }
          : null,
      };
    });

    const isPro = String(req.user.plan || "free").toLowerCase() === "pro";

    return res.json({
      bookmarks: list,
      count: list.length,
      // null = unlimited (Pro); 5 = the free-plan cap
      limit: isPro ? null : FREE_BOOKMARK_LIMIT,
      plan: isPro ? "pro" : "free",
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Something went wrong on the server" });
  }
});

// GET /api/bookmarks/check/:tuitionId — is THIS tuition
// bookmarked by me? (the View Details page uses it to pick
// between "Bookmark" and "Bookmarked ✓")
app.get(
  "/api/bookmarks/check/:tuitionId",
  verifyToken,
  verifyStudent,
  async (req, res) => {
    try {
      if (req.user.role !== "student") {
        return res.status(403).json({ message: "Only students can bookmark" });
      }

      const existing = await db.collection("bookmarks").findOne({
        userId: req.user.id,
        tuitionId: req.params.tuitionId,
      });

      return res.json({ bookmarked: !!existing });
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: "Something went wrong on the server" });
    }
  },
);

// POST /api/bookmarks — SAVE a tuition (student only).
// Rules enforced in order:
//   1. only students (403)
//   2. valid + existing tuition id (404)
//   3. not already bookmarked (400)
//   4. FREE plan stops at 5 bookmarks (403) — Pro is unlimited
app.post("/api/bookmarks", verifyToken, verifyStudent, async (req, res) => {
  try {
    // ---------- 1) role rule: students only ----------
    if (req.user.role !== "student") {
      return res
        .status(403)
        .json({ message: "Only students can bookmark tuitions" });
    }

    const { tuitionId } = req.body || {};
    if (typeof tuitionId !== "string" || !/^[0-9a-fA-F]{24}$/.test(tuitionId)) {
      return res.status(404).json({ message: "Tuition not found" });
    }

    // ---------- 2) the tuition must exist ----------
    const tuition = await db
      .collection("tuitions")
      .findOne({ _id: new ObjectId(tuitionId) });
    if (!tuition) {
      return res.status(404).json({ message: "Tuition not found" });
    }

    // ---------- 3) no duplicates ----------
    const already = await db.collection("bookmarks").findOne({
      userId: req.user.id,
      tuitionId,
    });
    if (already) {
      return res
        .status(400)
        .json({ message: "You already bookmarked this tuition" });
    }

    // ---------- 4) the PLAN LIMIT (the new requirement) ----------
    const isPro = String(req.user.plan || "free").toLowerCase() === "pro";
    if (!isPro) {
      const count = await db
        .collection("bookmarks")
        .countDocuments({ userId: req.user.id });
      if (count >= FREE_BOOKMARK_LIMIT) {
        return res.status(403).json({
          message: `Free plan allows up to ${FREE_BOOKMARK_LIMIT} bookmarks. Upgrade to Pro for unlimited bookmarks`,
        });
      }
    }

    // ---------- 5) save ----------
    const bookmark = {
      userId: req.user.id, // from the session, not the body
      tuitionId,
      createdAt: new Date(),
    };
    const result = await db.collection("bookmarks").insertOne(bookmark);

    return res.status(201).json({
      message: "Tuition bookmarked!",
      bookmark: { ...bookmark, id: String(result.insertedId) },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Something went wrong on the server" });
  }
});

// DELETE /api/bookmarks/:tuitionId — REMOVE a bookmark
// (the student's own row; other people's rows are untouched
// because the filter always includes MY userId).
app.delete(
  "/api/bookmarks/:tuitionId",
  verifyToken,
  verifyStudent,
  async (req, res) => {
    try {
      if (req.user.role !== "student") {
        return res
          .status(403)
          .json({ message: "Only students can manage bookmarks" });
      }

      const result = await db.collection("bookmarks").deleteOne({
        userId: req.user.id,
        tuitionId: req.params.tuitionId,
      });

      if (result.deletedCount === 0) {
        return res.status(404).json({ message: "Bookmark not found" });
      }

      return res.json({ message: "Bookmark removed" });
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: "Something went wrong on the server" });
    }
  },
);

// ============================================================
// PATCH /api/profile — update MY OWN profile.
//
// EVERY logged-in user may call this (student, tutor, admin):
// there is deliberately NO role check here. Only these 4
// fields are read from the body — anything else (role, plan,
// email ...) is ignored, so nobody can upgrade their plan or
// change their role through this endpoint.
// ============================================================
app.patch("/api/profile", verifyToken, async (req, res) => {
  try {
    const { name, phone, bio, image } = req.body || {};

    // ---------- validate ----------
    const errors = [];

    // name is the only required field
    if (typeof name !== "string" || name.trim().length < 2) {
      errors.push("Name must be at least 2 characters");
    }

    // phone / bio / image are optional — but must be TEXT
    if (phone !== undefined && phone !== null && typeof phone !== "string") {
      errors.push("Phone must be text");
    }
    if (bio !== undefined && bio !== null && typeof bio !== "string") {
      errors.push("Bio must be text");
    }
    if (typeof bio === "string" && bio.length > 500) {
      errors.push("Bio must be 500 characters or fewer");
    }
    if (image !== undefined && image !== null && typeof image !== "string") {
      errors.push("Image must be a URL");
    }
    // "" simply means "no photo"; anything else must be http(s)
    if (
      typeof image === "string" &&
      image !== "" &&
      !image.startsWith("http")
    ) {
      errors.push("Image must be a URL starting with http");
    }

    if (errors.length > 0) {
      return res.status(400).json({ message: errors[0], errors });
    }

    // ---------- build the update (ONLY these 4 keys!) ----------
    const updates = {
      name: name.trim(),
      phone: typeof phone === "string" ? phone.trim() : "",
      bio: typeof bio === "string" ? bio.trim() : "",
      image: typeof image === "string" ? image.trim() : "",
    };

    // saved straight into the BetterAuth "users" collection —
    // the navbar + drawer read these values on the next
    // session fetch, so they update everywhere at once
    await db
      .collection("users")
      .updateOne({ _id: new ObjectId(req.user.id) }, { $set: updates });

    return res.json({
      message: "Profile updated",
      profile: {
        ...updates,
        email: req.user.email, // read-only info for the form
        role: req.user.role,
        plan: req.user.plan,
      },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Something went wrong on the server" });
  }
});

// ============================================================
// GET /api/admin/stats — platform numbers for the admin
// Overview page (admin role only):
//   Total Users / Total Tutors / Pending vs. Approved Tuitions
//   / Total Stripe Revenue
// ============================================================
app.get("/api/admin/stats", verifyToken, verifyAdmin, async (req, res) => {
  try {
    if (req.user.role !== "admin") {
      return res
        .status(403)
        .json({ message: "Only admins can view platform stats" });
    }

    // 1) how many accounts exist in total
    const totalUsers = await db.collection("users").countDocuments();

    // 2) how many of them teach (role === "tutor")
    const totalTutors = await db
      .collection("users")
      .countDocuments({ role: "tutor" });

    // 3) tuitions waiting for approval vs already approved
    const pendingTuitions = await db
      .collection("tuitions")
      .countDocuments({ approvalStatus: "pending" });
    const approvedTuitions = await db
      .collection("tuitions")
      .countDocuments({ approvalStatus: "approved" });

    // 4) money collected through Stripe — every verified checkout
    //    is stored in "payments" by POST /api/payments/verify and
    //    its "amount" (whole dollars: 15 / 10) is summed here.
    const payments = await db.collection("payments").find({}).toArray();
    const totalRevenue = payments.reduce(
      (sum, p) => sum + (typeof p.amount === "number" ? p.amount : 0),
      0,
    );

    return res.json({
      stats: {
        totalUsers,
        totalTutors,
        pendingTuitions,
        approvedTuitions,
        totalRevenue,
      },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Something went wrong on the server" });
  }
});

// ============================================================
// GET /api/admin/users — EVERY registered user for the
// User Management page (/dashboard/admin/users).
// Admin role only. Only safe fields are returned (no account
// secrets — passwords live in the separate "account" collection
// and are never queried here).
// ============================================================
app.get("/api/admin/users", verifyToken, verifyAdmin, async (req, res) => {
  try {
    // ---------- 1) only admins may see the full user list ----------
    if (req.user.role !== "admin") {
      return res
        .status(403)
        .json({ message: "Only admins can view all users" });
    }

    // ---------- 2) load every user, newest first ----------
    // The projection picks ONLY the columns the page shows —
    // anything not listed here never leaves the server.
    const users = await db
      .collection("users")
      .find(
        {}, // no filter -> all users
        {
          projection: {
            _id: 1, // becomes "id" below
            name: 1,
            email: 1,
            image: 1, // "" when the user has no photo
            role: 1, // "student" | "tutor" | "admin"
            plan: 1, // "free" | "pro"
            createdAt: 1, // join date
          },
        },
      )
      .sort({ createdAt: -1 }) // newest accounts first
      .toArray();

    // ---------- 3) turn Mongo's _id into a normal "id" field ----------
    const list = users.map(({ _id, ...rest }) => ({
      ...rest,
      id: String(_id), // string id the frontend can use
      name: rest.name || "", // defaults for older/odd documents
      email: rest.email || "",
      image: rest.image || "",
      role: rest.role || "student", // same default as BetterAuth
      plan: rest.plan || "free",
      createdAt: rest.createdAt || null,
    }));

    return res.json({ users: list });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Something went wrong on the server" });
  }
});

// ============================================================
// PATCH /api/admin/users/:id — change ONE user's role
// (student | tutor | admin). Admin role only.
// ============================================================
app.patch(
  "/api/admin/users/:id",
  verifyToken,
  verifyAdmin,
  async (req, res) => {
    try {
      // ---------- 1) only admins may change roles ----------
      if (req.user.role !== "admin") {
        return res
          .status(403)
          .json({ message: "Only admins can change roles" });
      }

      // ---------- 2) validate the id format ----------
      const { id } = req.params;
      if (!/^[0-9a-fA-F]{24}$/.test(id)) {
        return res.status(404).json({ message: "User not found" });
      }

      // ---------- 3) validate the new role ----------
      const { role } = req.body || {};
      if (role !== "student" && role !== "tutor" && role !== "admin") {
        return res
          .status(400)
          .json({ message: "Role must be student, tutor or admin" });
      }

      // ---------- 4) nobody may demote THEMSELVES ----------
      // Without this an admin could remove their own "admin"
      // role by accident and then nobody could manage users.
      if (id === req.user.id) {
        return res
          .status(400)
          .json({ message: "You cannot change your own role" });
      }

      // ---------- 5) the target user must exist ----------
      const user = await db
        .collection("users")
        .findOne({ _id: new ObjectId(id) });
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }

      // ---------- 6) write the new role ----------
      // verifyToken reads the role from the DB on every request,
      // so the change takes effect immediately — no re-login.
      await db
        .collection("users")
        .updateOne({ _id: new ObjectId(id) }, { $set: { role } });

      // ---------- 7) answer with the updated row ----------
      return res.json({
        message: `${user.name || user.email} is now ${role}`,
        user: {
          id: String(user._id),
          name: user.name || "",
          email: user.email || "",
          image: user.image || "",
          role, // the NEW role
          plan: user.plan || "free",
          createdAt: user.createdAt || null,
        },
      });
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: "Something went wrong on the server" });
    }
  },
);

// ============================================================
// GET /api/admin/tuitions — EVERY tuition post ever submitted
// by a tutor, for the approval page (/dashboard/admin/tuitions).
// Admin role only. Posts already store tutorName/tutorImage
// (denormalized when posted), so we only join the tutor's
// EMAIL from the users collection.
// ============================================================
app.get("/api/admin/tuitions", verifyToken, verifyAdmin, async (req, res) => {
  try {
    // ---------- 1) only admins may review posts ----------
    if (req.user.role !== "admin") {
      return res
        .status(403)
        .json({ message: "Only admins can review tuitions" });
    }

    // ---------- 2) load every post, newest first ----------
    // No filter on purpose: admins must see pending, approved
    // AND rejected posts (plus paused ones) in one place.
    const list = await db
      .collection("tuitions")
      .find({})
      .sort({ createdAt: -1 }) // newest posts first
      .toArray();

    // ---------- 3) the tutors' emails (ONE query) ----------
    // postedBy is a plain string id — collect the unique ones,
    // keep only valid 24-hex ids, then fetch them in one go.
    const tutorIds = [...new Set(list.map((t) => String(t.postedBy)))].filter(
      (id) => /^[0-9a-fA-F]{24}$/.test(id),
    ); // safety first
    const tutors =
      tutorIds.length > 0
        ? await db
            .collection("users")
            .find({ _id: { $in: tutorIds.map((id) => new ObjectId(id)) } })
            .toArray()
        : [];
    const tutorById = new Map(tutors.map((u) => [String(u._id), u]));

    // ---------- 4) merge into flat rows for the page ----------
    const tuitions = list.map((t) => {
      const { _id, ...rest } = t; // _id -> "id" below
      const tutor = tutorById.get(String(t.postedBy)); // may be undefined
      return {
        ...rest, // title, subject, classLevel, mode, fee, ...
        id: String(_id), // string id the frontend can use
        tutorName: t.tutorName || "(unknown tutor)", // saved at post time
        tutorEmail: tutor?.email || "(unknown email)", // joined just now
        approvalStatus: t.approvalStatus || "pending", // older docs default
      };
    });

    return res.json({ tuitions });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Something went wrong on the server" });
  }
});

// ============================================================
// PATCH /api/admin/tuitions/:id — APPROVE or REJECT one post
// (the Admin Tuition Approval Flow). Admin role only.
// ============================================================
app.patch(
  "/api/admin/tuitions/:id",
  verifyToken,
  verifyAdmin,
  async (req, res) => {
    try {
      // ---------- 1) only admins may decide ----------
      if (req.user.role !== "admin") {
        return res
          .status(403)
          .json({ message: "Only admins can approve or reject tuitions" });
      }

      // ---------- 2) validate the id format ----------
      const { id } = req.params;
      if (!/^[0-9a-fA-F]{24}$/.test(id)) {
        return res.status(404).json({ message: "Tuition not found" });
      }

      // ---------- 3) validate the new status ----------
      // Only the two decisions from the requirement are allowed
      // (setting it back to "pending" is not part of the flow).
      const { approvalStatus } = req.body || {};
      if (approvalStatus !== "approved" && approvalStatus !== "rejected") {
        return res
          .status(400)
          .json({ message: "approvalStatus must be approved or rejected" });
      }

      // ---------- 4) the post must exist ----------
      const tuition = await db
        .collection("tuitions")
        .findOne({ _id: new ObjectId(id) });
      if (!tuition) {
        return res.status(404).json({ message: "Tuition not found" });
      }

      // ---------- 5) write the decision ----------
      // Only this one field changes — the rest of the post is
      // untouched, and the admin can flip the decision later.
      await db
        .collection("tuitions")
        .updateOne({ _id: new ObjectId(id) }, { $set: { approvalStatus } });

      // ---------- 6) answer with the new status ----------
      return res.json({
        message: `Tuition ${approvalStatus}`, // "Tuition approved" / "Tuition rejected"
        tuition: {
          id: String(tuition._id),
          approvalStatus, // the NEW status
        },
      });
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: "Something went wrong on the server" });
    }
  },
);

// ============================================================
// GET /api/admin/transactions — EVERY Stripe payment row from
// the "payments" collection, for the Transaction Management page
// (/dashboard/admin/transactions).
//
// Project requirement:
//   "Display all Stripe subscription payment records from the
//   payments collection (User Name, Email, Role, Plan Name,
//   Amount, Transaction ID, Payment Date)."
//
// Admin role only. The payments collection stores the buyer's id
// as a STRING — we join the users collection to get the name and
// role back (the email is also saved on the payment itself, so
// deleted accounts still show something sensible).
// ============================================================
app.get(
  "/api/admin/transactions",
  verifyToken,
  verifyAdmin,
  async (req, res) => {
    try {
      // ---------- 1) only admins may see the money ----------
      if (req.user.role !== "admin") {
        return res
          .status(403)
          .json({ message: "Only admins can view transactions" });
      }

      // ---------- 2) every payment row, newest first ----------
      const list = await db
        .collection("payments")
        .find({})
        .sort({ createdAt: -1 }) // latest transactions at the top
        .toArray();

      // ---------- 3) join the buyers (ONE query) ----------
      // userId is a plain string id — collect the unique ones,
      // keep only valid 24-hex ids, then fetch them in one go.
      // (same trick as the admin tuitions endpoint above)
      const buyerIds = [...new Set(list.map((p) => String(p.userId)))].filter(
        (id) => /^[0-9a-fA-F]{24}$/.test(id),
      ); // safety first
      const buyers =
        buyerIds.length > 0
          ? await db
              .collection("users")
              .find({ _id: { $in: buyerIds.map((id) => new ObjectId(id)) } })
              .toArray()
          : [];
      const buyerById = new Map(buyers.map((u) => [String(u._id), u]));

      // ---------- 4) merge into flat rows for the table ----------
      const transactions = list.map((p) => {
        const buyer = buyerById.get(String(p.userId)); // may be undefined

        // "student" / "tutor" -> "Pro Student Plan" / "Pro Tutor Plan"
        const planName =
          p.product === "tutor"
            ? "Pro Tutor Plan"
            : p.product === "student"
              ? "Pro Student Plan"
              : p.planName || "Pro Plan"; // older/odd docs

        return {
          id: String(p._id), // row key for React
          userName: buyer?.name || "(deleted user)", // joined from users
          userEmail: buyer?.email || p.userEmail || "(unknown email)",
          role: buyer?.role || "unknown", // student | tutor | admin
          planName, // what was bought
          amount: typeof p.amount === "number" ? p.amount : 0, // whole dollars
          currency: p.currency || "usd",
          // Stripe's payment id = the transaction id on the page
          // (falls back to the checkout session id for old rows)
          transactionId: p.stripePaymentIntentId || p.stripeSessionId || "",
          paymentDate: p.createdAt || null, // ISO date of the payment
          status: p.status || "paid", // paid | ...
        };
      });

      return res.json({ transactions });
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: "Something went wrong on the server" });
    }
  },
);

// ============================================================
// POST /api/payments/verify — CHECKOUT VERIFICATION
//
// Project requirement:
//   "Use Stripe Webhook (or checkout verification) to save the
//   transaction in the payments collection and update
//   plan: 'pro' in the users collection."
//
// We use CHECKOUT VERIFICATION because it works locally without
// the Stripe CLI / a public URL (a webhook TODO is noted at the
// bottom of this route). The /payment/success page calls this
// with the session id Stripe appended to the redirect URL.
//
// The browser only ever sends the session id — the server asks
// STRIPE itself whether the money arrived, so nobody can claim
// "I paid" from the client side.
// ============================================================
app.post("/api/payments/verify", verifyToken, async (req, res) => {
  try {
    // ---------- 1) Stripe must be configured ----------
    if (!stripe) {
      return res.status(500).json({
        message: "Stripe is not configured (missing STRIPE_SECRET_KEY)",
      });
    }

    // ---------- 2) validate the session id ----------
    // Stripe session ids look like cs_test_AbC123... — anything
    // else cannot exist, so reject it before calling Stripe.
    const { sessionId } = req.body || {};
    if (
      typeof sessionId !== "string" ||
      !/^cs_(test|live)_[A-Za-z0-9_-]+$/.test(sessionId)
    ) {
      return res.status(400).json({ message: "Invalid checkout session id" });
    }

    // ---------- 3) ask STRIPE about this session ----------
    let session;
    try {
      session = await stripe.checkout.sessions.retrieve(sessionId);
    } catch (err) {
      // Stripe says this session id does not exist
      console.error(err);
      return res.status(404).json({ message: "Checkout session not found" });
    }

    // ---------- 4) it must be THIS user's session ----------
    // metadata.userId was written server-side when the session
    // was created — the browser cannot change it. Without this
    // check, user B could "verify" user A's paid session and
    // the upgrade would land on the wrong account.
    if (session.metadata?.userId !== req.user.id) {
      return res
        .status(403)
        .json({ message: "This checkout session belongs to another account" });
    }

    // ---------- 5) Stripe must say the money arrived ----------
    if (session.payment_status !== "paid") {
      return res
        .status(400)
        .json({ message: "This payment is not completed yet" });
    }

    // ---------- 6) which product did they buy ----------
    const product = session.metadata?.plan; // "tutor" | "student"
    if (product !== "tutor" && product !== "student") {
      return res.status(400).json({ message: "Unknown plan on this session" });
    }

    // ---------- 7) the transaction we want to save ----------
    // "amount" is in whole DOLLARS because /api/admin/stats sums
    // exactly this field (1500 cents -> 15). The raw cents value
    // is kept too, in case the UI ever needs exact Stripe data.
    const paymentDoc = {
      stripeSessionId: sessionId, // unique key — one row per checkout
      stripePaymentIntentId:
        typeof session.payment_intent === "string"
          ? session.payment_intent
          : null,
      userId: req.user.id, // the upgraded account
      userEmail: req.user.email,
      plan: "pro", // what we write onto the user below
      product, // "tutor" -> $15 / "student" -> $10
      amount: (session.amount_total ?? 0) / 100, // 1500 -> 15
      amountCents: session.amount_total ?? 0, // raw Stripe value
      currency: session.currency ?? "usd",
      status: "paid",
      createdAt: new Date(),
    };

    // ---------- 8) save it ONCE (idempotent) ----------
    // $setOnInsert + upsert: the FIRST verify inserts the row,
    // every later verify finds it and does nothing — revenue can
    // never be counted twice (e.g. two open success tabs).
    const result = await db
      .collection("payments")
      .updateOne(
        { stripeSessionId: sessionId },
        { $setOnInsert: paymentDoc },
        { upsert: true },
      );
    const isNewPayment = result.upsertedCount === 1;

    // ---------- 9) upgrade the user to "pro" ----------
    // Runs even when the payment row already existed — that
    // repairs the rare case where an earlier verify crashed
    // between steps 8 and 9. Setting "pro" twice is harmless.
    await db
      .collection("users")
      .updateOne({ _id: new ObjectId(req.user.id) }, { $set: { plan: "pro" } });

    // ---------- 10) answer the success page ----------
    return res.json({
      message: isNewPayment
        ? "Payment verified — you are now Pro!"
        : "Payment already recorded",
      plan: "pro",
      payment: {
        product, // "tutor" | "student"
        amount: paymentDoc.amount, // 15 / 10
        currency: paymentDoc.currency,
      },
    });

    // TODO (hardening): add a real Stripe webhook
    // (checkout.session.completed with signature verification via
    // STRIPE_WEBHOOK_SECRET) so payments are recorded even when
    // the visitor closes the success page before it loads.
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
