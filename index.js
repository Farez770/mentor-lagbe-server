import express from "express";
import cors from "cors";
import { MongoClient, ObjectId } from "mongodb";
import "dotenv/config";
import Stripe from "stripe";
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

const CLIENT_URL = (process.env.CLIENT_URL || "http://localhost:3000").replace(
  /\/$/,
  "",
);

const JWKS = createRemoteJWKSet(new URL(`${CLIENT_URL}/api/auth/jwks`));

const stripe = process.env.STRIPE_SECRET_KEY
  ? new Stripe(process.env.STRIPE_SECRET_KEY)
  : null;

app.post(
  "/api/webhooks/stripe",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    const signature = req.headers["stripe-signature"];
    const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

    if (!stripe || !webhookSecret) {
      return res.status(503).json({
        message: "Stripe webhook is not configured (missing env vars)",
      });
    }
    if (!signature || typeof signature !== "string") {
      return res.status(400).json({ message: "Missing Stripe signature" });
    }

    let event;
    try {
      event = stripe.webhooks.constructEvent(
        req.body,
        signature,
        webhookSecret,
      );
    } catch (err) {
      console.error(
        "Stripe webhook signature verification failed:",
        err?.message ?? err,
      );
      return res.status(400).json({ message: "Invalid Stripe signature" });
    }

    if (event.type === "checkout.session.completed") {
      const session = event.data.object;

      if (session.payment_status === "paid") {
        const product = session.metadata?.plan; // "tutor" | "student"
        const userId = session.metadata?.userId; // set server-side at checkout

        if (
          (product === "tutor" || product === "student") &&
          typeof userId === "string" &&
          /^[0-9a-fA-F]{24}$/.test(userId)
        ) {
          const user = await db
            .collection("users")
            .findOne(
              { _id: new ObjectId(userId) },
              { projection: { name: 1, email: 1 } },
            );

          if (user) {
            await db.collection("payments").updateOne(
              { stripeSessionId: session.id },
              {
                $setOnInsert: {
                  stripeSessionId: session.id,
                  stripePaymentIntentId:
                    typeof session.payment_intent === "string"
                      ? session.payment_intent
                      : null,
                  userId,
                  userEmail: user.email,
                  userName: user.name,
                  plan: "pro",
                  product,
                  amount: (session.amount_total ?? 0) / 100,
                  amountCents: session.amount_total ?? 0,
                  currency: session.currency ?? "usd",
                  status: "paid",
                  createdAt: new Date(),
                },
              },
              { upsert: true },
            );

            await db
              .collection("users")
              .updateOne(
                { _id: new ObjectId(userId) },
                { $set: { plan: "pro" } },
              );
          }
        }
      }
    }

    return res.json({ received: true });
  },
);

app.use(express.json());

app.get("/", (req, res) => {
  res.send("Hello World!");
});

async function verifyToken(req, res, next) {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).send({ message: "Unauthorized" });
    }
    const token = authHeader.slice(7); // remove "Bearer "

    const { payload } = await jwtVerify(token, JWKS, {
      issuer: CLIENT_URL,
      audience: CLIENT_URL,
    });

    if (!payload.sub) {
      return res.status(401).send({ message: "Unauthorized" });
    }

    const user = await db
      .collection("users")
      .findOne({ _id: new ObjectId(payload.sub) });
    if (!user) {
      return res.status(401).send({ message: "User not found" });
    }

    req.user = {
      id: String(user._id),
      name: user.name,
      email: user.email,
      image: user.image || "",
      role: user.role || "student", // "student" | "tutor" | "admin"
      plan: user.plan || "free", // "free" | "pro"
    };
    req.jwtPayload = payload;

    next();
  } catch (err) {
    console.error("JWT verification failed:", err?.message ?? err);
    return res.status(401).send({ message: "Unauthorized" });
  }
}

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

app.post("/api/tuitions", verifyToken, verifyTutor, async (req, res) => {
  try {
    if (req.user.role !== "tutor") {
      return res
        .status(403)
        .json({ message: "Only tutors can post a tuition" });
    }

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

    const errors = validateTuition(req.body);

    if (errors.length > 0) {
      return res.status(400).json({ message: errors[0], errors });
    }

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

      approvalStatus: "pending",
      isActive: true,

      postedBy: req.user.id,
      tutorName: req.user.name,
      tutorImage: req.user.image,

      createdAt: new Date(),
    };

    const result = await db.collection("tuitions").insertOne(newTuition);

    return res.status(201).json({
      message: "Tuition posted! It will be visible after admin approval",
      tuition: { ...newTuition, id: String(result.insertedId) },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Something went wrong on the server" });
  }
});

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

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function exactIgnoreCase(value) {
  return { $regex: `^${escapeRegex(value)}$`, $options: "i" };
}

app.get("/api/tuitions", async (req, res) => {
  try {
    const q = String(req.query.q ?? req.query.search ?? "").trim();
    const subject = String(req.query.subject ?? "all").trim();
    const classLevel = String(req.query.classLevel ?? "all").trim();
    const mode = String(req.query.mode ?? "all").trim();

    const publicFilter = { approvalStatus: "approved", isActive: true };

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

app.get("/api/tuitions/stats", verifyToken, verifyTutor, async (req, res) => {
  try {
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

    const applicants = await db
      .collection("applications")
      .countDocuments({ tutorId: postedBy });

    return res.json({ total, approved, pending, applicants });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Something went wrong on the server" });
  }
});

app.get("/api/tuitions/:id", async (req, res) => {
  try {
    const { id } = req.params; // the id from the URL
    if (!/^[0-9a-fA-F]{24}$/.test(id)) {
      return res.status(404).json({ message: "Tuition not found" });
    }

    const doc = await db
      .collection("tuitions")
      .findOne({ _id: new ObjectId(id), isActive: true });

    if (!doc) {
      return res.status(404).json({ message: "Tuition not found" });
    }

    let tutorPlan = "free";
    const postedBy = String(doc.postedBy ?? "");
    if (/^[0-9a-fA-F]{24}$/.test(postedBy)) {
      const tutor = await db
        .collection("users")
        .findOne({ _id: new ObjectId(postedBy) }, { projection: { plan: 1 } });
      tutorPlan = tutor?.plan === "pro" ? "pro" : "free";
    }

    const { _id, ...rest } = doc;
    return res.json({
      tuition: {
        id: String(_id),
        ...rest,
        tutorPlan,
        tutorVerified: tutorPlan === "pro",
      },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Something went wrong on the server" });
  }
});

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

app.patch("/api/tuitions/:id", verifyToken, verifyTutor, async (req, res) => {
  try {
    if (req.user.role !== "tutor") {
      return res.status(403).json({ message: "Only tutors can edit tuitions" });
    }

    const tuition = await getOwnedTuition(req, res);
    if (!tuition) return; // error response already sent

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

app.post("/api/applications", verifyToken, verifyStudent, async (req, res) => {
  try {
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

    const already = await db.collection("applications").findOne({
      tuitionId: cleanTuitionId,
      studentId: req.user.id,
    });
    if (already) {
      return res
        .status(400)
        .json({ message: "You have already applied to this tuition" });
    }

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

      const applications = await db
        .collection("applications")
        .find({ tutorId: req.user.id })
        .sort({ createdAt: -1 }) // newest first
        .toArray();

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

      const applications = await db
        .collection("applications")
        .find({ studentId: req.user.id })
        .sort({ createdAt: -1 })
        .toArray();

      if (applications.length === 0) {
        return res.json({ applications: [] }); // nothing to join
      }

      const tuitionIds = applications.map((a) => a.tuitionId);
      const tuitions = await db
        .collection("tuitions")
        .find({ _id: { $in: tuitionIds.map((id) => new ObjectId(id)) } })
        .toArray();
      const tuitionById = new Map(tuitions.map((t) => [String(t._id), t]));

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

      const list = applications.map((a) => {
        const tuition = tuitionById.get(a.tuitionId); // may be undefined
        const tutor = tuition
          ? tutorById.get(String(tuition.postedBy))
          : undefined;

        return {
          id: String(a._id),
          tuitionId: a.tuitionId,
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

      if (application.studentId !== req.user.id) {
        return res.status(403).json({
          message: "You can only cancel your own applications",
        });
      }

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

const FREE_BOOKMARK_LIMIT = 5;

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
      limit: isPro ? null : FREE_BOOKMARK_LIMIT,
      plan: isPro ? "pro" : "free",
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Something went wrong on the server" });
  }
});

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

app.post("/api/bookmarks", verifyToken, verifyStudent, async (req, res) => {
  try {
    if (req.user.role !== "student") {
      return res
        .status(403)
        .json({ message: "Only students can bookmark tuitions" });
    }

    const { tuitionId } = req.body || {};
    if (typeof tuitionId !== "string" || !/^[0-9a-fA-F]{24}$/.test(tuitionId)) {
      return res.status(404).json({ message: "Tuition not found" });
    }

    const tuition = await db
      .collection("tuitions")
      .findOne({ _id: new ObjectId(tuitionId) });
    if (!tuition) {
      return res.status(404).json({ message: "Tuition not found" });
    }

    const already = await db.collection("bookmarks").findOne({
      userId: req.user.id,
      tuitionId,
    });
    if (already) {
      return res
        .status(400)
        .json({ message: "You already bookmarked this tuition" });
    }

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

app.patch("/api/profile", verifyToken, async (req, res) => {
  try {
    const { name, phone, bio, image } = req.body || {};

    const errors = [];

    if (typeof name !== "string" || name.trim().length < 2) {
      errors.push("Name must be at least 2 characters");
    }

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

    const updates = {
      name: name.trim(),
      phone: typeof phone === "string" ? phone.trim() : "",
      bio: typeof bio === "string" ? bio.trim() : "",
      image: typeof image === "string" ? image.trim() : "",
    };

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

app.get("/api/admin/stats", verifyToken, verifyAdmin, async (req, res) => {
  try {
    if (req.user.role !== "admin") {
      return res
        .status(403)
        .json({ message: "Only admins can view platform stats" });
    }

    const totalUsers = await db.collection("users").countDocuments();

    const totalTutors = await db
      .collection("users")
      .countDocuments({ role: "tutor" });

    const pendingTuitions = await db
      .collection("tuitions")
      .countDocuments({ approvalStatus: "pending" });
    const approvedTuitions = await db
      .collection("tuitions")
      .countDocuments({ approvalStatus: "approved" });

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

app.get("/api/admin/users", verifyToken, verifyAdmin, async (req, res) => {
  try {
    if (req.user.role !== "admin") {
      return res
        .status(403)
        .json({ message: "Only admins can view all users" });
    }

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

app.patch(
  "/api/admin/users/:id",
  verifyToken,
  verifyAdmin,
  async (req, res) => {
    try {
      if (req.user.role !== "admin") {
        return res
          .status(403)
          .json({ message: "Only admins can change roles" });
      }

      const { id } = req.params;
      if (!/^[0-9a-fA-F]{24}$/.test(id)) {
        return res.status(404).json({ message: "User not found" });
      }

      const { role } = req.body || {};
      if (role !== "student" && role !== "tutor" && role !== "admin") {
        return res
          .status(400)
          .json({ message: "Role must be student, tutor or admin" });
      }

      if (id === req.user.id) {
        return res
          .status(400)
          .json({ message: "You cannot change your own role" });
      }

      const user = await db
        .collection("users")
        .findOne({ _id: new ObjectId(id) });
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }

      await db
        .collection("users")
        .updateOne({ _id: new ObjectId(id) }, { $set: { role } });

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

app.get("/api/admin/tuitions", verifyToken, verifyAdmin, async (req, res) => {
  try {
    if (req.user.role !== "admin") {
      return res
        .status(403)
        .json({ message: "Only admins can review tuitions" });
    }

    const list = await db
      .collection("tuitions")
      .find({})
      .sort({ createdAt: -1 }) // newest posts first
      .toArray();

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

app.patch(
  "/api/admin/tuitions/:id",
  verifyToken,
  verifyAdmin,
  async (req, res) => {
    try {
      if (req.user.role !== "admin") {
        return res
          .status(403)
          .json({ message: "Only admins can approve or reject tuitions" });
      }

      const { id } = req.params;
      if (!/^[0-9a-fA-F]{24}$/.test(id)) {
        return res.status(404).json({ message: "Tuition not found" });
      }

      const { approvalStatus } = req.body || {};
      if (approvalStatus !== "approved" && approvalStatus !== "rejected") {
        return res
          .status(400)
          .json({ message: "approvalStatus must be approved or rejected" });
      }

      const tuition = await db
        .collection("tuitions")
        .findOne({ _id: new ObjectId(id) });
      if (!tuition) {
        return res.status(404).json({ message: "Tuition not found" });
      }

      await db
        .collection("tuitions")
        .updateOne({ _id: new ObjectId(id) }, { $set: { approvalStatus } });

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

app.get(
  "/api/admin/transactions",
  verifyToken,
  verifyAdmin,
  async (req, res) => {
    try {
      if (req.user.role !== "admin") {
        return res
          .status(403)
          .json({ message: "Only admins can view transactions" });
      }

      const list = await db
        .collection("payments")
        .find({})
        .sort({ createdAt: -1 }) // latest transactions at the top
        .toArray();

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

      const transactions = list.map((p) => {
        const buyer = buyerById.get(String(p.userId)); // may be undefined

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

app.post("/api/payments/verify", verifyToken, async (req, res) => {
  try {
    if (!stripe) {
      return res.status(500).json({
        message: "Stripe is not configured (missing STRIPE_SECRET_KEY)",
      });
    }

    const { sessionId } = req.body || {};
    if (
      typeof sessionId !== "string" ||
      !/^cs_(test|live)_[A-Za-z0-9_-]+$/.test(sessionId)
    ) {
      return res.status(400).json({ message: "Invalid checkout session id" });
    }

    let session;
    try {
      session = await stripe.checkout.sessions.retrieve(sessionId);
    } catch (err) {
      console.error(err);
      return res.status(404).json({ message: "Checkout session not found" });
    }

    if (session.metadata?.userId !== req.user.id) {
      return res
        .status(403)
        .json({ message: "This checkout session belongs to another account" });
    }

    if (session.payment_status !== "paid") {
      return res
        .status(400)
        .json({ message: "This payment is not completed yet" });
    }

    const product = session.metadata?.plan; // "tutor" | "student"
    if (product !== "tutor" && product !== "student") {
      return res.status(400).json({ message: "Unknown plan on this session" });
    }

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

    const result = await db
      .collection("payments")
      .updateOne(
        { stripeSessionId: sessionId },
        { $setOnInsert: paymentDoc },
        { upsert: true },
      );
    const isNewPayment = result.upsertedCount === 1;

    await db
      .collection("users")
      .updateOne({ _id: new ObjectId(req.user.id) }, { $set: { plan: "pro" } });

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

    // The signed /api/webhooks/stripe route above also records this
    // payment if the visitor closes the success page before it loads.
    // Both paths use the same idempotent payments upsert.
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Something went wrong on the server" });
  }
});

app.use((req, res) => {
  res.status(404).json({ message: "Route not found" });
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});

export default app;
