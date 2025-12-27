const express = require("express");
const cors = require("cors");
const app = express();
require("dotenv").config();
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const port = process.env.PORT || 3000;
const bcrypt = require("bcrypt");
const admin = require("firebase-admin");
const crypto = require("crypto");
const nodemailer = require("nodemailer");

const stripe = require("stripe")(process.env.STRIPE_SECRET);
//const serviceAccount = require("./etuition-firebase-adminsdk.json");
const decoded = Buffer.from(process.env.FB_SERVICE_KEY, "base64").toString(
  "utf8"
);

const serviceAccount = JSON.parse(decoded);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});
// middleware
app.use(express.json());
app.use(cors());
const saltRounds = 10;
// Firebase token verification middleware
const verifyFBToken = async (req, res, next) => {
  const token = req.headers.authorization;
  if (!token) {
    return res.status(401).send({ message: "Unauthorized access , no token" });
  }
  try {
    const idToken = token.split(" ")[1];
    const decoded = await admin.auth().verifyIdToken(idToken);

    req.decoded_email = decoded.email;
    next();
  } catch (err) {
    console.error("Firebase token verification error:", err);
    return res
      .status(401)
      .send({ message: "Unauthorized access , invalid token" });
  }
};

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASSWORD}@cluster0.eemz9pt.mongodb.net/?appName=Cluster0`;
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    await client.connect();

    const db = client.db("e_tuitionBD_db");
    const usersCollection = db.collection("users");
    const tutorsCollection = db.collection("tutors");
    const tuitionsCollection = db.collection("tuitions");
    const paymentsCollection = db.collection("payments");
    const applicationsCollection = db.collection("applications");
    const reviewsCollection = db.collection("reviews");
    const conversationCollection = db.collection("conversations");
    const messagesCollection = db.collection("messages");
    const notificationsCollection = db.collection("notifications");

    // middlewares
    const verifyAdmin = async (req, res, next) => {
      const email = req.decoded_email;
      const query = { email };
      const user = await usersCollection.findOne(query);
      if (!user || user.role !== "admin") {
        return res.status(403).send({ message: "Forbidden Access" });
      }
      next();
    };
    const verifyTutor = async (req, res, next) => {
      try {
        const email = req.decoded_email;

        if (!email) {
          return res.status(401).send({ message: "Unauthorized access" });
        }

        const tutor = await tutorsCollection.findOne({ email });

        if (!tutor) {
          return res
            .status(403)
            .send({ message: "Access denied: Tutor not found" });
        }
        if (tutor.status !== "approved") {
          return res.status(403).send({
            message: "Access denied: Tutor is not verified",
          });
        }
        req.tutor = tutor;

        next();
      } catch (err) {
        console.error("verifyTutor error:", err);
        res.status(500).send({ message: "Tutor verification failed" });
      }
    };

    // auth related API
    // forgot pass
    app.post("/auth/forgot-password", async (req, res) => {
      const { email } = req.body;
      const user = await usersCollection.findOne({ email });

      if (!user) {
        return res.status(404).send({ message: "User not found" });
      }

      if (user.otpExpiry && Date.now() < user.otpExpiry - 4 * 60 * 1000) {
        return res
          .status(429)
          .send({ message: "Please wait before requesting again" });
      }

      const otp = Math.floor(100000 + Math.random() * 900000).toString();
      const hashedOtp = await bcrypt.hash(otp, 10);

      await usersCollection.updateOne(
        { email },
        {
          $set: {
            resetOtp: hashedOtp,
            otpExpiry: Date.now() + 5 * 60 * 1000,
            otpVerified: false,
          },
        }
      );

      const transporter = nodemailer.createTransport({
        service: "Gmail",
        auth: {
          user: process.env.EMAIL_USER,
          pass: process.env.EMAIL_PASS,
        },
      });

      await transporter.sendMail({
        from: `" eTuitionBD" <${process.env.EMAIL_USER}>`,
        to: email,
        subject: "Password Reset OTP",
        html: `
      <h2>eTuitionBD – Rest Password Verification Code</h2>
      <p>Dear User,</p>

      <p>To continue with your request on <strong>eTuitionBD</strong>, please use the verification code below:</p>

      <p style="font-size: 22px; font-weight: 600; letter-spacing: 2px;">
        ${otp}
      </p>

      <p>This code will expire in <strong>5 minutes</strong>. For security reasons, please do not share this code with anyone.</p>

      <p>If you did not request this verification, you can safely ignore this email.</p>

      <p>Regards,<br/>
      <strong>eTuitionBD Team</strong></p>

    `,
      });

      res.send({ message: "OTP sent successfully" });
    });
    // verify otp
    app.post("/auth/verify-otp", async (req, res) => {
      const { email, otp } = req.body;
      const user = await usersCollection.findOne({ email });

      if (!user || !user.resetOtp)
        return res.status(400).send({ message: "Invalid request" });

      if (Date.now() > user.otpExpiry)
        return res.status(400).send({ message: "OTP expired" });

      const isValid = await bcrypt.compare(otp, user.resetOtp);
      if (!isValid) return res.status(400).send({ message: "Incorrect OTP" });

      const resetToken = crypto.randomBytes(32).toString("hex");

      await usersCollection.updateOne(
        { email },
        {
          $set: {
            otpVerified: true,
            resetToken,
            resetTokenExpiry: Date.now() + 10 * 60 * 1000,
          },
        }
      );

      res.send({ message: "OTP verified", resetToken });
    });
    // reset pass
    app.post("/auth/reset-password", async (req, res) => {
      const { email, resetToken, newPassword } = req.body;
      const user = await usersCollection.findOne({ email });

      if (
        !user ||
        user.resetToken !== resetToken ||
        Date.now() > user.resetTokenExpiry
      ) {
        return res.status(400).send({ message: "Invalid or expired token" });
      }

      const hashedPassword = await bcrypt.hash(newPassword, 10);

      await usersCollection.updateOne(
        { email },
        {
          $set: { password: hashedPassword },
          $unset: {
            resetOtp: "",
            otpExpiry: "",
            otpVerified: "",
            resetToken: "",
            resetTokenExpiry: "",
          },
        }
      );

      res.send({ message: "Password reset successful" });
    });

    // dashboard
    // student
    app.get("/dashboard/student", verifyFBToken, async (req, res) => {
      try {
        const email = req.decoded_email;
        const user = await usersCollection.findOne({ email });
        if (!user) return res.status(404).send({ message: "User not found" });

        let dashboardData = {};

        const tuitionsPipeline = [
          { $match: { email } },
          { $group: { _id: "$status", count: { $sum: 1 } } },
        ];

        const paymentsPipeline = [
          { $match: { studentEmail: email } },
          {
            $group: {
              _id: null,
              totalSpent: { $sum: "$amount" },
              totalPayments: { $sum: 1 },
            },
          },
        ];

        const applicationsPipeline = [
          { $match: { studentId: user._id } },
          {
            $group: {
              _id: "$status",
              count: { $sum: 1 },
            },
          },
        ];

        const subjectsPipeline = [
          { $match: { email: email } },
          { $unwind: "$subjects" },
          { $group: { _id: "$subjects", count: { $sum: 1 } } },
          { $sort: { count: -1 } },
        ];

        const [
          tuitionsSummary,
          paymentsSummary,
          applicationsSummary,
          subjectsSummary,
        ] = await Promise.all([
          tuitionsCollection.aggregate(tuitionsPipeline).toArray(),
          paymentsCollection.aggregate(paymentsPipeline).toArray(),
          applicationsCollection.aggregate(applicationsPipeline).toArray(),
          tuitionsCollection.aggregate(subjectsPipeline).toArray(),
        ]);

        dashboardData = {
          role: "student",
          tuitionsSummary,
          paymentsSummary: paymentsSummary[0] || {
            totalSpent: 0,
            totalPayments: 0,
          },
          applicationsSummary,
          subjectsSummary,
        };

        res.send(dashboardData);
      } catch (err) {
        console.error("Dashboard fetch error:", err);
        res.status(500).send({ message: "Failed to fetch dashboard data" });
      }
    });
    // tutor
    app.get(
      "/dashboard/tutor",
      verifyFBToken,
      verifyTutor,
      async (req, res) => {
        try {
          const email = req.decoded_email;
          const tutor = await tutorsCollection.findOne({ email });
          if (!tutor)
            return res.status(404).send({ message: "Tutor profile not found" });

          const tutorId = tutor._id;

          const tuitionsSummaryPipeline = [
            { $match: { tutorId } },
            { $group: { _id: "$status", count: { $sum: 1 } } },
          ];

          const paymentsPipeline = [
            { $match: { tutorId } },
            {
              $group: {
                _id: null,
                totalIncome: { $sum: "$salary" },
                totalPayments: { $sum: 1 },
              },
            },
          ];

          const applicationsPipeline = [
            { $match: { tutorId } },
            { $group: { _id: "$status", count: { $sum: 1 } } },
          ];

          const reviewsPipeline = [
            { $match: { tutorId } },
            { $group: { _id: "$rating", count: { $sum: 1 } } },
            { $sort: { _id: -1 } },
          ];

          const [
            tuitionsSummary,
            paymentsSummary,
            applicationsSummary,
            reviewsSummary,
          ] = await Promise.all([
            tuitionsCollection.aggregate(tuitionsSummaryPipeline).toArray(),
            paymentsCollection.aggregate(paymentsPipeline).toArray(),
            applicationsCollection.aggregate(applicationsPipeline).toArray(),
            reviewsCollection.aggregate(reviewsPipeline).toArray(),
          ]);

          const totalTuitions = tuitionsSummary.reduce(
            (acc, t) => acc + t.count,
            0
          );
          const ongoingTuitions =
            tuitionsSummary.find((t) => t._id === "ongoing")?.count || 0;
          const totalApplications = applicationsSummary.reduce(
            (acc, a) => acc + a.count,
            0
          );
          const acceptedApplications =
            applicationsSummary.find((a) => a._id === "accepted")?.count || 0;
          const totalIncome = paymentsSummary[0]?.totalIncome || 0;
          const averageRating =
            tutor.ratingCount > 0 ? tutor.ratingSum / tutor.ratingCount : 0;

          const cards = {
            totalTuitions,
            ongoingTuitions,
            totalApplications,
            acceptedApplications,
            totalIncome,
            averageRating: parseFloat(averageRating.toFixed(1)),
          };

          res.send({
            role: "tutor",
            cards,
            tuitionsSummary,
            applicationsSummary,
            paymentsSummary: paymentsSummary[0] || {
              totalIncome: 0,
              totalPayments: 0,
            },
            reviewsSummary,
          });
        } catch (err) {
          console.error("Tutor dashboard error:", err);
          res
            .status(500)
            .send({ message: "Failed to fetch tutor dashboard data" });
        }
      }
    );
    // admin
    app.get(
      "/dashboard/admin",
      verifyFBToken,
      verifyAdmin,
      async (req, res) => {
        try {
          const totalTuitionsPromise = tuitionsCollection.countDocuments();
          const totalTutorsPromise = tutorsCollection.countDocuments();
          const totalStudentsPromise = usersCollection.countDocuments({
            role: "student",
          });

          const totalRevenuePromise = paymentsCollection
            .aggregate([
              {
                $group: {
                  _id: null,
                  totalRevenue: { $sum: { $subtract: ["$amount", "$salary"] } },
                },
              },
            ])
            .toArray();

          const tuitionsStatusPromise = tuitionsCollection
            .aggregate([{ $group: { _id: "$status", count: { $sum: 1 } } }])
            .toArray();

          const [
            totalTuitions,
            totalTutors,
            totalStudents,
            totalRevenueAgg,
            tuitionsStatus,
          ] = await Promise.all([
            totalTuitionsPromise,
            totalTutorsPromise,
            totalStudentsPromise,
            totalRevenuePromise,
            tuitionsStatusPromise,
          ]);

          const totalRevenue = totalRevenueAgg[0]?.totalRevenue || 0;
          const ongoingTuitions =
            tuitionsStatus.find((t) => t._id === "ongoing")?.count || 0;
          const pendingTuitions =
            tuitionsStatus.find((t) => t._id === "open")?.count || 0;

          const pieChart = tuitionsStatus;

          const today = new Date();
          const sixMonthsAgo = new Date(
            today.getFullYear(),
            today.getMonth() - 5,
            1
          );

          const barChart = await paymentsCollection
            .aggregate([
              { $match: { paidAt: { $gte: sixMonthsAgo } } },
              {
                $group: {
                  _id: {
                    year: { $year: "$paidAt" },
                    month: { $month: "$paidAt" },
                  },
                  revenue: { $sum: { $subtract: ["$amount", "$salary"] } },
                },
              },
              { $sort: { "_id.year": 1, "_id.month": 1 } },
            ])
            .toArray();

          res.send({
            role: "admin",
            cards: {
              totalTuitions,
              totalTutors,
              totalStudents,
              totalRevenue,
              ongoingTuitions,
              pendingTuitions,
            },
            pieChart,
            barChart,
          });
        } catch (err) {
          console.error("Admin dashboard error:", err);
          res
            .status(500)
            .send({ message: "Failed to fetch admin dashboard data" });
        }
      }
    );

    //  users API

    // Get all users
    app.get("/users", verifyFBToken, async (req, res) => {
      try {
        const { page = 1, limit = 10, email, all = "false" } = req.query;

        const pageNumber = Number(page);
        const limitNumber = Number(limit);

        const query = {};
        if (email) query.email = email;

        const totalUsers = await usersCollection.countDocuments(query);

        let cursor = usersCollection.find(query);

        // Apply pagination ONLY if not requesting all
        if (all !== "true") {
          cursor = cursor
            .skip((pageNumber - 1) * limitNumber)
            .limit(limitNumber);
        }

        const users = await cursor.toArray();

        res.send({
          users,
          page: all === "true" ? 1 : pageNumber,
          limit: all === "true" ? totalUsers : limitNumber,
          totalUsers,
          totalPages: all === "true" ? 1 : Math.ceil(totalUsers / limitNumber),
        });
      } catch (error) {
        console.error("Get users error:", error);
        res.status(500).send({ message: "Failed to fetch users" });
      }
    });

    // Get the role of the logged-in user
    app.get("/user-role", verifyFBToken, async (req, res) => {
      try {
        const email = req.decoded_email;

        const user = await usersCollection.findOne({ email });

        if (!user) {
          return res.status(404).send({ message: "User not found" });
        }

        res.send({ role: user.role });
      } catch (error) {
        console.error("Get user role error:", error);
        res.status(500).send({ message: "Failed to fetch user role" });
      }
    });
    // patch user
    app.patch("/users/:email", verifyFBToken, async (req, res) => {
      try {
        const { email } = req.params;

        if (email !== req.decoded_email) {
          return res.status(403).send({ message: "Forbidden Access" });
        }

        const allowedFields = ["name", "phone", "photoURL"];
        const updateDataFiltered = {};

        for (const key of allowedFields) {
          if (req.body[key] !== undefined) {
            updateDataFiltered[key] = req.body[key];
          }
        }

        if (Object.keys(updateDataFiltered).length === 0) {
          return res.status(400).send({ message: "No valid fields to update" });
        }

        const result = await usersCollection.updateOne(
          { email },
          { $set: updateDataFiltered }
        );

        if (result.matchedCount === 0) {
          return res.status(404).send({ message: "User not found" });
        }

        const updatedUser = await usersCollection.findOne({ email });
        res.send(updatedUser);
      } catch (error) {
        console.error("Patch user error:", error);
        res.status(500).send({ message: "Failed to update user" });
      }
    });

    // admin only patch
    app.patch(
      "/users/:id/role",
      verifyFBToken,
      verifyAdmin,
      async (req, res) => {
        try {
          const { id } = req.params;
          const { role, isBanned } = req.body;
          const updateData = {};

          if (role) {
            const allowedRoles = ["admin", "student", "tutor"];
            if (!allowedRoles.includes(role)) {
              return res.status(400).send({ message: "Invalid role" });
            }
            updateData.role = role;
          }
          if (typeof isBanned === "boolean") {
            updateData.isBanned = isBanned;
          }

          if (Object.keys(updateData).length === 0) {
            return res
              .status(400)
              .send({ message: "No valid fields to update" });
          }

          const result = await usersCollection.updateOne(
            { _id: new ObjectId(id) },
            { $set: updateData }
          );

          res.send(result);
        } catch (error) {
          console.error("Admin role patch error:", error);
          res.status(500).send({ message: "Failed to update user" });
        }
      }
    );
    // delete user
    app.delete("/users/:id", verifyFBToken, verifyAdmin, async (req, res) => {
      try {
        const { id } = req.params;

        const result = await usersCollection.deleteOne({
          _id: new ObjectId(id),
        });

        res.send(result);
      } catch (error) {
        console.error("Delete user error:", error);
        res.status(500).send({ message: "Failed to delete user" });
      }
    });

    // post user
    app.post("/users", async (req, res) => {
      try {
        const { name, email, password, role, phone, photoURL } = req.body;

        const existingUser = await usersCollection.findOne({ email });

        if (existingUser) {
          return res.status(409).send({ message: "User already exists" });
        }

        let hashedPassword = null;

        if (password) {
          hashedPassword = await bcrypt.hash(password, saltRounds);
        }

        const newUser = {
          name,
          email,
          password: hashedPassword,
          role,
          phone,
          photoURL,
          createdAt: new Date(),
        };

        const result = await usersCollection.insertOne(newUser);

        res.send({
          success: true,
          message: "User registered successfully",
          userId: result.insertedId,
        });
      } catch (err) {
        console.error(err);
        res.status(500).send({ message: "Internal server error" });
      }
    });

    // tutor related API
    // get latest tutors
    app.get("/tutors/latest", async (req, res) => {
      try {
        const tutors = await tutorsCollection
          .find()
          .sort({ submittedAt: -1 })
          .limit(6)
          .toArray();

        res.send({ tutors });
      } catch (error) {
        console.error("Latest tutors error:", error);
        res.status(500).send({ message: "Failed to fetch latest tutors" });
      }
    });
    // tutor Info district
    app.get("/tutor-info", verifyFBToken, async (req, res) => {
      try {
        const email = req.decoded_email;

        const tutor = await tutorsCollection.findOne(
          { email },
          { projection: { _id: 1, district: 1 } }
        );

        if (!tutor) {
          return res.status(404).send({ message: "Tutor not found" });
        }

        res.send(tutor);
      } catch (err) {
        console.error("Fetch tutor info error:", err);
        res.status(500).send({ message: "Failed to fetch tutor info" });
      }
    });
    // get all tutors
    app.get("/tutors", verifyFBToken, async (req, res) => {
      try {
        const {
          email,
          status,
          page = 1,
          limit = 10,
          sortBy = "submittedAt",
          order = "desc",
        } = req.query;

        const pageNumber = Number(page);
        const limitNumber = Number(limit);
        const skip = (pageNumber - 1) * limitNumber;

        const query = {};
        if (email) query.email = email;
        if (status) query.status = status;

        const sortQuery = {
          [sortBy]: order === "asc" ? 1 : -1,
        };

        const totalTutors = await tutorsCollection.countDocuments(query);

        const tutors = await tutorsCollection
          .find(query)
          .sort(sortQuery)
          .skip(skip)
          .limit(limitNumber)
          .toArray();

        res.send({
          tutors,
          page: pageNumber,
          limit: limitNumber,
          totalPages: Math.ceil(totalTutors / limitNumber),
          totalTutors,
        });
      } catch (error) {
        console.error("Get tutors error:", error);
        res.status(500).send({ message: "Failed to fetch tutors" });
      }
    });
    // getting tutors by id
    app.get("/tutors/:id", verifyFBToken, async (req, res) => {
      try {
        const { id } = req.params;
        const tutor = await tutorsCollection.findOne({ _id: new ObjectId(id) });

        if (!tutor) {
          return res.status(404).send({ message: "Tutor not found" });
        }

        res.send(tutor);
      } catch (error) {
        console.error("Get tutor error:", error);
        res.status(500).send({ message: "Failed to fetch tutor" });
      }
    });
    // patch tutor
    app.patch("/tutors/:id", verifyFBToken, verifyAdmin, async (req, res) => {
      try {
        const { id } = req.params;
        const updateData = req.body;

        const result = await tutorsCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: updateData }
        );

        if (result.matchedCount === 0) {
          return res.status(404).send({ message: "Tutor not found" });
        }
        if (updateData.status === "approved") {
          const tutor = await tutorsCollection.findOne({
            _id: new ObjectId(id),
          });

          if (tutor?.email) {
            await notificationsCollection.insertOne({
              userEmail: tutor.email,
              type: "PROFILE_APPROVED",
              title: "Profile Approved",
              message: `Your tutor profile has been approved by admin.`,
              link: `/dashboard`,
              isRead: false,
              createdAt: new Date(),
            });
          }
        }

        res.send({
          success: true,
          modifiedCount: result.modifiedCount,
        });
      } catch (error) {
        console.error("Patch tutor error:", error);
        res.status(500).send({ message: "Failed to update tutor" });
      }
    });
    // delete tutors
    app.delete("/tutors/:id", verifyFBToken, verifyAdmin, async (req, res) => {
      try {
        const { id } = req.params;

        const tutor = await tutorsCollection.findOne({ _id: new ObjectId(id) });
        if (!tutor) {
          return res.status(404).send({ message: "Tutor not found" });
        }
        const result = await tutorsCollection.deleteOne({
          _id: new ObjectId(id),
        });

        if (result.deletedCount === 0) {
          return res.status(404).send({ message: "Tutor not found" });
        }
        await usersCollection.updateOne(
          { email: tutor.email },
          { $set: { role: "student" } }
        );

        res.send({ success: true });
      } catch (error) {
        console.error("Delete tutor error:", error);
        res.status(500).send({ message: "Failed to delete tutor" });
      }
    });
    // posting tutors
    app.post("/tutors", verifyFBToken, async (req, res) => {
      try {
        const {
          name,
          email,
          qualification,
          institution,
          idCardURL,
          district,
          location,
          experienceMonths,
          experienceYears,
          salary,
          subjects,
          time,
          mode,
          bio,
        } = req.body;

        if (!name || !email || !idCardURL || !subjects?.length) {
          return res.status(400).send({
            success: false,
            message: "Missing required fields",
          });
        }
        //   find user to get phone , photoURL
        const userData = await usersCollection.findOne(
          { email },
          { projection: { phone: 1, photoURL: 1 } }
        );
        if (!userData) {
          return res.status(404).send({
            success: false,
            message: "User not found in usersCollection",
          });
        }
        // prevent duplicate tutor profile
        const existing = await tutorsCollection.findOne({ email });
        if (existing) {
          return res.status(409).send({
            success: false,
            message: "You have already submitted a tutor application.",
          });
        }
        const application = {
          name,
          email,
          phone: userData.phone || "",
          photoURL: userData.photoURL || "",
          qualification,
          institution,
          idCardURL,
          experienceYears,
          experienceMonths,
          subjects,
          district,
          time,
          location,
          salary,
          mode,
          bio,
          status: "pending",
          submittedAt: new Date(),
        };
        const result = await tutorsCollection.insertOne(application);
        // create notifications for all admins
        const admins = await usersCollection.find({ role: "admin" }).toArray();
        const notifications = admins.map((admin) => ({
          userEmail: admin.email,
          type: "TUTOR_APPLICATION",
          title: "New Tutor Application",
          message: `${name} has applied to become a tutor.`,
          link: `/dashboard/tutors`,
          isRead: false,
          createdAt: new Date(),
        }));

        if (notifications.length) {
          await notificationsCollection.insertMany(notifications);
        }
        res.send({
          success: true,
          message: "Tutor application submitted successfully",
          insertedId: result.insertedId,
        });
      } catch (err) {
        console.error("Tutor Application Error:", err);
        res.status(500).send({
          success: false,
          message: "Internal server error",
        });
      }
    });

    // tuitions API
    // get latest tuitions
    app.get("/tuitions/latest", async (req, res) => {
      try {
        const latestTuitions = await tuitionsCollection
          .find({ status: "open" })
          .sort({ postedAt: -1 })
          .limit(6)
          .toArray();

        res.send({ latestTuitions });
      } catch (err) {
        console.error("Latest tuitions error:", err);
        res.status(500).send({ message: "Failed to fetch latest tuitions" });
      }
    });

    // get all tuitions
    app.get("/tuitions", verifyFBToken, async (req, res) => {
      try {
        let {
          page = 1,
          limit = 10,
          subject,
          classLevel,
          district,
          location,
          sortBy = "date",
          order = "desc",
        } = req.query;

        const pageNumber = parseInt(page);
        const limitNumber = Math.min(parseInt(limit), 20);
        const skip = (pageNumber - 1) * limitNumber;
        const sortOrder = order === "asc" ? 1 : -1;

        const matchStage = { status: "open" };

        // subject
        if (subject) {
          matchStage.subjects = { $regex: subject, $options: "i" };
        }

        //  Class
        if (classLevel) {
          matchStage.classLevel = { $regex: classLevel, $options: "i" };
        }

        //  District
        if (district) {
          matchStage.district = { $regex: district, $options: "i" };
        }

        //  Location
        if (location) {
          matchStage.location = { $regex: location, $options: "i" };
        }

        const pipeline = [
          { $match: matchStage },

          {
            $addFields: {
              avgBudget: {
                $avg: ["$minBudget", "$maxBudget"],
              },
            },
          },
          {
            $sort:
              sortBy === "budget"
                ? { avgBudget: sortOrder }
                : { postedAt: sortOrder },
          },

          { $skip: skip },
          { $limit: limitNumber },

          {
            $project: {
              classLevel: 1,
              subjects: 1,
              district: 1,
              location: 1,
              minBudget: 1,
              maxBudget: 1,
              mode: 1,
              days: 1,
              time: 1,
              postedAt: 1,
            },
          },
        ];

        const [tuitions, total] = await Promise.all([
          tuitionsCollection.aggregate(pipeline).toArray(),
          tuitionsCollection.countDocuments(matchStage),
        ]);

        res.send({
          tuitions,
          page: pageNumber,
          limit: limitNumber,
          total,
          totalPages: Math.ceil(total / limitNumber),
        });
      } catch (err) {
        console.error("Get tuitions error:", err);
        res.status(500).send({ message: "Failed to fetch tuitions" });
      }
    });
    // get tuitions for teachers
    app.get(
      "/dashboard/tutor-tuitions",
      verifyFBToken,
      verifyTutor,
      async (req, res) => {
        try {
          const tutorEmail = req.decoded_email;
          let { page = 1, limit = 10 } = req.query;
          const pageNumber = parseInt(page);
          const limitNumber = Math.min(parseInt(limit), 10);
          const skip = (pageNumber - 1) * limitNumber;
          const query = { tutorEmail };
          const projection = {
            subjects: 1,
            days: 1,
            status: 1,
            salary: 1,
            mode: 1,
            startedAt: 1,
            time: 1,
            name: 1,
            phone: 1,
            email: 1,
          };
          const [tuitions, total] = await Promise.all([
            tuitionsCollection
              .find(query, { projection })
              .sort({ assignedAt: -1 })
              .skip(skip)
              .limit(limitNumber)
              .toArray(),

            tuitionsCollection.countDocuments(query),
          ]);

          res.send({
            tuitions,
            page: pageNumber,
            limit: limitNumber,
            total,
            totalPages: Math.ceil(total / limitNumber),
          });
        } catch (err) {
          console.error("Tutor tuitions fetch error:", err);
          res.status(500).send({ message: "Failed to fetch tutor tuitions" });
        }
      }
    );

    // get tuitions by email for students
    app.get("/dashboard/my-tuitions", verifyFBToken, async (req, res) => {
      try {
        const email = req.decoded_email;

        let { page = 1, limit = 10 } = req.query;

        const pageNumber = parseInt(page);
        const limitNumber = Math.min(parseInt(limit), 10);
        const skip = (pageNumber - 1) * limitNumber;

        const query = { email };

        const projection = {
          subjects: 1,
          days: 1,
          time: 1,
          minBudget: 1,
          maxBudget: 1,
          mode: 1,
          status: 1,
          postedAt: 1,
          reviewed: 1,
        };

        const [tuitions, total] = await Promise.all([
          tuitionsCollection
            .find(query, { projection })
            .sort({ postedAt: -1 })
            .skip(skip)
            .limit(limitNumber)
            .toArray(),

          tuitionsCollection.countDocuments(query),
        ]);

        res.send({
          tuitions,
          page: pageNumber,
          limit: limitNumber,
          total,
          totalPages: Math.ceil(total / limitNumber),
        });
      } catch (err) {
        console.error("My tuitions fetch error:", err);
        res.status(500).send({ message: "Failed to fetch my tuitions" });
      }
    });
    // individual tuitions
    app.get("/tuitions/:id", verifyFBToken, async (req, res) => {
      const { id } = req.params;

      try {
        const tuition = await tuitionsCollection.findOne(
          {
            _id: new ObjectId(id),
          },
          {
            projection: {
              name: 1,
              email: 1,
              phone: 1,
              photoURL: 1,
              status: 1,
              classLevel: 1,
              subjects: 1,
              minBudget: 1,
              maxBudget: 1,
              location: 1,
              district: 1,
              mode: 1,
              days: 1,
              time: 1,
              duration: 1,
              postedAt: 1,
              description: 1,
            },
          }
        );

        if (!tuition) {
          return res.status(404).json({ message: "Tuition not found" });
        }

        res.json(tuition);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch tuition" });
      }
    });
    //tutor completing tuition
    app.patch(
      "/tuitions/tutor/:id",
      verifyFBToken,
      verifyTutor,
      async (req, res) => {
        try {
          const { id } = req.params;
          const email = req.decoded_email;
          const tuition = await tuitionsCollection.findOne({
            _id: new ObjectId(id),
          });
          if (!tuition) {
            return res.status(404).send({ message: "Tuition not found" });
          }
          if (email !== tuition.tutorEmail) {
            return res
              .status(403)
              .send({ message: "You are not allowed to update this tuition" });
          }
          if (!["ongoing"].includes(tuition.status)) {
            return res.status(400).send({
              message: "Only ongoing tuitions can be closed",
            });
          }

          const result = await tuitionsCollection.updateOne(
            { _id: new ObjectId(id) },
            {
              $set: {
                status: "completed",
                closedAt: new Date(),
              },
            }
          );

          res.send({
            success: true,
            message: "Tuition closed successfully",
            modifiedCount: result.modifiedCount,
          });
        } catch (err) {
          console.error("Close tuition error:", err);
          res.status(500).send({ message: "Failed to close tuition" });
        }
      }
    );

    // update tuition

    app.patch("/tuitions/:id", verifyFBToken, async (req, res) => {
      try {
        const { id } = req.params;
        const emailFromToken = req.decoded_email;
        const { status, ...rest } = req.body;

        const tuition = await tuitionsCollection.findOne({
          _id: new ObjectId(id),
        });

        if (!tuition) {
          return res.status(404).send({ message: "Tuition not found" });
        }

        if (tuition.email !== emailFromToken) {
          return res
            .status(403)
            .send({ message: "You are not allowed to update this tuition" });
        }

        const allowedFields = [
          "classLevel",
          "subjects",
          "days",
          "time",
          "duration",
          "minBudget",
          "maxBudget",
          "mode",
          "description",
        ];

        const updateDoc = {};
        allowedFields.forEach((field) => {
          if (field in rest) updateDoc[field] = rest[field];
        });

        if (status) {
          const transitions = {
            open: ["assigned", "closed"],
            assigned: ["ongoing"],
            ongoing: ["completed"],
          };

          const allowedNext = transitions[tuition.status] || [];

          if (!allowedNext.includes(status)) {
            return res.status(400).send({
              message: `Invalid status change from ${tuition.status} to ${status}`,
            });
          }

          updateDoc.status = status;

          if (status === "closed") updateDoc.closedAt = new Date();
          if (status === "completed") updateDoc.completedAt = new Date();
        }

        if (!Object.keys(updateDoc).length) {
          return res.status(400).send({ message: "Nothing to update" });
        }

        const result = await tuitionsCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: updateDoc }
        );

        if (result.modifiedCount === 0) {
          return res.status(400).send({ message: "No changes applied" });
        }

        res.send({ message: "Tuition updated successfully" });
      } catch (err) {
        console.error("Patch tuition error:", err);
        res.status(500).send({ message: "Failed to update tuition" });
      }
    });

    // delete tuition
    app.delete("/tuitions/:id", verifyFBToken, async (req, res) => {
      try {
        const tuitionId = req.params.id;
        const email = req.decoded_email;

        const query = { _id: new ObjectId(tuitionId), email };

        const result = await tuitionsCollection.deleteOne(query);

        if (result.deletedCount === 1) {
          await applicationsCollection.deleteMany({
            tuitionId: new ObjectId(tuitionId),
          });

          res.send({ success: true, message: "Tuition deleted successfully." });
        } else {
          res.status(403).send({
            success: false,
            message: "Not authorized or tuition not found.",
          });
        }
      } catch (err) {
        console.error("Delete tuition error:", err);
        res
          .status(500)
          .send({ success: false, message: "Failed to delete tuition." });
      }
    });

    // post tuitions
    app.post("/tuitions", verifyFBToken, async (req, res) => {
      try {
        const {
          email,
          subjects,
          classLevel,
          district,
          location,
          days,
          time,
          duration,
          minBudget,
          maxBudget,
          description,
          mode,
          idempotencyKey,
        } = req.body;

        if (
          !email ||
          !subjects?.length ||
          !classLevel ||
          !mode ||
          !district ||
          !idempotencyKey
        ) {
          return res.status(400).send({
            success: false,
            message: "Missing required fields",
          });
        }
        const existing = await tuitionsCollection.findOne({
          idempotencyKey,
        });

        if (existing) {
          return res.send({
            success: true,
            message: "Tuition already posted (duplicate request prevented)",
            insertedId: existing._id,
          });
        }

        const userData = await usersCollection.findOne(
          { email },
          {
            projection: {
              _id: 1,
              name: 1,
              phone: 1,
              photoURL: 1,
            },
          }
        );

        if (!userData) {
          return res.status(404).send({
            success: false,
            message:
              "User not found in usersCollection . Tuitions cannot be posted",
          });
        }

        const tuitionRequest = {
          userId: userData._id,
          name: userData.name,
          email,
          phone: userData.phone || "",
          photoURL: userData.photoURL || "",
          classLevel,
          subjects,
          district,
          location,
          days,
          time,
          duration,
          minBudget,
          maxBudget,
          description,
          mode,
          postedAt: new Date(),
          status: "open",
          idempotencyKey,
        };
        const result = await tuitionsCollection.insertOne(tuitionRequest);
        res.send({
          success: true,
          message: "Tuition posted successfully",
          insertedId: result.insertedId,
        });
      } catch (err) {
        console.error("Tuition Post Error:", err);
        res.status(500).send({
          success: false,
          message: "Internal server error",
        });
      }
    });

    // Applications API
    // my applications
    app.get(
      "/applications/my-applications",
      verifyFBToken,
      async (req, res) => {
        try {
          const email = req.decoded_email;
          const page = Math.max(parseInt(req.query.page) || 1, 1);
          const limit = Math.min(parseInt(req.query.limit) || 10, 50);
          const skip = (page - 1) * limit;

          const user = await usersCollection.findOne(
            { email },
            { projection: { role: 1, _id: 1 } }
          );

          if (!user) {
            return res.status(404).send({ message: "User Not found" });
          }

          const tutor = await tutorsCollection.findOne(
            { email },
            { projection: { _id: 1 } }
          );

          let filter = {};
          if (user.role === "tutor") {
            filter = { tutorId: tutor._id };
          } else if (user.role === "student") {
            filter = { studentId: user._id };
          }

          const total = await applicationsCollection.countDocuments(filter);

          const applications = await applicationsCollection
            .find(filter, {
              projection: {
                tutorName: 1,
                tutorPhoto: 1,
                qualification: 1,
                institution: 1,
                experienceYears: 1,
                experienceMonths: 1,
                salary: 1,
                coverLetter: 1,
                location: 1,
                status: 1,
                tuitionTime: 1,
                days: 1,
                classLevel: 1,
                subjects: 1,
                appliedAt: 1,
                tutorId: 1,
                studentId: 1,
              },
            })
            .sort({ appliedAt: -1 })
            .skip(skip)
            .limit(limit)
            .toArray();

          res.send({
            applications,
            pagination: {
              total,
              page,
              limit,
              totalPages: Math.ceil(total / limit),
            },
          });
        } catch (err) {
          console.error("Fetch my applications error:", err);
          res.status(500).send({ message: "Failed to fetch applications" });
        }
      }
    );

    // getting application for a particular tuition
    app.get(
      "/applications/has-applied/:tuitionId",
      verifyFBToken,
      async (req, res) => {
        try {
          const email = req.decoded_email;
          const { tuitionId } = req.params;

          const user = await usersCollection.findOne(
            { email },
            { projection: { role: 1 } }
          );

          if (!user) {
            return res
              .status(404)
              .send({ message: "User not found", hasApplied: false });
          }

          if (user.role !== "tutor") {
            return res.send({ hasApplied: false, role: user.role });
          }
          const tutor = await tutorsCollection.findOne(
            { email },
            { projection: { _id: 1 } }
          );

          if (!tutor) {
            return res
              .status(404)
              .send({ message: "Tutor profile not found", hasApplied: false });
          }

          const exists = await applicationsCollection.findOne(
            { tuitionId: new ObjectId(tuitionId), tutorId: tutor._id },
            { projection: { _id: 1 } }
          );

          return res.send({ hasApplied: !!exists });
        } catch (err) {
          console.error("Has-applied error:", err);
          res.status(500).send({
            message: "Failed to check application status",
            hasApplied: false,
          });
        }
      }
    );
    // delete application
    app.delete("/applications/:id", verifyFBToken, async (req, res) => {
      try {
        const email = req.decoded_email;
        const { id } = req.params;

        const user = await usersCollection.findOne(
          { email },
          { projection: { _id: 1, role: 1 } }
        );
        const tutor = await tutorsCollection.findOne(
          { email },
          { projection: { _id: 1 } }
        );

        if (!user) {
          return res.status(404).send({ message: "User not found" });
        }

        // ownership condition
        const ownershipFilter =
          user.role === "tutor"
            ? { tutorId: tutor._id }
            : { studentId: user._id };

        const result = await applicationsCollection.deleteOne({
          _id: new ObjectId(id),
          status: { $in: ["pending", "rejected"] },
          ...ownershipFilter,
        });

        if (result.deletedCount === 0) {
          return res.status(403).send({
            message: "Cannot cancel this application",
          });
        }

        res.send({ message: "Application cancelled successfully" });
      } catch (err) {
        console.error("Cancel application error:", err);
        res.status(500).send({ message: "Failed to cancel application" });
      }
    });
    // updating application
    app.patch("/applications/:id", verifyFBToken, async (req, res) => {
      try {
        const applicationId = req.params.id;
        const { status } = req.body;

        if (!applicationId) {
          return res.status(400).send({ message: "Application id is missing" });
        }

        if (!["accepted", "rejected"].includes(status)) {
          return res.status(400).send({ message: "Invalid status value" });
        }

        const application = await applicationsCollection.findOne({
          _id: new ObjectId(applicationId),
        });

        if (!application) {
          return res.status(404).send({ message: "Application not found" });
        }

        if (status === "accepted") {
          const tuition = await tuitionsCollection.findOne({
            _id: application.tuitionId,
          });

          if (tuition?.status === "assigned") {
            return res
              .status(400)
              .send({ message: "Tuition already assigned" });
          }

          const tutor = await tutorsCollection.findOne({
            _id: application.tutorId,
          });

          if (!tutor) {
            return res.status(404).send({ message: "Tutor not found" });
          }

          await applicationsCollection.updateOne(
            { _id: new ObjectId(applicationId) },
            { $set: { status: "accepted" } }
          );

          await applicationsCollection.updateMany(
            {
              tuitionId: application.tuitionId,
              status: "pending",
              _id: { $ne: new ObjectId(applicationId) },
            },
            { $set: { status: "rejected" } }
          );

          await tuitionsCollection.updateOne(
            { _id: application.tuitionId },
            {
              $set: {
                status: "assigned",
                tutorId: application.tutorId,
                assignedApplicationId: application._id,
                tutorName: application.tutorName,
                tutorPhoto: application.tutorPhoto,
                tutorEmail: tutor.email,
                tutorPhone: tutor.phone,
                salary: application.salary,
                assignedAt: new Date(),
              },
            }
          );
          // notification to tutor
          if (tutor && tutor.email) {
            await notificationsCollection.insertOne({
              userEmail: tutor.email,
              type: "APPLICATION_ACCEPTED",
              title: "Application Accepted",
              message: `Your application for ${tuition?.studentName}'s tuition has been accepted`,
              link: `/dashboard/my-tuitions/tutor`,
              isRead: false,
              createdAt: new Date(),
            });
          }
          return res.send({
            message:
              "Application accepted, tuition assigned, other applications rejected",
          });
        }

        await applicationsCollection.updateOne(
          { _id: new ObjectId(applicationId) },
          { $set: { status: "rejected" } }
        );

        res.send({ message: "Application rejected successfully" });
      } catch (err) {
        console.error("Update application status error:", err);
        res
          .status(500)
          .send({ message: "Failed to update application status" });
      }
    });
    // posting application
    app.post("/applications", verifyFBToken, verifyTutor, async (req, res) => {
      try {
        const { tuitionId, salary, coverLetter } = req.body;
        const tutor = req.tutor;
        if (!tuitionId || !salary) {
          return res.status(400).send({ message: "Missing required fields" });
        }
        const tuition = await tuitionsCollection.findOne({
          _id: new ObjectId(tuitionId),
        });
        if (!tuition) {
          return res.status(404).send({ message: "Tuition not found" });
        }
        if (tuition.status !== "open") {
          return res
            .status(400)
            .send({ message: "Tuition is not open for application" });
        }
        if (tuition.userId === tutor._id.toString()) {
          return res
            .status(403)
            .send({ message: "You cannot apply to your own tuition" });
        }
        if (tuition.district !== tutor.district) {
          return res.status(403).send({
            message: `You can only apply to tuitions within your district (${tutor.district}).`,
          });
        }
        if (salary < tuition.minBudget || salary > tuition.maxBudget) {
          return res.status(400).send({
            message: `Salary must be between ${tuition.minBudget} and ${tuition.maxBudget}`,
          });
        }
        const alreadyApplied = await applicationsCollection.findOne({
          tuitionId: tuition._id,
          tutorId: tutor._id,
        });
        if (alreadyApplied) {
          return res
            .status(409)
            .send({ message: "You have already applied for this tuition" });
        }
        const application = {
          tuitionId: tuition._id,
          tutorId: tutor._id,
          studentId: tuition.userId,
          location: tuition.location,
          salary,
          coverLetter: coverLetter || "",
          tutorName: tutor.name,
          tutorPhoto: tutor.photoURL,
          qualification: tutor.qualification,
          institution: tutor.institution,
          experienceYears: tutor.experienceYears,
          experienceMonths: tutor.experienceMonths,
          status: "pending",
          tuitionTime: tuition.time,
          days: tuition.days,
          classLevel: tuition.classLevel,
          subjects: tuition.subjects,
          appliedAt: new Date(),
        };
        const result = await applicationsCollection.insertOne(application);
        const student = await usersCollection.findOne({
          _id: new ObjectId(tuition.userId),
        });
        if (student?.email) {
          await notificationsCollection.insertOne({
            userEmail: student.email,
            type: "NEW_APPLICATION",
            title: "New Tutor Application",
            message: `${tutor.name} has applied for your tuition`,
            link: `/dashboard/applications`,
            isRead: false,
            createdAt: new Date(),
          });
        }
        res.status(201).send({
          message: "Application submitted successfully",
          applicationId: result.insertedId,
        });
      } catch (err) {
        console.log("apply tuition error", err);
        res.status(500).send({ message: "Failed to apply for tuition" });
      }
    });

    // getting payments
    app.get("/payments", verifyFBToken, async (req, res) => {
      try {
        const email = req.decoded_email;
        const page = Math.max(parseInt(req.query.page) || 1, 1);
        const limit = Math.min(parseInt(req.query.limit) || 10, 50);
        const skip = (page - 1) * limit;
        const user = await usersCollection.findOne({ email });
        if (!user) {
          return res.status(401).send({ message: "User not found" });
        }
        let query = {};

        if (user.role === "student") {
          query.studentEmail = email;
        } else if (user.role === "tutor") {
          query.tutorEmail = email;
        } else if (user.role === "admin") {
          query = {};
        } else {
          return res.status(403).send({ message: "Unauthorized role" });
        }

        const total = await paymentsCollection.countDocuments(query);

        const payments = await paymentsCollection
          .find(query)
          .sort({ paidAt: -1 })
          .skip(skip)
          .limit(limit)
          .toArray();

        res.send({
          payments,
          pagination: {
            total,
            page,
            limit,
            totalPages: Math.ceil(total / limit),
          },
        });
      } catch (err) {
        console.error("Fetch payments error:", err);
        res.status(500).send({ message: "Failed to fetch payments" });
      }
    });

    // payment API
    app.post("/payment-checkout-session", verifyFBToken, async (req, res) => {
      try {
        const { tuitionId } = req.body;
        const emailFromToken = req.decoded_email;

        if (!tuitionId) {
          return res.status(400).send({ message: "Tuition id is required" });
        }

        const tuition = await tuitionsCollection.findOne({
          _id: new ObjectId(tuitionId),
        });

        if (!tuition) {
          return res.status(404).send({ message: "Tuition not found" });
        }

        if (tuition.email !== emailFromToken) {
          return res
            .status(403)
            .send({ message: "Unauthorized payment attempt" });
        }

        if (tuition.status !== "assigned") {
          return res
            .status(400)
            .send({ message: "Payment allowed only for assigned tuition" });
        }

        const session = await stripe.checkout.sessions.create({
          payment_method_types: ["card"],
          mode: "payment",
          customer_email: tuition.email,
          line_items: [
            {
              price_data: {
                currency: "bdt",
                product_data: {
                  name: `Tuition Fee - ${tuition.subjects.join(", ")}`,
                  description: `Tutor: ${tuition.tutorName} | ${tuition.days} days/week | ${tuition.time}`,
                },
                unit_amount: parseInt(tuition.salary) * 100,
              },
              quantity: 1,
            },
          ],

          metadata: {
            tuitionId: tuition._id.toString(),
            studentId: tuition.userId.toString(),
            tutorId: tuition.tutorId.toString(),
            assignedApplicationId:
              tuition.assignedApplicationId?.toString() || "",
            purpose: "tuition_payment",
          },

          success_url: `${process.env.CLIENT_URL}/dashboard/payment-success?session_id={CHECKOUT_SESSION_ID}`,
          cancel_url: `${process.env.CLIENT_URL}/dashboard/payment-failure`,
        });

        res.send({ url: session.url });
      } catch (err) {
        console.error("Create checkout session error:", err);
        res.status(500).send({ message: "Failed to create checkout session" });
      }
    });
    // payment success
    app.patch("/payment-success", verifyFBToken, async (req, res) => {
      try {
        const sessionId = req.query.session_id;
        if (!sessionId) {
          return res.status(400).send({ message: "Session id missing" });
        }
        const session = await stripe.checkout.sessions.retrieve(sessionId);
        if (session.customer_email !== req.decoded_email) {
          return res.status(403).send({ message: "Forbidden access" });
        }
        if (session.payment_status !== "paid") {
          return res.status(400).send({ message: "Payment not completed" });
        }
        const transactionId = session.payment_intent;
        const paymentExist = await paymentsCollection.findOne({
          transactionId,
        });
        if (paymentExist) {
          return res.send({
            message: "Payment already recorded",
            transactionId,
            tuitionId: paymentExist.tuitionId,
            paymentId: paymentExist._id,
          });
        }

        const tuitionId = session.metadata.tuitionId;
        const tuition = await tuitionsCollection.findOne({
          _id: new ObjectId(tuitionId),
        });
        if (!tuition) {
          return res.status(404).send({ message: "Tuition not found" });
        }
        await tuitionsCollection.updateOne(
          {
            _id: tuition._id,
          },
          {
            $set: {
              status: "ongoing",
              startedAt: new Date(),
            },
          }
        );
        const paymentInfo = {
          tuitionId: tuition._id,
          studentId: tuition.userId,
          tutorId: tuition.tutorId,
          applicationId: tuition.assignedApplicationId,
          transactionId,
          paidAt: new Date(),
          amount: session.amount_total / 100,
          salary: session.amount_total * 0.004,
          studentEmail: session.customer_email,
          tutorEmail: tuition.tutorEmail,
          paymentStatus: session.payment_status,
        };

        await paymentsCollection.updateOne(
          { transactionId },
          { $setOnInsert: paymentInfo },
          { upsert: true }
        );
        if (tuition.tutorId && tuition.tutorEmail) {
          const totalAmount = session.amount_total; 
          const platformFee = Math.round(totalAmount * 0.6);
          const tutorReceives = totalAmount - platformFee;

          await notificationsCollection.insertOne({
            userEmail: tuition.tutorEmail,
            type: "TUITION_STARTED",
            title: "Tuition Started",
            message: `Payment ৳${(totalAmount / 100).toFixed(
              2
            )} received from ${session.customer_email}. Platform fee: ৳${(
              platformFee / 100
            ).toFixed(2)}. Your earnings: ৳${(tutorReceives / 100).toFixed(
              2
            )}. Tuition is now ongoing.`,
            link: "/dashboard/my-tuitions/tutor",
            isRead: false,
            createdAt: new Date(),
          });
        }

        res.send({
          success: true,
          transactionId,
          tuitionId,
        });
      } catch (err) {
        console.error("Payment success error:", err);
        res.status(500).send({ message: "Payment verification failed" });
      }
    });

    // reviews API
    // latest reviews
    app.get("/latest-reviews", async (req, res) => {
      try {
        const projection = {
          _id: 1,
          studentName: 1,
          studentPhoto: 1,
          tutorName: 1,
          tutorPhoto: 1,
          review: 1,
          rating: 1,
          postedAt: 1,
        };

        const latestReviews = await reviewsCollection
          .find({}, { projection })
          .sort({ postedAt: -1 })
          .limit(6)
          .toArray();

        res.send({ reviews: latestReviews });
      } catch (err) {
        console.error("Fetch latest reviews error:", err);
        res.status(500).send({ message: "Failed to fetch latest reviews" });
      }
    });
    // getting reviews for tutors
    app.get("/tutor-reviews", verifyFBToken, verifyTutor, async (req, res) => {
      try {
        const email = req.decoded_email;
        let { page = 1, limit = 10 } = req.query;
        const pageNumber = parseInt(page);
        const limitNumber = Math.min(parseInt(limit), 10);
        const skip = (pageNumber - 1) * limitNumber;
        const tutor = await tutorsCollection.findOne({ email });
        if (!tutor) {
          return res.status(400).send({ message: "Tutor not found" });
        }
        const tutorId = tutor._id;
        const projection = {
          _id: 1,
          tuitionId: 1,
          rating: 1,
          tutorId: 1,
          studentId: 1,
          review: 1,
          postedAt: 1,
          studentName: 1,
          studentPhoto: 1,
          subjects: 1,
        };
        const [reviews, total] = await Promise.all([
          reviewsCollection
            .find({ tutorId }, { projection })
            .sort({ postedAt: -1 })
            .skip(skip)
            .limit(limitNumber)
            .toArray(),

          reviewsCollection.countDocuments({ tutorId }),
        ]);
        res.send({
          reviews,
          page: pageNumber,
          limit: limitNumber,
          total,
          totalPages: Math.ceil(total / limitNumber),
        });
      } catch (err) {
        console.error("Tutor tuitions fetch error:", err);
        res.status(500).send({ message: "Failed to fetch tutor tuitions" });
      }
    });

    // posting
    app.post("/reviews", verifyFBToken, async (req, res) => {
      try {
        const email = req.decoded_email;
        const { tuitionId, rating, review } = req.body;

        if (!tuitionId || !rating) {
          return res.status(400).send({ message: "Missing required fields" });
        }

        if (rating < 1 || rating > 5) {
          return res
            .status(400)
            .send({ message: "Rating must be between 1 to 5" });
        }
        const student = await usersCollection.findOne(
          { email },
          { projection: { _id: 1, role: 1, photoURL: 1, name: 1 } }
        );

        if (!student || student.role !== "student") {
          return res
            .status(403)
            .send({ message: "Only students can post reviews" });
        }
        const tuition = await tuitionsCollection.findOne({
          _id: new ObjectId(tuitionId),
        });

        if (!tuition) {
          return res.status(404).send({ message: "Tuition not found" });
        }
        if (tuition.userId.toString() !== student._id.toString()) {
          return res.status(403).send({ message: "Unauthorized access" });
        }
        if (tuition.status !== "completed") {
          return res
            .status(400)
            .send({ message: "Tuition must be completed to review" });
        }
        if (!tuition.tutorId) {
          return res
            .status(400)
            .send({ message: "No tutor assigned to this tuition" });
        }

        if (tuition.reviewed === true) {
          return res.status(409).send({ message: "Review already submitted" });
        }
        const reviewDoc = {
          tuitionId: tuition._id,
          studentId: tuition.userId,
          tutorId: tuition.tutorId,
          studentName: student.name,
          studentPhoto: student.photoURL,
          rating: Number(rating),
          review: review?.trim() || "",
          tutorPhoto: tuition.tutorPhoto,
          tutorName: tuition.tutorName,
          postedAt: new Date(),
          subjects: tuition.subjects,
        };

        const result = await reviewsCollection.insertOne(reviewDoc);
        await tutorsCollection.updateOne(
          { _id: tuition.tutorId },
          {
            $inc: {
              ratingCount: 1,
              ratingSum: Number(rating),
            },
          }
        );
        await tuitionsCollection.updateOne(
          { _id: tuition._id },
          {
            $set: {
              reviewed: true,
              reviewedAt: new Date(),
              reviewId: result.insertedId,
            },
          }
        );
        const tutor = await tutorsCollection.findOne({ _id: tuition.tutorId });
        if (tutor?.email) {
          await notificationsCollection.insertOne({
            userEmail: tutor.email,
            type: "NEW_REVIEW",
            title: "New Review",
            message: `${student.name} has posted a review for your tuition`,
            link: `/dashboard/review`,
            isRead: false,
            createdAt: new Date(),
          });
        }

        res.status(201).send({
          message: "Review submitted successfully",
          reviewId: result.insertedId,
        });
      } catch (err) {
        console.error("Post review error:", err);
        res.status(500).send({ message: "Failed to submit review" });
      }
    });

    // conversations related API
    // get
    app.get("/conversations", verifyFBToken, async (req, res) => {
      try {
        const email = req.decoded_email;

        const user = await usersCollection.findOne(
          { email },
          { projection: { _id: 1, role: 1, name: 1, photoURL: 1 } }
        );

        if (!user) {
          return res.status(401).send({ message: "Unauthorized" });
        }

        let filter = {};

        if (user.role === "tutor") {
          const tutor = await tutorsCollection.findOne(
            { email },
            { projection: { _id: 1 } }
          );

          if (!tutor) {
            return res.status(403).send({ message: "Tutor profile not found" });
          }

          filter = { tutorId: tutor._id };
        } else {
          filter = { studentId: user._id };
        }

        // console.log("User role:", user.role);
        // console.log("Mongo filter:", filter);

        const conversations = await conversationCollection
          .find(filter)
          .sort({ lastMessageAt: -1 })
          .toArray();

        const mappedConvos = conversations.map((convo) => ({
          ...convo,
          otherName:
            user.role === "tutor" ? convo.studentName : convo.otherName,
          otherPhoto:
            user.role === "tutor" ? convo.studentPhoto : convo.otherPhoto,
        }));

        console.log("Conversations found:", mappedConvos.length);

        res.send(mappedConvos);
      } catch (err) {
        console.error("Get conversations error:", err);
        res.status(500).send({ message: "Failed to load conversations" });
      }
    });

    app.get("/conversations/:id", async (req, res) => {
      try {
        const { id } = req.params;

        if (!ObjectId.isValid(id)) {
          return res.status(400).send({ message: "Invalid conversation ID" });
        }

        const conversation = await conversationCollection.findOne({
          _id: new ObjectId(id),
        });

        if (!conversation) {
          return res.status(404).send({ message: "Conversation not found" });
        }

        res.send(conversation);
      } catch (err) {
        console.error("Get conversation error:", err);
        res.status(500).send({ message: "Server error" });
      }
    });
    // post
    app.post("/conversations", verifyFBToken, async (req, res) => {
      try {
        const email = req.decoded_email;
        const { tutorId } = req.body;

        if (!tutorId) {
          return res.status(400).send({ message: "TutorId is required" });
        }
        const tutor = await tutorsCollection.findOne({
          _id: new ObjectId(tutorId),
        });
        if (!tutor) {
          return res.status(400).send({ message: "Tutor not found" });
        }
        const student = await usersCollection.findOne({ email });
        if (!student || student.role !== "student") {
          return res
            .status(403)
            .send({ message: "Only students can contact tutors" });
        }
        const existing = await conversationCollection.findOne({
          tutorId: new ObjectId(tutorId),
          studentId: student._id,
        });
        if (existing) {
          return res.send(existing);
        }
        const conversationDoc = {
          tutorId: new ObjectId(tutorId),
          studentId: student._id,
          lastMessage: "",
          lastMessageAt: new Date(),
          unreadForTutor: 0,
          unreadForStudent: 0,
          createdAt: new Date(),
          otherName: tutor.name,
          otherPhoto: tutor.photoURL,
          studentPhoto: student.photoURL,
          studentName: student.name,
        };
        const result = await conversationCollection.insertOne(conversationDoc);
        if (tutor?.email) {
          //console.log(tutor.email)
          await notificationsCollection.insertOne({
            userEmail: tutor.email,
            type: "NEW_MESSAGE",
            title: "New Conversation",
            message: `${student.name} started a conversation with you`,
            link: `/dashboard/messages/${result.insertedId}`,
            isRead: false,
            createdAt: new Date(),
          });
        }

        res.status(201).send({
          _id: result.insertedId,
          ...conversationDoc,
        });
      } catch (err) {
        console.error("Create conversation error:", err);
        res.status(500).send({ message: "Failed to create conversation" });
      }
    });
    app.post("/tutor/conversations", verifyFBToken, async (req, res) => {
      try {
        const email = req.decoded_email;
        const { studentId } = req.body;

        if (!studentId)
          return res.status(400).send({ message: "Student ID is required" });

        const tutor = await tutorsCollection.findOne(
          { email },
          { projection: { _id: 1, name: 1, photoURL: 1 } }
        );

        if (!tutor)
          return res
            .status(403)
            .send({ message: "Only tutors can start conversation" });

        const student = await usersCollection.findOne({
          _id: new ObjectId(studentId),
          role: "student",
        });

        if (!student)
          return res.status(404).send({ message: "Student not found" });

        const existing = await conversationCollection.findOne({
          tutorId: tutor._id,
          studentId: student._id,
        });

        if (existing) return res.send(existing);

        const conversationDoc = {
          tutorId: tutor._id,
          studentId: student._id,
          lastMessage: "",
          lastMessageAt: new Date(),
          unreadForTutor: 0,
          unreadForStudent: 0,
          createdAt: new Date(),
          studentName: student.name,
          studentPhoto: student.photoURL,
          otherName: tutor.name,
          otherPhoto: tutor.photoURL,
        };

        const result = await conversationCollection.insertOne(conversationDoc);
        if (student?.email) {
          await notificationsCollection.insertOne({
            userEmail: student.email,
            type: "NEW_MESSAGE",
            title: "New Conversation",
            message: `${tutor.name} started a conversation with you`,
            link: `/dashboard/messages/${result.insertedId}`,
            isRead: false,
            createdAt: new Date(),
          });
        }
        res.status(201).send({ _id: result.insertedId, ...conversationDoc });
      } catch (err) {
        console.error("Tutor create conversation error:", err);
        res.status(500).send({ message: "Failed to create conversation" });
      }
    });
    // messages
    app.get("/messages/:conversationId", verifyFBToken, async (req, res) => {
      try {
        const email = req.decoded_email;
        const { conversationId } = req.params;

        if (!ObjectId.isValid(conversationId)) {
          return res.status(400).send({ message: "Invalid conversation ID" });
        }

        const user = await usersCollection.findOne(
          { email },
          { projection: { _id: 1, role: 1 } }
        );

        if (!user) {
          return res.status(401).send({ message: "Unauthorized" });
        }

        const conversation = await conversationCollection.findOne({
          _id: new ObjectId(conversationId),
        });

        if (!conversation) {
          return res.status(404).send({ message: "Conversation not found" });
        }

        let isAllowed = false;

        if (user.role === "student") {
          isAllowed = conversation.studentId.toString() === user._id.toString();
        }

        if (user.role === "tutor") {
          const tutor = await tutorsCollection.findOne({ email });

          if (!tutor) {
            return res.status(403).send({ message: "Tutor profile not found" });
          }

          isAllowed = conversation.tutorId.toString() === tutor._id.toString();
        }

        if (!isAllowed) {
          return res.status(403).send({ message: "Unauthorized access" });
        }

        const messages = await messagesCollection
          .find({ conversationId: conversation._id })
          .sort({ createdAt: 1 })
          .toArray();

        res.send(messages);
      } catch (err) {
        console.error("Get messages error:", err);
        res.status(500).send({ message: "Failed to load messages" });
      }
    });

    // send message
    app.post("/messages", verifyFBToken, async (req, res) => {
      try {
        const email = req.decoded_email;
        const { conversationId, text } = req.body;

        if (!conversationId || !text?.trim()) {
          return res.status(400).send({ message: "Message text required" });
        }

        const user = await usersCollection.findOne(
          { email },
          { projection: { _id: 1, role: 1 } }
        );

        if (!user) {
          return res.status(401).send({ message: "Unauthorized" });
        }

        const conversation = await conversationCollection.findOne({
          _id: new ObjectId(conversationId),
        });

        if (!conversation) {
          return res.status(404).send({ message: "Conversation not found" });
        }

        let senderId;
        let isAllowed = false;

        if (user.role === "student") {
          isAllowed = conversation.studentId.toString() === user._id.toString();
          senderId = user._id;
        }

        if (user.role === "tutor") {
          const tutor = await tutorsCollection.findOne({ email });

          if (!tutor) {
            return res.status(403).send({ message: "Tutor profile not found" });
          }

          isAllowed = conversation.tutorId.toString() === tutor._id.toString();
          senderId = tutor._id;
        }

        if (!isAllowed) {
          return res.status(403).send({ message: "Unauthorized access" });
        }

        const messageDoc = {
          conversationId: conversation._id,
          senderId, // IMPORTANT FIX
          senderEmail: email,
          senderRole: user.role,
          text: text.trim(),
          seen: false,
          createdAt: new Date(),
        };

        await messagesCollection.insertOne(messageDoc);

        const unreadField =
          user.role === "student" ? "unreadForTutor" : "unreadForStudent";

        await conversationCollection.updateOne(
          { _id: conversation._id },
          {
            $set: {
              lastMessage: text.trim(),
              lastMessageAt: new Date(),
            },
            $inc: {
              [unreadField]: 1,
            },
          }
        );
        let recipientEmail;
        if (user.role === "student") {
          const tutor = await tutorsCollection.findOne({
            _id: conversation.tutorId,
          });
          recipientEmail = tutor?.email;
        } else if (user.role === "tutor") {
          const student = await usersCollection.findOne({
            _id: conversation.studentId,
          });
          recipientEmail = student?.email;
        }
        if (recipientEmail) {
          await notificationsCollection.insertOne({
            userEmail: recipientEmail,
            type: "NEW_MESSAGE",
            title: "New Message",
            message: `${
              user.role === "student" ? student.name : tutor.name
            } sent you a message`,
            link: `/dashboard/messages/${conversation._id}`,
            isRead: false,
            createdAt: new Date(),
          });
        }
        res.status(201).send(messageDoc);
      } catch (err) {
        console.error("Send message error:", err);
        res.status(500).send({ message: "Failed to send message" });
      }
    });
    app.patch(
      "/messages/seen/:conversationId",
      verifyFBToken,
      async (req, res) => {
        try {
          const email = req.decoded_email;
          const { conversationId } = req.params;

          const user = await usersCollection.findOne(
            { email },
            { projection: { _id: 1, role: 1 } }
          );

          if (!user) {
            return res.status(401).send({ message: "Unauthorized" });
          }

          const conversation = await conversationCollection.findOne({
            _id: new ObjectId(conversationId),
          });

          if (!conversation) {
            return res.status(404).send({ message: "Conversation not found" });
          }

          let isAllowed = false;
          let viewerId;

          if (user.role === "student") {
            isAllowed =
              conversation.studentId.toString() === user._id.toString();
            viewerId = user._id;
          }

          if (user.role === "tutor") {
            const tutor = await tutorsCollection.findOne({ email });

            if (!tutor) {
              return res
                .status(403)
                .send({ message: "Tutor profile not found" });
            }

            isAllowed =
              conversation.tutorId.toString() === tutor._id.toString();
            viewerId = tutor._id;
          }

          if (!isAllowed) {
            return res.status(403).send({ message: "Unauthorized access" });
          }

          const unreadField =
            user.role === "student" ? "unreadForStudent" : "unreadForTutor";

          await conversationCollection.updateOne(
            { _id: conversation._id },
            { $set: { [unreadField]: 0 } }
          );

          await messagesCollection.updateMany(
            {
              conversationId: conversation._id,
              senderId: { $ne: viewerId }, // IMPORTANT FIX
              seen: false,
            },
            { $set: { seen: true } }
          );

          res.send({ message: "Messages marked as seen" });
        } catch (err) {
          console.error("Seen message error:", err);
          res.status(500).send({ message: "Failed to mark messages as seen" });
        }
      }
    );
    // notifications

    app.get("/notifications", verifyFBToken, async (req, res) => {
      try {
        const email = req.decoded_email;
        const notifications = await notificationsCollection
          .find({ userEmail: email })
          .sort({ createdAt: -1 })
          .toArray();

        res.send(notifications);
      } catch (err) {
        console.error("Fetch notifications error:", err);
        res.status(500).send({ message: "Failed to fetch notifications" });
      }
    });
    // mark as read
    app.patch("/notifications/:id/read", verifyFBToken, async (req, res) => {
      try {
        const email = req.decoded_email;
        const { id } = req.params;

        const result = await notificationsCollection.updateOne(
          { _id: new ObjectId(id), userEmail: email },
          { $set: { isRead: true } }
        );

        if (result.matchedCount === 0) {
          return res.status(404).send({ message: "Notification not found" });
        }

        res.send({ success: true, modifiedCount: result.modifiedCount });
      } catch (err) {
        console.error("Mark notification read error:", err);
        res.status(500).send({ message: "Failed to update notification" });
      }
    });
    // mark all read
    app.patch("/notifications/read-all", verifyFBToken, async (req, res) => {
      try {
        const email = req.decoded_email;

        const result = await notificationsCollection.updateMany(
          { userEmail: email, isRead: false },
          { $set: { isRead: true } }
        );

        res.send({ success: true, modifiedCount: result.modifiedCount });
      } catch (err) {
        console.error("Mark all notifications read error:", err);
        res.status(500).send({ message: "Failed to update notifications" });
      }
    });

    await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
  } finally {
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("ETuitionBD Backend Service is running!");
});

app.listen(port, () => {
  console.log(`meow ${port}`);
});
module.exports = app;
