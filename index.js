require("dotenv").config();
const express = require("express");
const cors = require("cors");
const app = express();
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const port = process.env.PORT || 3000;
const bcrypt = require("bcrypt");
const admin = require("firebase-admin");

const serviceAccount = require("./etuition-firebase-adminsdk.json");

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
    console.log("Decoded Firebase token:", decoded);
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

    // indexing
    await tuitionsCollection.createIndex(
      { idempotencyKey: 1 },
      { unique: true }
    );
    await tuitionsCollection.createIndex({ postedAt: -1 });
    await tuitionsCollection.createIndex({ subjects: 1 });
    await tuitionsCollection.createIndex({ district: 1 });
    await tuitionsCollection.createIndex({ minBudget: 1 });
    await tuitionsCollection.createIndex({ maxBudget: 1 });

    //  users API

    // Get all users
    app.get("/users", async (req, res) => {
      try {
        const { page = 1, limit = 10, email } = req.query;

        const pageNumber = parseInt(page);
        const limitNumber = parseInt(limit);

        const query = {};
        if (email) query.email = email;

        const totalUsers = await usersCollection.countDocuments(query);

        const users = await usersCollection
          .find(query)
          .skip((pageNumber - 1) * limitNumber)
          .limit(limitNumber)
          .toArray();

        res.send({
          page: pageNumber,
          limit: limitNumber,
          totalUsers,
          totalPages: Math.ceil(totalUsers / limitNumber),
          users,
        });
      } catch (error) {
        console.error(error);
        res.status(500).send({ message: "Failed to fetch users" });
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
    // get all tutors
    app.get("/tutors", async (req, res) => {
      try {
        const { email, status, page = 1, limit = 10 } = req.query;
        const pageNumber = Number(page);
        const limitNumber = Number(limit);
        const skip = (pageNumber - 1) * limitNumber;
        const query = {};
        if (email) query.email = email;
        if (status) query.status = status;
        const sortQuery = {
          status: 1,
          submittedAt: -1,
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

    // posting tutors
    app.post("/tutors", async (req, res) => {
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
        const {
          page = 1,
          limit = 10,
          subject,
          district,
          location,
          sortBy = "date",
          order = "desc",
        } = req.query;

        const pageNumber = parseInt(page);
        const limitNumber = parseInt(limit);
        const skip = (pageNumber - 1) * limitNumber;

        // 🔍 Build query
        const query = { status: "open" };

        if (subject) {
          query.subjects = { $regex: subject, $options: "i" };
        }

        if (district) {
          query.district = { $regex: district, $options: "i" };
        }

        if (location) {
          query.location = { $regex: location, $options: "i" };
        }

        let sortQuery = { postedAt: -1 };

        if (sortBy === "minBudget") {
          sortQuery = { minBudget: order === "asc" ? 1 : -1 };
        } else if (sortBy === "maxBudget") {
          sortQuery = { maxBudget: order === "asc" ? 1 : -1 };
        } else if (sortBy === "date") {
          sortQuery = { postedAt: order === "asc" ? 1 : -1 };
        }

        const total = await tuitionsCollection.countDocuments(query);

        const tuitions = await tuitionsCollection
          .find(query)
          .sort(sortQuery)
          .skip(skip)
          .limit(limitNumber)
          .toArray();
        res.send({
          tuitions,
          page: pageNumber,
          limit: limitNumber,
          totalPages: Math.ceil(total / limitNumber),
          totalTuitions: total,
        });
      } catch (err) {
        console.error("Get tuitions error:", err);
        res.status(500).send({ message: "Failed to fetch tuitions" });
      }
    });

    // post tuitions
    app.post("/tuitions", async (req, res) => {
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
