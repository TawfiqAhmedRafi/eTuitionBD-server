require("dotenv").config();
const express = require("express");
const cors = require("cors");
const app = express();
const { MongoClient, ServerApiVersion } = require("mongodb");
const port = process.env.PORT || 3000;
const bcrypt = require("bcrypt");

// middleware
app.use(express.json());
app.use(cors());
const saltRounds = 10;

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

    //  users API

    // Get all users
    app.get("/users",  async (req, res) => {
      try {
        const { page = 1, limit = 10, email } = req.query;

        const pageNumber = parseInt(page);
        const limitNumber = parseInt(limit);

        const query = {};
        if (email) query.email = email;

        const totalUsers = await usersCollection.countDocuments(query);

        // Paginated fetch
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
    // get tutors
    app.get("/tutors", async (req, res) => {
      try {
        const { email, page = 1, limit = 10 } = req.query;

        const pageNumber = parseInt(page);
        const limitNumber = parseInt(limit);

        const query = email ? { email } : {};

        const skip = (pageNumber - 1) * limitNumber;

        const tutors = await tutorsCollection
          .find(query)
          .sort({ submittedAt: -1 }) 
          .skip(skip)
          .limit(limitNumber)
          .toArray();

        const totalTutors = await tutorsCollection.countDocuments(query);

        res.send({
          tutors,
          page: pageNumber,
          limit: limitNumber,
          totalPages: Math.ceil(totalTutors / limitNumber),
          totalTutors,
        });
      } catch (error) {
        console.error(error);
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
      } catch (error) {
        console.error("Tutor Application Error:", error);
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
