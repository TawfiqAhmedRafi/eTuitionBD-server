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
    app.get("/users", async (req, res) => {
      try {
        const users = await usersCollection.find().toArray();
        res.send(users);
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
