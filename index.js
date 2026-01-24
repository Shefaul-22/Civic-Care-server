const express = require('express');
const app = express();
const cors = require('cors')

const port = 3000;
require('dotenv').config();


app.get('/', (req, res) => {
    res.send("CivicCare is running")
})

const admin = require("firebase-admin");


const decoded = Buffer.from(process.env.FB_SERVICE_KEY, 'base64').toString('utf8')
const serviceAccount = JSON.parse(decoded);

admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
});

const verifyFBToken = async (req, res, next) => {
    const token = req.headers.authorization;
    // console.log(token);

    if (!token) {
        return res.status(401).send({ message: 'unauthorized access' })
    }

    try {
        const idToken = token.split(' ')[1];
        const decoded = await admin.auth().verifyIdToken(idToken);
        console.log('decoded in the token', decoded);
        req.decoded_email = decoded.email;
        next();
    }
    catch (err) {
        return res.status(401).send({ message: 'unauthorized access' })
    }


}

const verifyAdmin = async (req, res, next) => {
    const token = req.headers.authorization;
    if (!token) return res.status(401).send({ message: 'Unauthorized access' });

    try {
        const idToken = token.split(' ')[1];
        const decoded = await admin.auth().verifyIdToken(idToken);
        req.decoded_email = decoded.email;

        // check role in usersCollection
        const user = await usersCollection.findOne({ email: decoded.email });
        if (!user || user.role !== 'admin') {
            return res.status(403).send({ message: 'Forbidden: Admins only' });
        }

        req.user = user; 
        next();
    } catch (err) {
        console.error(err);
        res.status(401).send({ message: 'Unauthorized access' });
    }
};



const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@crud-server-practices.rbtbow5.mongodb.net/?appName=crud-server-practices`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

// Middleware 
app.use(cors())
app.use(express.json())

async function run() {
    try {
        // Connect the client to the server	(optional starting in v4.7)
        await client.connect();

        const db = client.db('civic-care-db');
        const usersCollection = db.collection('users')
        const issuesCollection = db.collection('issues')


        app.post('/users', async (req, res) => {
            const user = req.body;
            user.role = "freeuser";
            user.createdAt = new Date();
            const email = user.email;
            const userExists = await usersCollection.findOne({ email })

            if (userExists) {
                return res.send({ message: 'user exists' })
            }

            const result = await usersCollection.insertOne(user);
            res.send(result);

        })

        app.patch('/users/premium', async (req, res) => {
            const email = req.body.email;


            const filter = { email: email };

            const updateQuery = {
                $set: {
                    role: 'premium',
                    premiumAt: new Date()
                }
            };


            const result = await usersCollection.updateOne(filter, updateQuery);


            if (result.matchedCount === 0) {
                return res.status(404).send({ message: "User not found" });
            }

            res.send({ message: "User upgraded to premium", result });

        });

        // Get current user's issue count
        app.get('/users/:email/issues/count', async (req, res) => {
            try {
                const email = req.params.email;
                const count = await issuesCollection.countDocuments({ senderEmail: email });

                //  get role
                const user = await usersCollection.findOne({ email });

                if (!user) return res.status(404).send({ message: "User not found" });

                res.send({ count, role: user.role });
            } catch (error) {
                console.error(error);
                res.status(500).send({ message: "Failed to get issue count" });
            }
        });



        // Issues related api
        app.post('/issues', async (req, res) => {
            try {
                const issue = req.body;
                const email = issue.senderEmail;

                //find user
                const user = await usersCollection.findOne({ email });

                if (!user) {
                    return res.status(404).send({ message: 'User not found' });
                }

                // count user's total submitted issues
                const issueCount = await issuesCollection.countDocuments({
                    senderEmail: email
                });

                // Free user limit check
                if (user.role !== 'premium' && issueCount >= 3) {
                    return res.status(403).send({
                        message: 'Free user issue limit reached',
                        limitReached: true
                    });
                }

                // create issue
                issue.createdAt = new Date();
                issue.priority = 'low';
                issue.status = 'pending';

                const result = await issuesCollection.insertOne(issue);
                res.send(result);

            } catch (error) {
                console.error(error);
                res.status(500).send({ message: 'Failed to create issue' });
            }
        });

        app.get('/issues/:id', async (req, res) => {
            try {
                const { id } = req.params;
                const issue = await issuesCollection.findOne({ _id: new ObjectId(id) });
                if (!issue) return res.status(404).send({ message: "Issue not found" });
                res.send(issue);
            } catch (error) {
                console.error(error);
                res.status(500).send({ message: "Failed to fetch issue" });
            }
        });



        // Edit issue (only pending issues by the creator)
        app.patch('/issues/:id', async (req, res) => {
            try {
                const { id } = req.params;
                const updates = req.body;
                const userEmail = updates.editorEmail;

                // find the issue
                const issue = await issuesCollection.findOne({ _id: new ObjectId(id) });
                if (!issue) return res.status(404).send({ message: "Issue not found" });

                // check if the user is the creator and issue is pending
                if (issue.senderEmail !== userEmail) {
                    return res.status(403).send({ message: "You can only edit your own issues" });
                }
                if (issue.status !== "pending") {
                    return res.status(403).send({ message: "Only pending issues can be edited" });
                }


                const result = await issuesCollection.updateOne(
                    { _id: new ObjectId(id) },
                    { $set: updates }
                );

                res.send(result);

            } catch (error) {
                console.error(error);
                res.status(500).send({ message: "Failed to update issue" });
            }
        });

        // Boost issue priority
        app.post('/issues/:id/boost', async (req, res) => {
            try {
                const { id } = req.params;
                const { boostedBy } = req.body;

                const issue = await issuesCollection.findOne({ _id: new ObjectId(id) });
                if (!issue) return res.status(404).send({ message: "Issue not found" });

                if (issue.priority === "high") {
                    return res.status(400).send({ message: "Issue already boosted" });
                }

                const boostEntry = {
                    status: "Pending",
                    message: "Issue priority boosted",
                    updatedBy: boostedBy,
                    timestamp: new Date()
                };

                const result = await issuesCollection.updateOne(
                    { _id: new ObjectId(id) },
                    { $set: { priority: "high" }, $push: { timeline: boostEntry } }
                );

                res.send(result);

            } catch (error) {
                console.error(error);
                res.status(500).send({ message: "Failed to boost issue" });
            }
        });

        app.delete('/issues/:id', async (req, res) => {
            try {
                const { id } = req.params;
                const { userEmail } = req.body;

                const issue = await issuesCollection.findOne({ _id: new ObjectId(id) });
                if (!issue) return res.status(404).send({ message: "Issue not found" });

                if (issue.senderEmail !== userEmail) {
                    return res.status(403).send({ message: "You can only delete your own issues" });
                }

                await issuesCollection.deleteOne({ _id: new ObjectId(id) });

                res.send({ message: "Issue deleted successfully" });

            } catch (error) {
                console.error(error);
                res.status(500).send({ message: "Failed to delete issue" });
            }
        });

        // Staffs related api

        // app.post('/staffs', async (req, res) => {

        //     const staffs = req.body;

        //     const email = staffs.email;
        //     console.log(email);

        //     const existingStaff = await usersCollection.findOne({email});

        //     if (existingStaff) {
        //         return res.send({
        //             success: false,
        //             message: "You have already applied with this email"
        //         });
        //     }
        //     staffs.status = "pending"
        //     staffs.role = "user"
        //     staffs.createdAt = new Date();

        //     const result = await usersCollection.insertOne(staffs)
        //     res.send(result);
        // })

        // -- Admin related apis ---------

        // Add new staff
        app.post('/admin/staffs', async (req, res) => {
            try {
                const { name, email, password, phone, photo } = req.body;
                const normalizedEmail = email.trim().toLowerCase();

                //  Duplicate check
                const existingStaff = await usersCollection.findOne({ email: normalizedEmail });
                if (existingStaff) {
                    return res.send({ success: false, message: "Staff already exists" });
                }

                // create staff account using firebase
                const firebaseUser = await admin.auth().createUser({
                    email: normalizedEmail,
                    password,
                    displayName: name,
                    photoURL: photo,
                });


                const staff = {
                    uid: firebaseUser.uid,
                    name,
                    email: normalizedEmail,
                    phone,
                    photo,
                    role: "staff",
                    createdAt: new Date(),
                };

                const result = await usersCollection.insertOne(staff);

                res.send({ success: true, insertedId: result.insertedId });
            } catch (error) {
                console.error(error);
                res.status(500).send({ success: false, message: error.message });
            }
        });

        // Get all staff
        app.get('/admin/staffs', async (req, res) => {
            try {
                const staffs = await usersCollection.find({ role: "staff" }).toArray();
                res.send(staffs);
            } catch (err) {
                res.status(500).send({ success: false, message: err.message });
            }
        });

        // update staff info
        app.patch('/admin/staffs/:id', async (req, res) => {
            try {
                const id = req.params.id;
                const updateData = req.body;

                const result = await usersCollection.updateOne(
                    { _id: new ObjectId(id), role: "staff" },
                    { $set: updateData }
                );

                res.send(result);
            } catch (err) {
                res.status(500).send({ success: false, message: err.message });
            }
        });

        // Delete staff
        app.delete('/admin/staffs/:id', async (req, res) => {
            try {
                const id = req.params.id;

                // Find staff by using _id
                const staff = await usersCollection.findOne({ _id: new ObjectId(id), role: "staff" });
                if (!staff) return res.status(404).send({ success: false, message: "Staff not found" });

                // Delete Firebase Auth user
                await admin.auth().deleteUser(staff.uid);

                // Delete from usersCollection
                await usersCollection.deleteOne({ _id: new ObjectId(id) });

                res.send({ success: true });
            } catch (err) {
                res.status(500).send({ success: false, message: err.message });
            }
        });






        // Send a ping to confirm a successful connection
        await client.db("admin").command({ ping: 1 });
        console.log("Pinged your deployment. You successfully connected to MongoDB!");
    } finally {
        // Ensures that the client will close when you finish/error
        // await client.close();
    }
}
run().catch(console.dir);


app.listen(port, () => {
    console.log(`CivicCare server is running on port ${port}`);
})