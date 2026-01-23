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


const { MongoClient, ServerApiVersion } = require('mongodb');
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