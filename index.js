const express = require('express');
const app = express();
const cors = require('cors')

const port = process.env.PORT || 3000;
require('dotenv').config();


const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);



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
        // console.log('decoded in the token', decoded);
        req.decoded_email = decoded.email;
        next();
    }
    catch (err) {
        return res.status(401).send({ message: 'unauthorized access' })
    }


}



const crypto = require("crypto");

function generateTrackingId() {

    const prefix = "CVCPS";  // brand
    const date = new Date().toISOString().slice(0, 10).replace(/-/g, "");
    const random = crypto.randomBytes(3).toString("hex").toUpperCase();
    return `${prefix}-${date}-${random}`;
}

// console.log(generateTrackingId());


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
        const paymentCollection = db.collection('payments');


        // prevent duplicate user 

        await usersCollection.createIndex(
            { email: 1 },
            { unique: true }
        );

        await usersCollection.createIndex(
            { uid: 1 },
            { unique: true }
        );

        // prevent payment duplicate entry
        await paymentCollection.createIndex(
            { transactionId: 1 },
            { unique: true }
        );


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

        const verifyStaff = async (req, res, next) => {


            const token = req.headers.authorization;
            if (!token) return res.status(401).send({ message: 'Unauthorized access' });

            try {
                const idToken = token.split(' ')[1];
                const decoded = await admin.auth().verifyIdToken(idToken);
                req.decoded_email = decoded.email;

                // check role in usersCollection
                const user = await usersCollection.findOne({ email: decoded.email });

                if (!user || user.role !== 'staff') {
                    return res.status(403).send({ message: 'Forbidden: Staff only' });
                }

                req.user = user;
                next();


            } catch (err) {
                console.error(err);
                res.status(401).send({ message: 'Unauthorized access' });
            }
        };


        const verifyBlockedUser = async (req, res, next) => {
            try {
                const token = req.headers.authorization;
                if (!token) return res.status(401).send({ message: "Unauthorized" });

                const idToken = token.split(" ")[1];
                const decoded = await admin.auth().verifyIdToken(idToken);
                const email = decoded.email;

                // Find user in DB
                const user = await usersCollection.findOne({ email });

                if (!user) return res.status(404).send({ message: "User not found" });

                // Check if blocked
                if (user.userStatus === "blocked") {
                    return res.status(403).send({ message: "User is blocked" });
                }

                // attach user to request
                req.user = user;
                next();

            } catch (err) {
                console.error(err);
                res.status(401).send({ message: "Unauthorized" });
            }
        };



        app.post('/users', async (req, res) => {
            const user = req.body;
            user.role = "user";
            user.createdAt = new Date();
            const email = user.email;
            const userExists = await usersCollection.findOne({ email })

            if (userExists) {
                return res.send({ message: 'user exists' })
            }

            const result = await usersCollection.insertOne(user);
            res.send(result);

        })


        app.post('/create-premium-checkout-session', async (req, res) => {
            try {
                const { email, name } = req.body;

                const cost = 1000; // Bdt 1000 for premium
                const amount = cost * 100;

                const session = await stripe.checkout.sessions.create({
                    payment_method_types: ['card'],
                    line_items: [
                        {
                            price_data: {
                                currency: 'bdt',
                                unit_amount: amount,
                                product_data: {
                                    name: 'Premium Subscription',
                                    description: 'Unlimited issue submission'
                                }
                            },
                            quantity: 1
                        }
                    ],
                    mode: 'payment',
                    customer_email: email,
                    metadata: {
                        email,
                        type: 'premium'
                    },
                    success_url: `${process.env.SITE_DOMAIN}/profile?session_id={CHECKOUT_SESSION_ID}`,
                    cancel_url: `${process.env.SITE_DOMAIN}/profile?payment=cancelled`
                });

                res.send({ url: session.url });

            } catch (err) {
                console.error('Premium checkout error:', err);
                res.status(500).send({ message: 'Failed to create premium checkout session' });
            }
        });

        app.patch('/premium-payment-success', async (req, res) => {
            try {
                const sessionId = req.query.session_id;

                const session = await stripe.checkout.sessions.retrieve(sessionId);

                if (session.payment_status !== 'paid') {
                    return res.send({ success: false, message: 'Payment not completed' });
                }

                const { email } = session.metadata;

                // Optional: prevent duplicate premium payment
                const alreadyPremium = await usersCollection.findOne({
                    email,
                    role: 'premiumUser'
                });

                if (alreadyPremium) {
                    return res.send({
                        success: true,
                        message: 'User already premium'
                    });
                }

                // Update user role
                const updateUser = await usersCollection.updateOne(
                    { email },
                    {
                        $set: {
                            role: 'premiumUser',
                            isPremium: true,
                            premiumSince: new Date()
                        }
                    }
                );

                // Save payment history 
                const premiumPayment = {
                    email,
                    amount: session.amount_total / 100,
                    currency: session.currency,
                    transactionId: session.payment_intent,
                    paymentStatus: session.payment_status,
                    type: 'premium',
                    paidAt: new Date()
                };

                await paymentCollection.insertOne(premiumPayment);

                res.send({
                    success: true,
                    message: 'Premium activated successfully'
                });
            } catch (err) {
                console.error('Premium payment success error:', err);
                res.status(500).send({ success: false, message: err.message });
            }
        });


        // premium check

        // app.patch('/users/premium', async (req, res) => {
        //     const email = req.body.email;


        //     const filter = { email: email };

        //     const updateQuery = {
        //         $set: {
        //             role: 'premium',
        //             premiumAt: new Date()
        //         }
        //     };


        //     const result = await usersCollection.updateOne(filter, updateQuery);


        //     if (result.matchedCount === 0) {
        //         return res.status(404).send({ message: "User not found" });
        //     }

        //     res.send({ message: "User upgraded to premium", result });

        // });

        // All user,staff,admin update profile route

        // Update user profile (name, phone, photo)
        app.patch('/users/profile', verifyFBToken, async (req, res) => {
            try {
                const { displayName, phone, photoURL } = req.body;
                const email = req.decoded_email;

                const updateDoc = {
                    $set: {
                        displayName,
                        phone,
                    }
                };

                // photo optional
                if (photoURL) {
                    updateDoc.$set.photo = photoURL;
                }

                const result = await usersCollection.updateOne(
                    { email },
                    updateDoc
                );

                if (result.matchedCount === 0) {
                    return res.status(404).send({ message: "User not found" });
                }

                res.send({
                    success: true,
                    message: "Profile updated successfully"
                });

            } catch (error) {
                console.error("PROFILE UPDATE ERROR:", error);
                res.status(500).send({ message: "Failed to update profile" });
            }
        });

        // get specific using query (email)
        app.get('/users', async (req, res) => {

            try {

                const { email } = req.query;

                if (!email) {
                    return res.status(400).send({ message: "Email is required" });
                }

                const result = await usersCollection.findOne({ email });
                res.send(result);

            } catch (err) {
                res.status(500).send({ message: "Failed to fetch user" });
            }
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


        app.get("/citizen/dashboard/summary", async (req, res) => {
            try {
                const { email } = req.query;

                if (!email) {
                    return res.status(400).send({ message: "Email required" });
                }

                const issueQuery = { senderEmail: email };

                const totalIssues = await issuesCollection.countDocuments(issueQuery);
                const pendingIssues = await issuesCollection.countDocuments({
                    ...issueQuery,
                    status: "pending"
                });

                const inProgressIssues = await issuesCollection.countDocuments({
                    ...issueQuery,
                    status: "in-progress"
                });


                const resolvedIssues = await issuesCollection.countDocuments({
                    ...issueQuery,
                    status: "resolved"
                });

                const payments = await paymentCollection.find({
                    boostedBy: email,
                    paymentStatus: "paid"
                }).toArray();

                const totalPayments = payments.reduce((sum, p) => sum + p.amount, 0);

                // ChartData 
                const paymentChart = {};
                payments.forEach(p => {
                    const month = new Date(p.paidAt).toISOString().slice(0, 7);
                    paymentChart[month] = (paymentChart[month] || 0) + p.amount;
                });

                const chartData = Object.keys(paymentChart).map(m => ({
                    month: m,
                    total: paymentChart[m]
                }));

                res.send({
                    totalIssues,
                    pendingIssues,
                    inProgressIssues,
                    resolvedIssues,
                    totalPayments,
                    chartData
                });

            } catch (error) {
                res.status(500).send({ message: error.message });
            }
        });

        // GET /users/:email/role  (projection use , if we dont send other data)
        app.get('/users/:email/role', verifyFBToken, async (req, res) => {

            try {
                const email = req.params.email;


                if (req.decoded_email !== email) {
                    return res.status(403).send({ message: "Forbidden: Cannot access other user's role" });
                }


                const user = await usersCollection.findOne(
                    { email },
                    { projection: { role: 1 } }
                );

                if (!user) {
                    return res.status(404).send({ message: "User not found" });
                }

                res.send({ role: user.role || 'user' });

            } catch (err) {
                console.error(err);
                res.status(500).send({ message: "Failed to fetch user role" });
            }
        });




        // Issues related api
        app.post('/issues', verifyFBToken, verifyBlockedUser, async (req, res) => {

            try {
                const issue = req.body;
                const email = issue.senderEmail;
                const name = issue.senderName;

                // console.log(name, issue);

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
                if (user.role !== 'premiumUser' && issueCount >= 3) {
                    return res.status(403).send({
                        message: 'Free user issue limit reached',
                        limitReached: true
                    });
                }

                // Add issue related field
                issue.createdAt = new Date();
                issue.priority = 'normal';
                issue.status = 'pending';

                issue.upvotes = 0;
                issue.upvotedBy = [];

                // timeline entry

                issue.timeline = [
                    {
                        status: 'pending',
                        message: `Issue reported by citizen .Name ${name}`,
                        updatedBy: {
                            role: 'Citizen',
                            email: issue.senderEmail
                        },
                        createdAt: new Date()
                    }
                ];


                const result = await issuesCollection.insertOne(issue);
                res.send(result);

            } catch (error) {
                console.error(error);
                res.status(500).send({ message: 'Failed to create issue' });
            }
        });


        // Get all issues

        // app.get('/issues', async (req, res) => {

        //     const result = await issuesCollection.find().sort({ createdAt: -1 }).toArray();
        //     res.send(result)
        // })


        // get all issues and search filter

        // without pagination
        // app.get('/issues', async (req, res) => {
        //     const { search, status, priority, category } = req.query;

        //     let query = {};

        //     if (search) {

        //         query.$or = [
        //             { title: { $regex: search, $options: "i" } },
        //             { category: { $regex: search, $options: "i" } },
        //             { senderDistrict: { $regex: search, $options: "i" } }
        //         ];
        //     }

        //     if (status) query.status = status;
        //     if (priority) query.priority = priority;
        //     if (category) query.category = category;

        //     const result = await issuesCollection
        //         .find(query)
        //         .sort({ upvotes: -1, createdAt: -1 }) // boosted first
        //         .toArray();

        //     res.send(result);
        // });

        // With pagination
        app.get("/issues", async (req, res) => {

            try {
                const { search, status, priority, category, page = 1,
                    limit = 12
                } = req.query;

                let query = {};

                //  search
                if (search) {
                    query.$or = [
                        { title: { $regex: search, $options: "i" } },
                        { category: { $regex: search, $options: "i" } },
                        { senderDistrict: { $regex: search, $options: "i" } }
                    ];
                }

                // Filters by
                if (status) query.status = status;
                if (priority) query.priority = priority;
                if (category) query.category = category;

                const skip = (Number(page) - 1) * Number(limit);

                // total count (for pagination)
                const total = await issuesCollection.countDocuments(query);

                const issues = await issuesCollection
                    .find(query)
                    .sort({
                        priority: -1,
                        upvotes: -1,
                        createdAt: -1
                    })
                    .skip(skip)
                    .limit(Number(limit))
                    .toArray();

                res.send({
                    issues,
                    total,
                    currentPage: Number(page),
                    totalPages: Math.ceil(total / limit)
                });

            } catch (error) {
                res.status(500).send({ message: "Failed to load issues" });
            }
        });

        // Get latest resolved issue

        app.get('/issues/resolved/latest', async (req, res) => {


            const result = await issuesCollection.find(
                {

                    // status: "resolved"
                    status: { $in: ["resolved", "closed"] }
                })
                .sort({ updatedAt: -1 })
                .limit(6)
                .toArray();

            res.send(result);

        });

        // upvote issue
        app.patch('/issues/:id/upvote', verifyFBToken, verifyBlockedUser, async (req, res) => {

            const issueId = req.params.id;
            const userEmail = req.decoded_email;

            const issueObjectId = new ObjectId(issueId);


            const issue = await issuesCollection.findOne({ _id: issueObjectId });

            if (!issue) {
                return res.status(404).send({ message: "Issue not found" });
            }

            // User cannot upvote own issue
            if (issue.senderEmail === userEmail) {
                return res.status(403).send({ message: "You cannot upvote your own issue" });
            }

            //  if not already upvoted
            const result = await issuesCollection.updateOne(

                // { $inc: { upvotes: 1 }, $push: { upvotedBy: userEmail } },

                {
                    _id: issueObjectId,
                    upvotedBy: { $ne: userEmail }
                },

                {
                    $inc: { upvotes: 1 },
                    $addToSet: { upvotedBy: userEmail }
                }
            );

            if (result.modifiedCount === 0) {
                return res.status(400).send({ message: "Already upvoted" });
            }

            res.send({
                message: "Upvoted successfully",
                upvotes: (issue.upvotes || 0) + 1
            });
        });



        // Verified citizen submitted issues
        app.get("/citizen-issues", verifyFBToken, async (req, res) => {

            try {
                const userEmail = req.decoded_email;

                const { status, category } = req.query;

                // MongoDB query object
                let query = { senderEmail: userEmail };

                // add optional filters
                if (status) query.status = status;
                if (category) query.category = category;

                const issues = await issuesCollection
                    .find(query)
                    .sort({ createdAt: -1 })
                    .toArray();

                res.send(issues);
            } catch (err) {
                console.error(err);
                res.status(500).send({ message: "Failed to fetch issues" });
            }
        });


        app.get('/issues/:id', async (req, res) => {

            try {

                const { id } = req.params;

                const issue = await issuesCollection.findOne({ _id: new ObjectId(id) });

                if (!issue) {
                    return res.status(404).send({ message: "Issue not found" });
                }

                res.send(issue);


            } catch (error) {
                console.error(error);
                res.status(500).send({ message: "Failed to fetch issue" });
            }
        });



        // Edit issue (only pending issues by the creator)
        app.patch('/issues/:id', verifyFBToken, verifyBlockedUser, async (req, res) => {

            try {
                const { id } = req.params;
                const updates = req.body;

                // logged-in user from token
                const userEmail = req.decoded_email;

                const issue = await issuesCollection.findOne({ _id: new ObjectId(id) });

                if (!issue) {
                    return res.status(404).send({ message: "Issue not found" });
                }

                // issue ownership check 
                if (issue.senderEmail !== userEmail) {
                    return res.status(403).send({ message: "You can only edit your own issues" });
                }

                if (issue.status !== "pending") {

                    return res.status(403).send({ message: "Only pending issues can be edited !" });
                }

                // allow only editable fields

                const result = await issuesCollection.updateOne(

                    { _id: new ObjectId(id) },

                    {

                        $set: {
                            title: updates.title,
                            category: updates.category,
                            issueDescription: updates.issueDescription,
                            photoURL: updates.photoURL,
                            updatedAt: new Date(),
                        }
                    }
                );

                // Only update editable fields
                // const updateData = {
                //     title: updates.title,
                //     category: updates.category,
                //     issueDescription: updates.issueDescription,
                //     updatedAt: new Date(),
                // };

                // // new image uploaded
                // if (updates.photoURL) {
                //     updateData.photoURL = updates.photoURL;
                // }

                // const result = await issuesCollection.updateOne(
                //     { _id: new ObjectId(id) },
                //     { $set: updateData }
                // );

                res.send(result);
            } catch (error) {
                console.error("EDIT ISSUE ERROR:", error);
                res.status(500).send({ message: "Failed to update issue" });
            }
        });

        // ---Payment related Api---

        app.post('/create-checkout-session', verifyFBToken, verifyBlockedUser, async (req, res) => {
            try {
                const issueInfo = req.body;
                const { issueId, boostedBy, title } = issueInfo;

                // console.log("Received issue info:", issueInfo);


                const cost = 100;
                const amount = parseInt(cost) * 100; // BDT 

                const session = await stripe.checkout.sessions.create({
                    payment_method_types: ['card'],
                    line_items: [
                        {
                            price_data: {
                                currency: 'bdt',
                                unit_amount: amount,
                                product_data: {
                                    name: `Boost Issue: ${title}`,
                                },
                            },
                            quantity: 1,
                        },
                    ],
                    mode: 'payment',
                    metadata: {
                        title,
                        issueId,
                        boostedBy,
                        trackingId: issueInfo.trackingId
                    },
                    customer_email: boostedBy, // user email
                    success_url: `${process.env.SITE_DOMAIN}/issues/${issueId}?session_id={CHECKOUT_SESSION_ID}`,
                    cancel_url: `${process.env.SITE_DOMAIN}/issues/${issueId}?payment=cancelled`,
                });

                res.send({ url: session.url });
            } catch (err) {
                console.error("Stripe checkout error:", err);
                res.status(500).send({ message: "Failed to create checkout session" });
            }
        });

        // payment success
        app.patch('/payment-success', async (req, res) => {
            try {
                const sessionId = req.query.session_id;
                // console.log(sessionId);

                // Retrieve session from Stripe
                const session = await stripe.checkout.sessions.retrieve(sessionId);

                // Only proceed if payment is completed
                if (session.payment_status !== 'paid') {
                    return res.send({ success: false, message: 'Payment not completed' });
                }

                // metadata from checkout session
                const { issueId, boostedBy, title } = session.metadata;

                // Check if this payment already exists
                const existingPayment = await paymentCollection.findOne({ transactionId: session.payment_intent });
                if (existingPayment) {
                    return res.send({
                        success: true,
                        message: 'Payment already recorded',
                        transactionId: session.payment_intent
                    });
                }

                // get issue related data from db
                const issue = await issuesCollection.findOne({
                    _id: new ObjectId(issueId)
                });

                if (!issue) {
                    return res.status(404).send({ success: false, message: "Issue not found" });
                }

                //  Update the issue
                const query = { _id: new ObjectId(issueId) };
                const updateIssue = {
                    $set: {
                        priority: 'high',
                        boostedAt: new Date(),
                        boostedBy,
                        statusMessage: `Issue boosted via payment by ${boostedBy}`,
                    },

                    $push: {
                        timeline: {
                            status: issue.status,
                            message: `Issue boosted via payment by ${boostedBy}`,
                            updatedBy: {
                                role: 'Citizen',
                                email: boostedBy
                            },
                            createdAt: new Date()
                        }
                    }


                };
                const resultIssue = await issuesCollection.updateOne(query, updateIssue);

                // Insert into paymentCollection
                const paymentRecord = {
                    issueId,
                    title,
                    boostedBy,
                    amount: session.amount_total / 100, // BDT
                    currency: session.currency,
                    transactionId: session.payment_intent,
                    paymentStatus: session.payment_status,
                    paidAt: new Date()
                };

                // const resultPayment = await paymentCollection.insertOne(paymentRecord);

                // check db error when want to insert double entry
                let resultPayment;

                try {
                    resultPayment = await paymentCollection.insertOne(paymentRecord);

                } catch (err) {
                    if (err.code === 11000) {
                        return res.send({
                            success: true,
                            message: "Duplicate payment prevented",
                            transactionId: session.payment_intent
                        });
                    }
                    throw err;
                }


                res.send({
                    success: true,
                    updatedIssue: resultIssue,
                    paymentInfo: resultPayment,
                    transactionId: session.payment_intent
                });
            } catch (err) {
                console.error("Payment success error:", err);
                res.status(500).send({ success: false, message: err.message });
            }
        });




        app.delete('/issues/:id', verifyFBToken, async (req, res) => {

            // console.log("REQ USER:", req.user);


            try {

                const { id } = req.params;
                const userEmail = req.decoded_email;
                // const { userEmail } = req.user.email;
                // console.log(userEmail);

                const issue = await issuesCollection.findOne({ _id: new ObjectId(id) });

                if (!issue) {
                    return res.status(404).send({ message: "Issue not found" });
                }

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


        // -- Admin related apis ---------

        // Add new staff
        app.post('/admin/staffs', async (req, res) => {
            try {
                const { displayName, email, password, phone, photoURL } = req.body;
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
                    displayName,
                    photoURL
                });


                const staff = {
                    uid: firebaseUser.uid,
                    displayName,
                    email: normalizedEmail,
                    phone,
                    photoURL,
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

        // admin get all payments

        // app.get("/admin/payments/by-month", async (req, res) => {
        //     try {
        //         const { month } = req.query; // e.g. 2026-01

        //         if (!month) {
        //             return res.status(400).send({ message: "Month is required" });
        //         }

        //         const payments = await paymentsCollection.find({
        //             paidAt: {
        //                 $gte: new Date(`${month}-01`),
        //                 $lt: new Date(`${month}-31`)
        //             }
        //         }).sort({ paidAt: -1 }).toArray();

        //         res.send(payments);
        //     } catch (error) {
        //         res.status(500).send({ message: error.message });
        //     }
        // });

        app.get("/admin/payments/by-month", async (req, res) => {
            try {
                const { month, page = 1, limit = 10 } = req.query;

                if (!month) {
                    return res.status(400).send({ message: "Month is required" });
                }

                const pageNumber = parseInt(page);
                const limitNumber = parseInt(limit);
                const skip = (pageNumber - 1) * limitNumber;

                const startDate = new Date(`${month}-01`);
                const endDate = new Date(startDate);
                endDate.setMonth(endDate.getMonth() + 1);

                const query = {
                    paidAt: {
                        $gte: startDate,
                        $lt: endDate
                    }
                };

                // total count
                const totalCount = await paymentCollection.countDocuments(query);

                // paginated data
                const payments = await paymentCollection
                    .find(query)
                    .sort({ paidAt: -1 })
                    .skip(skip)
                    .limit(limitNumber)
                    .toArray();

                res.send({
                    payments,
                    totalCount,
                    totalPages: Math.ceil(totalCount / limitNumber),
                    currentPage: pageNumber
                });

            } catch (error) {
                res.status(500).send({ message: error.message });
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

        // ----admin all Issues related apis---

        app.get('/admin/issues', async (req, res) => {
            const result = await issuesCollection.find()
                .sort({ priority: -1, createdAt: -1 })
                .toArray();

            res.send(result);
        });

        app.get('/admin/staffs', verifyAdmin, async (req, res) => {
            const result = await usersCollection.find({ role: "staff" }).toArray();
            res.send(result);
        });


        app.patch('/admin/issues/:id/assign', verifyAdmin, async (req, res) => {

            const issueId = req.params.id;
            const { staffId, name, email } = req.body;

            const issue = await issuesCollection.findOne({ _id: new ObjectId(issueId) });

            if (!issue) {
                return res.status(404).send({ message: "Issue not found" });
            }


            if (issue.staffId) {
                return res.status(400).send({ message: "Staff already assigned" });
            }

            const result = await issuesCollection.updateOne(
                { _id: new ObjectId(issueId) },
                {
                    $set: {
                        staffId: staffId,
                        staffName: name,
                        staffEmail: email,
                        status: issue.status,
                        statusMessage: `Assigned to ${name}`,
                        updatedAt: new Date()
                    },

                    $push: {
                        timeline: {
                            status: issue.status,
                            message: `Issue assigned to staff: ${name}`,
                            updatedBy: {
                                role: 'Admin',
                                email: req.decoded_email || 'admin'
                            },
                            createdAt: new Date()
                        }
                    }


                }
            );

            res.send(result);
        });

        app.patch('/admin/issues/:id/reject', verifyFBToken, async (req, res) => {
            const issueId = req.params.id;

            const issue = await issuesCollection.findOne({ _id: new ObjectId(issueId) });

            if (issue.status !== "pending") {
                return res.status(400).send({ message: "Only pending issues can be rejected" });
            }

            const result = await issuesCollection.updateOne(
                { _id: new ObjectId(issueId) },
                {
                    $set: {
                        status: "rejected",
                        statusMessage: "Issue rejected by admin",
                        updatedAt: new Date(),

                    },

                    $push: {
                        timeline: {
                            status: 'rejected',
                            message: 'Issue rejected by admin',
                            updatedBy: {
                                role: 'Admin',
                                email: req.decoded_email
                            },
                            createdAt: new Date()
                        }
                    }

                }
            );

            res.send(result);
        });

        // Admin Dashboard home related get api
        app.get('/admin/dashboard/summary', verifyFBToken, verifyAdmin, async (req, res) => {
            try {

                const totalIssues = await issuesCollection.countDocuments();

                const pendingIssues = await issuesCollection.countDocuments({
                    status: "pending"
                });

                const resolvedIssues = await issuesCollection.countDocuments({
                    status: "resolved"
                });

                const rejectedIssues = await issuesCollection.countDocuments({
                    status: "rejected"
                });


                const payments = await paymentCollection
                    .find({ paymentStatus: "paid" })
                    .toArray();

                const totalPaymentReceived = payments.reduce(
                    (sum, p) => sum + (p.amount || 0),
                    0
                );

                // ---- CHART DATA (Issues by Status) ----
                const issueStatusChart = [
                    { status: "pending", count: pendingIssues },
                    { status: "resolved", count: resolvedIssues },
                    { status: "rejected", count: rejectedIssues },
                ];

                // ---- PAYMENT CHART (Monthly) ----
                const paymentChartMap = {};

                payments.forEach(p => {
                    const month = new Date(p.paidAt).toISOString().slice(0, 7); // YYYY-MM
                    paymentChartMap[month] = (paymentChartMap[month] || 0) + p.amount;
                });

                const paymentChart = Object.keys(paymentChartMap).map(month => ({
                    month,
                    total: paymentChartMap[month]
                }));


                const latestIssues = await issuesCollection
                    .find()
                    .sort({ createdAt: -1 })
                    .limit(5)
                    .project({
                        title: 1,
                        status: 1,
                        priority: 1,
                        createdAt: 1
                    })
                    .toArray();

                const latestPayments = await paymentCollection
                    .find()
                    .sort({ paidAt: -1 })
                    .limit(5)
                    .project({
                        title: 1,
                        amount: 1,
                        boostedBy: 1,
                        paidAt: 1
                    })
                    .toArray();

                const latestUsers = await usersCollection
                    .find({ role: { $ne: "admin" } })
                    .sort({ createdAt: -1 })
                    .limit(5)
                    .project({
                        name: 1,
                        email: 1,
                        role: 1,
                        createdAt: 1
                    })
                    .toArray();

                res.send({
                    stats: {
                        totalIssues,
                        pendingIssues,
                        resolvedIssues,
                        rejectedIssues,
                        totalPaymentReceived
                    },
                    charts: {
                        issueStatusChart,
                        paymentChart
                    },
                    latest: {
                        issues: latestIssues,
                        payments: latestPayments,
                        users: latestUsers
                    }
                });

            } catch (error) {
                console.error(error);
                res.status(500).send({ message: error.message });
            }
        });



        // --- Staff related apis---


        // get assigned issues for staff
        app.get('/staff/issues', async (req, res) => {
            const staffEmail = req.query.email;
            const status = req.query.status;
            const priority = req.query.priority;


            let query = { staffEmail };
            // console.log("query email :", staffEmail);

            if (status) query.status = status;
            if (priority) query.priority = priority;

            const issues = await issuesCollection
                .find(query)
                .sort({ priority: -1, createdAt: -1 })
                .toArray();

            res.send(issues);
        });


        app.patch('/staff/issues/:id/status', verifyFBToken, async (req, res) => {
            const id = req.params.id;
            const { status, statusMessage } = req.body;
            const staffEmail = req.decoded_email;

            // console.log(staffEmail);

            const issue = await issuesCollection.findOne({ _id: new ObjectId(id) });
            // console.log(issue.staffEmail);

            const assignedEmail = issue.staffEmail;


            // only assigned staff can change status

            if (!assignedEmail || !staffEmail) {
                return res.status(403).send({ message: "Not authorized" });
            }

            if (assignedEmail.toLowerCase() !== staffEmail.toLowerCase()) {
                return res.status(403).send({ message: "Not authorized" });
            }


            // allowed status flow
            const allowedTransitions = {
                pending: ['in-progress'],
                'in-progress': ['working'],
                working: ['resolved'],
                resolved: ['closed'],
            };

            if (!allowedTransitions[issue.status]?.includes(status)) {
                return res.status(400).send({ message: 'Invalid status transition' });
            }

            const updateResult = await issuesCollection.updateOne(
                { _id: new ObjectId(id) },
                {
                    $set: {
                        status: status,
                        statusMessage: statusMessage
                    },

                    $push: {
                        timeline: {
                            status,
                            message: statusMessage,
                            updatedBy: {
                                role: 'Staff',
                                email: staffEmail
                            },
                            createdAt: new Date()
                        }
                    }

                }
            );

            res.send({ modifiedCount: updateResult.modifiedCount });
        });

        // staff dashboard home get api

        app.get('/staff/dashboard/summary', verifyFBToken, verifyStaff, async (req, res) => {

            const staffEmail = req.decoded_email;

            const baseQuery = { staffEmail };

            const totalAssigned = await issuesCollection.countDocuments(baseQuery);

            const resolvedIssues = await issuesCollection.countDocuments({
                staffEmail,
                status: "resolved"
            });

            const pendingIssues = await issuesCollection.countDocuments({
                staffEmail,
                status: "pending"
            });



            const inProgressIssues = await issuesCollection.countDocuments({
                staffEmail,
                status: "in-progress"
            });

            const closedIssues = await issuesCollection.countDocuments({
                staffEmail,
                status: "closed"
            });

            const todayTasks = await issuesCollection.countDocuments({
                staffEmail,
                createdAt: {
                    $gte: new Date(new Date().setHours(0, 0, 0, 0))
                }
            });

            // Latest assigned issues
            const latestIssues = await issuesCollection
                .find(baseQuery)
                .sort({ createdAt: -1 })
                .limit(5)
                .project({
                    title: 1,
                    status: 1,
                    priority: 1,
                    createdAt: 1
                })
                .toArray();

            res.send({
                totalAssigned,
                pendingIssues,
                inProgressIssues,
                resolvedIssues,
                closedIssues,
                todayTasks,
                latestIssues
            });
        });


        // Admin Manage users related api
        app.get("/admin/users", async (req, res) => {
            try {
                const query = {
                    role: { $in: ["user", "premiumUser"] }
                };

                const users = await usersCollection
                    .find(query)
                    .sort({ createdAt: -1 })
                    .toArray();

                res.send(users);
            } catch (error) {
                res.status(500).send({
                    message: "Failed to fetch users",
                    error: error.message
                });
            }
        });


        // Admin block & unblock related api
        // app.patch("/admin/users/block/:id", async (req, res) => {
        //     const id = req.params.id;

        //     const result = await usersCollection.updateOne(
        //         { _id: new ObjectId(id) },
        //         {
        //             $set: {
        //                 userStatus: "blocked"
        //             }
        //         }
        //     );

        //     res.send({ success: true, result });
        // });

        app.patch("/admin/users/block/:id", async (req, res) => {

            try {
                const id = req.params.id;

                const result = await usersCollection.updateOne(
                    {
                        _id: new ObjectId(id),
                        role: { $in: ["user", "premiumUser"] }
                    },

                    {
                        $set: { userStatus: "blocked" }
                    }

                );

                if (result.matchedCount === 0) {
                    return res.status(404).send({ message: "User not found" });
                }

                res.send({ success: true, message: "User blocked" });
            } catch (error) {
                res.status(500).send({ message: error.message });
            }
        });


        app.patch("/admin/users/unblock/:id", async (req, res) => {
            try {
                const id = req.params.id;

                const result = await usersCollection.updateOne(
                    {
                        _id: new ObjectId(id),

                        role: { $in: ["user", "premiumUser"] }
                    },

                    {
                        $unset: { userStatus: "" }
                    }
                );

                if (result.matchedCount === 0) {
                    return res.status(404).send({ message: "User not found" });
                }

                res.send({ success: true, message: "User unblocked" });

            } catch (error) {
                res.status(500).send({ message: error.message });
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