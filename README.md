
# Civic Care – Backend Server

This is the backend server for Civic Care – Public Infrastructure Issue Reporting System.  
It provides secure REST APIs for authentication, issue management, role control, payments, subscriptions, and timeline tracking.

🔗 Live Client: https://public-care.web.app/  

💻 Client Repo: https://github.com/Shefaul-22/Civic-Care-Client  

⚙️ Server Repo: https://github.com/Shefaul-22/Civic-Care-server  

---

## 📌 Overview

The server handles all core backend operations including:

- Authentication and authorization
- Issue CRUD operations
- Staff assignment
- Timeline tracking
- Payment processing
- Role-based access control
- Database management

Built using modern backend technologies ensuring security, scalability, and performance.

---

## 🚀 Core Features

- Secure REST API using Express.js
- JWT Authentication and Authorization
- Role-based access control (Admin, Staff, Citizen)
- Issue reporting and management
- Issue assignment system
- Issue timeline tracking system
- Upvote system
- Priority boost payment system
- Premium subscription system
- User and staff management
- Secure environment variables
- MongoDB database integration
- Protected private routes

---

## 🧰 Tech Stack

- Node.js
- Express.js
- MongoDB Atlas
- JWT (JSON Web Token)
- Firebase Admin SDK
- Stripe Payment Integration
- dotenv
- cors

---

## 📂 Project Structure

```

Civic-Care-server/
│
├── routes/
├── middleware/
├── controllers/
├── config/
├── utils/
└── index.js

```

---

## 🔐 Authentication System

- Firebase Authentication (Client)
- JWT verification (Server)
- Role-based middleware protection
- Secure private routes

---

## 🌐 API Endpoints Overview

### Authentication
```

POST /jwt

```

### Issues
```

GET /issues
POST /issues
PATCH /issues/:id
DELETE /issues/:id

```

### Users
```

GET /users
PATCH /users/role/:id
PATCH /users/block/:id

```

### Staff
```

GET /staff
POST /staff
PATCH /staff/:id
DELETE /staff/:id

```

### Payments
```

POST /create-payment-intent
GET /payments

```

---

## ⚙️ Installation

Clone repository:

```

git clone [https://github.com/Shefaul-22/Civic-Care-server.git](https://github.com/Shefaul-22/Civic-Care-server.git)

```

Install dependencies:

```

npm install

```

Run server:

```

npm start

```

---

## 🌐 Environment Variables

Create `.env` file:

```

PORT=5000

DB_USER=
DB_PASS=

JWT_SECRET=

STRIPE_SECRET_KEY=

```

---

## 🚀 Deployment

Server deployed on:

- Vercel

Database hosted on:

- MongoDB Atlas

---

## 🔒 Security Features

- JWT protected APIs
- Role-based middleware
- Secure environment variables
- Protected admin routes

---

## 👨‍💻 Author

Md Shefaul Karim

GitHub:  
https://github.com/Shefaul-22

---

## ⭐ Support

If you like this project, give it a star ⭐ on GitHub.
```

---
