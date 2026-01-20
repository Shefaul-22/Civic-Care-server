const express = require('express');
const app = express();
const port = 3000;

app.get('/', (req,res) => {
    res.send("CivicCare is running")
})

app.listen(port, ()=> {
    console.log(`CivicCare server is running on port ${port}`);
})