import dotenv from 'dotenv'
import app from './app.js'
import connectDB from './db/db-connection.js';

dotenv.config({
    path:'./.env'
})

const port = process.env.PORT || 8080;

connectDB()
.then(()=>{
    app.listen(port, ()=>{
        console.log(`Server is listening at http://localhost:${port}`);
    })
})
.catch(()=>{
    console.error('DB connection failed')
})



