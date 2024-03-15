import express, { response} from "express";
import mysql from 'mysql'
import cors from 'cors'
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import nodemailer from 'nodemailer';
import crypto from 'crypto';
import expressUploader from "express-fileupload";
import fetch from "node-fetch";


const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(expressUploader());
app.use(cors(
    {
        origin: ["http://localhost:3000", "http://localhost:3001"],
        methods: ["POST, GET, PUT, DELETE"],
        credentials: true
    }
))

const db = mysql.createConnection({
    host: "localhost",
    port: 1008,
    user: "root",
    password: "",
    database: "web_sport"
});

db.connect((err) => {
    if (err) {
      console.error("Error connecting to MySQL:", err);
      return;
    }
    console.log("Connected to MySQL database");
  });

//login admin
function verifyToken(req, res, next) {
    // Get the token from the cookie or wherever it's stored
    const token = req.cookies.token;
  
    if (!token) {
      return res.status(401).json({ message: 'Unauthorized' });
    }
  
    // Verify and decode the token
    jwt.verify(token, 'jwtSecretKey', (err, decoded) => {
      if (err) {
        return res.status(403).json({ message: 'Invalid token' });
      }
  
      // The user's ID is stored in the token payload
      req.id = decoded.id; // Assuming "id" is the key in the payload
  
      // Continue processing the request
      next();
    });
  }
  
app.post('/', (req, res) => {
    const sql = "SELECT * FROM users WHERE email = ? AND password = ? AND admin = 1";
    db.query(sql, [req.body.email, req.body.password], (err, data)=>{
        if (err) {
            return res.json({ Message: 'Database error' });
          }
          if (data.length > 0) {
                    const userName = data[0].userName;
                    const id = data[0].id;
                    const token = jwt.sign({id}, "jwtSecretKey", { expiresIn: '1d' });
                    res.cookie('token', token);
                    return res.json({ Status: "Success", id});
          } else {
            return res.json({ Message: "Wrong Email or Password"});
          }
    })
})

//forgot-password
function saveResetToken(email, token, callback) {
    const sql = 'UPDATE users SET reset_token = ? WHERE email = ?';
  
    // Execute the SQL query
    db.query(sql, [token, email], (error, results) => {
      if (error) {
        // Handle database query error
        return callback(error);
      }
  
      if (results.affectedRows === 0) {
        // No user found with the specified email
        return callback(new Error('User not found'));
      }
  
      // Password reset token saved successfully
      callback(null);
    });
  }
app.post('/forgot-password', (req, res) => {
    const { email } = req.body;
    const sqlEmail = 'SELECT * FROM users WHERE email = ? AND admin = 1';
    db.query(sqlEmail, email, (err, data)=>{
        if (err) {
            return res.json({ Message: 'Database error' });
          }
          if (data.length > 0) {
            const resetToken = crypto.randomBytes(20).toString('hex');
            const sqlToken = 'UPDATE users SET reset_token = ? WHERE email = ?';
            db.query(sqlToken, [resetToken, req.body.email])
            const transporter = nodemailer.createTransport({
                service: 'sangnnm.sec@gmail.com',
                auth: {
                  user: 'sangnnm.sec@gmail.com',
                  pass: 'hryndsvpuxlctdfs',
                },
              });
            
              const resetLink = `http://localhost:3000/reset-password/${resetToken}`;
              const mailOptions = {
                from: 'sangnnm.sec@gmail.com',
                to: email,
                subject: 'Password Reset',
                text: `Click the following link to reset your password: ${resetLink}`,
              };
            
              transporter.sendMail(mailOptions, (error, info) => {
                if (error) {
                  console.error('Error sending email:', error);
                  return res.status(500).json({ Message: 'Internal Server Error' });
                }
                console.log('Password reset email sent:', info.response);
                res.json({ Message: 'Password Reset Email Sent' });
              });
          } else {
            return res.json({ Message: "Email Does Not Exist" });
          }
        });
    });



//reset-password
app.post('/reset-password', (req, res) => {
    const { resetToken, newPassword } = req.body;
    const checkTokenQuery = 'SELECT * FROM users WHERE reset_token = ?';
    db.query(checkTokenQuery, [resetToken], (err, results) => {
      if (err) {
        return res.status(500).json({ Message: 'Database Error' });
      }
  
      if (results.length === 0) {
        return res.status(404).json({ Message: 'Invalid Reset Token' });
      }
  
    const userId = results[0].id;
    const updatePasswordQuery = 'UPDATE users SET password = ?, reset_token = NULL WHERE id = ?';
    db.query(updatePasswordQuery, [newPassword, userId], (err) => {
        if (err) {
          return res.status(500).json({ Message: 'Database Error' });
        }
  
        res.json({ Message: 'Password Reset Successful' });
      });
    });
  });



// main-layout
app.get('/admin', verifyToken, (req, res) => {
    const id = req.id;
    
    // Query the database to fetch user data
    const sql = 'SELECT * FROM users WHERE id = ?';
    db.query(sql, [id], (err, data) => {
      if (err) {
        return res.status(500).json({ Message: 'Database Error' });
      }
  
      if (data.length > 0) {
        const userName = data[0].userName;
      const email = data[0].email;
      return res.json({Status: 'Success',userName, email}); 
      } else {
        return res.status(404).json({ Message: 'User Not Found' });
      }
  
    });
  });



//logout
app.get('/logout', (req, res) => {
    res.clearCookie('token');
    return res.json({Status: "Success"});
})



//User Login
app.post('/login', (req, res) => {
    const sql = "SELECT * FROM users WHERE email = ? AND password = ?";
    db.query(sql, [req.body.email, req.body.password], (err, data)=>{
        if (err) {
            return res.json({ Message: 'Database error' });
          }
          if (data.length > 0) {
                    const userName = data[0].userName;
                    const id = data[0].id;
                    const token = jwt.sign({id}, "jwtSecretKey", { expiresIn: '1d' });
                    res.cookie('token', token);
                    return res.json({ Status: "Success", id});
          } else {
            return res.json({ Message: "Wrong Email or Password"});
          }
    })
})
app.get('/', verifyToken, (req, res) => {
    const id = req.id;
    
    // Query the database to fetch user data
    const sql = 'SELECT * FROM users WHERE id = ?';
    db.query(sql, [id], (err, data) => {
      if (err) {
        return res.status(500).json({ Message: 'Database Error' });
      }
  
      if (data.length > 0) {
        const userName = data[0].userName;
      const email = data[0].email;
      const phone = data[0]. phone;
      const address = data[0].address;
      const image = data[0].userImage;
      return res.json({data: data, userName: userName, email: email, phone: phone, address: address, image: image}); 
      } else {
        return res.status(404).json({ Message: 'User Not Found' });
      }
  
    });
  });



//sign up
app.post('/signup', (req, res) => {
    const {userName, email, userImage, phone, password, address} = req.body;
    const sql = 'INSERT INTO users (userName, email, userImage, phone, password, address) VALUES (?, ?, ?, ?, ?, ?)';
    const sqlEmail = 'SELECT * FROM users WHERE email = ?';
    db.query(sqlEmail, email, (err, results)=>{
        if (err) {
            return res.json({ Message: 'Database error' });
          }
          if (results.length > 0) {
            return res.json({ Message: "Email Exist. Please Enter Another Email" });
          } else {
            db.query(sql, [userName, email, userImage, phone, password, address], (err, data)=>{
                if (err) {
                    return res.json({ Message: 'Database error' });
                  }
                  const id = data.insertId;
                  const token = jwt.sign({id}, "jwtSecretKey", { expiresIn: '1d' });
                  res.cookie('token', token);
                return res.json({Status: 'Success'})  
            })
          }
        });
    })
//user-info
app.put('/info', verifyToken, (req, res) => {
    const id = req.id;
    const {userName, phone, address} = req.body;
    const sql = 'UPDATE users SET userName = ?, phone = ?, address = ? WHERE id = ?';
    db.query(sql, [userName, phone, address, id], (err, data)=>{
                if (err) {
                    console.log(err)
                    return res.json({ Message: 'Database error' });
                  }
                return res.json({Status: 'Success'})  
            })
    })
app.post('/userImage', verifyToken, (req,res) => {
    const id = req.id;
    const {image} = req.files;
    const sql = 'UPDATE users SET userImage = ? WHERE id =?'
    fetch("https://www.filestackapi.com/api/store/S3?key=AJmEEe9SJT16AJoXJkj5uz", {
    method: 'POST',
    headers: {'Content-Type': 'image/png'},
    body: image.data
}).then((r)=>r.json())
.then((r)=>{
        const userImage = r.url;
            db.query(sql, [userImage, id], (err, data) => {
            if(err) {
                console.log(err);
                return res.json({Message: "Database Error"})
            } 
            return res.json({Message: "Add Image Success", userImage: userImage, id: id})
    })
})
}) 

//get new product
app.listen(8081, () => {
        console.log("Running");
})