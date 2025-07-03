import express from "express"
import cors from "cors"
import connection from "./db.js";
import bcrypt from 'bcrypt';






//app config
const app = express()
const port = 4000


//middleware
app.use(express.json())
app.use(cors())


app.get("/",(req,res)=>{
    res.send("API Working")
})

app.get('/api/users', (req, res) => {
  connection.query('SELECT * FROM users', (err, results) => {
    if (err) {
      res.status(500).json({ error: err });
      return;
    }
    res.json(results);
  });
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  connection.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
    if (err) {
      console.error('MySQL error:', err);
      return res.status(500).json({ error: 'Database error' });
    }
    if (results.length === 0) return res.status(401).json({ error: 'Invalid credentials' });

    const user = results[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: 'Invalid credentials' });

    // Don't send password back!
    res.json({ user: { id: user.id, name: user.name, email: user.email, role: user.role } });
  });
});

app.post('/api/signup', async (req, res) => {
  const { name, email, password } = req.body;
  const hash = await bcrypt.hash(password, 10);
  connection.query(
    'INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)',
    [name, email, hash, 'user'],
    (err, results) => {
      if (err) {
        if (err.code === 'ER_DUP_ENTRY') {
          return res.status(400).json({ error: 'Email already exists' });
        }
        console.error('MySQL error:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      res.json({ success: true });
    }
  );
});

app.listen(port,()=>{
    console.log(`Server Started on http://localhost:${port} `)
})