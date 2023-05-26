const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const admin = require('firebase-admin');

const app = express();
app.use(express.json());


const serviceAccount = require('./firebaseServiceAccount.json');
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});
const db = admin.firestore();
const userCollection = db.collection('');


app.post('/register', async (req, res) => {
  const { username, email, password } = req.body;

  const hashedPassword = await bcrypt.hash(password, 10);

  await userCollection.doc(username).set({ username, email, password: hashedPassword });

  res.status(200).json({ message: 'Registrasi berhasil' });
});


app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  const userDoc = await userCollection.doc(username).get();
  const user = userDoc.data();


  
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ message: 'Username atau password salah' });
  }


  const token = jwt.sign({ username }, 'secret_key');

  res.status(200).json({ token });
});

app.get('/protected', (req, res) => {
  
  const token = req.headers.authorization;

  if (!token) {
    return res.status(401).json({ message: 'Token tidak ada' });
  }

  try {
 
    const decoded = jwt.verify(token, 'secret_key');
    const username = decoded.username;

    res.status(200).json({ message: `Halo, ${username}! Ini adalah halaman yang diatur` });
  } catch (error) {
    res.status(401).json({ message: 'Token tidak valid' });
  }
});


app.listen(3000, () => {
  console.log('Server berjalan pada port 3000');
});
