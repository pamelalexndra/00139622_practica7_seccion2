import express from "express";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import bodyParser from "body-parser";
import cors from "cors";

const app = express();
const PORT = 5000;
const JWT_SECRET = "your_jwt_secret"; // Use a strong, secure key in production

app.use(bodyParser.json());
app.use(cors());

const users = []; 

// Middleware: Verify Token
const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ message: "Unauthorized" });

  const token = authHeader.split(" ")[1];
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: "Invalid token" });
    req.user = user;
    next();
  });
};

// Routes

app.post("/register", async (req, res) => {
  const { email, password } = req.body;
  
  const existingUser = users.find((u) => u.email === email);
  if (existingUser) return res.status(400).json({ message: "User already exists" });

  const hashedPassword = await bcrypt.hash(password, 10);

  const newUser = {
    id: users.length + 1,
    email: email,
    password: hashedPassword
  };
  
  users.push(newUser);
  console.log("Usuario registrado:", newUser); 
  
  res.status(201).json({ message: "User created successfully" });
});

app.post("/signin", async (req, res) => {
  const { email, password } = req.body;
  const user = users.find((u) => u.email === email);
  if (!user) return res.status(404).json({ message: "User not found" });

  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) return res.status(400).json({ message: "Invalid credentials" });

  const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: "1h" });
  res.status(200).json({ token });
});

app.get("/protected", verifyToken, (req, res) => {
  res.status(200).json({ message: "Protected data accessed", user: req.user });
});

const movies = []; // almacenamiento en memoria 

app.get("/movies", (req, res) => {
  res.json(movies);
});

// obtener una película por id
app.get("/movies/:id", (req, res) => {
  const id = Number(req.params.id);
  const movie = movies.find(m => m.id === id);
  if (!movie) return res.status(404).json({ message: "Movie not found" });
  res.json(movie);
});

// crear película (protegida)
app.post("/movies", verifyToken, (req, res) => {
  const { title, description, year } = req.body;
  if (!title) return res.status(400).json({ message: "Title is required" });

  const newMovie = {
    id: movies.length + 1,
    title,
    description: description || "",
    year: year || null,
    createdBy: req.user.id 
  };
  movies.push(newMovie);
  res.status(201).json(newMovie);
});

// eliminar película (protegida)
app.delete("/movies/:id", verifyToken, (req, res) => {
  const id = Number(req.params.id);
  const idx = movies.findIndex(m => m.id === id);
  if (idx === -1) return res.status(404).json({ message: "Movie not found" });
  const deleted = movies.splice(idx, 1);
  res.json({ message: "Deleted", movie: deleted[0] });
});

app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`)
);