import express from "express";
import cors from "cors";
import { MongoClient } from "mongodb";
import dotenv from "dotenv";
import joi from "joi";
import bcrypt from "bcrypt";
import { v4 as uuid } from "uuid";

// Criação do app
const app = express();

// Configurações
app.use(cors());
app.use(express.json());
dotenv.config();

// Conexão com o Banco de dados
const mongoClient = new MongoClient(process.env.DATABASE_URL);

try {
  await mongoClient.connect(); // top level await
  console.log("MongoDB conectado!");
} catch (err) {
  (err) => console.log("Erro MongoDB: ", err);
}

const db = mongoClient.db();

// Funções (endpoints)
app.post("/cadastro", async (req, res) => {
  const { name, email, password } = req.body;

  const schemaUser = joi.object({
    name: joi.string().required(),
    email: joi.email().required(),
    password: joi.min(3).required(),
  });

  const validation = schemaUser.validate(req.body, { abortEarly: false });
  if (validation.error) {
    const errors = validation.error.details.map((detail) => detail.message);
    return res.status(422).send(errors);
  }

  const hash = bcrypt.hashSync(password, 10);

  try {
    const user = await db.collection("users").findOne({ name: name });
    if (user) return res.status(409).send("Usuário já cadastrado!");

    await db
      .collection("users")
      .insertOne({ name: name, email: email, password: hash });
    res.sendStatus(201);
  } catch (err) {
    res.status(500).send(err.message);
  }
});

app.post("/", async (req, res) => {
  const { email, password } = req.body;

  const schemaLogin = joi.object({
    email: joi.email().required(),
    password: joi.min(3).required(),
  });

  const validation = schemaLogin.validate(req.body, { abortEarly: false });
  if (validation.error) {
    const errors = validation.error.details.map((detail) => detail.message);
    return res.status(422).send(errors);
  }

  try {
    const user = await db.collection("users").findOne({ email: email });
    if (!user) return res.status(404).send("Usuário não cadastrado!");

    const passwordCorrect = bcrypt.compareSync(password, user.password);
    if (!passwordCorrect) return res.status(401).send("Senha incorreta!");

    const token = uuid();
    await db
      .collection("sessions")
      .insertOne({ token: token, idUser: user._id });

    res.status(200).send(token);
  } catch (err) {
    res.status(500).send(err.message);
  }
});

// Ligar a aplicação do servidor para ouvir requisições

const port = process.env.PORT || 5000;
app.listen(port, () => console.log(`Servidor rodando na porta ${port}`));
