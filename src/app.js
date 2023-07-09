import express from "express";
import cors from "cors";
import { MongoClient } from "mongodb";
import dotenv from "dotenv";
import joi from "joi";
import bcrypt from "bcrypt";
import { v4 as uuid } from "uuid";
import dayjs from "dayjs";

// URL deploy do back-end:
// https://mywallet-api-emzm.onrender.com

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
    email: joi.string().email().required(),
    password: joi.string().min(3).required(),
  });

  const validation = schemaUser.validate(req.body, { abortEarly: false });
  if (validation.error) {
    const errors = validation.error.details.map((detail) => detail.message);
    return res.status(422).send(errors);
  }

  const hash = bcrypt.hashSync(password, 10);

  try {
    const user = await db
      .collection("users")
      .findOne({ $or: [{ name: name }, { email: email }] });
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
    email: joi.string().email().required(),
    password: joi.string().min(3).required(),
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

app.get("/home", async (req, res) => {
  const { authorization } = req.headers;
  const token = authorization?.replace("Bearer ", "");

  if (!token) return res.sendStatus(401);

  try {
    const session = await db.collection("sessions").findOne({ token: token });
    if (!session) return res.sendStatus(401);
  } catch (err) {
    res.status(500).send(err.message);
  }
});

app.post("/nova-transacao/:tipo", async (req, res) => {
  const { tipo } = req.params;
  const { descricao, valor } = req.body;
  const { authorization } = req.headers;
  const token = authorization?.replace("Bearer ", "");

  if (!token) return res.sendStatus(401);

  const schemaTransacao = joi.object({
    tipo: joi.string().valid("entrada", "saida").required(),
    descricao: joi.string().required(),
    valor: joi.number().positive().required(),
  });

  const validation = schemaTransacao.validate(
    { ...req.body, tipo: tipo },
    { abortEarly: false }
  );

  if (validation.error)
    return res
      .status(422)
      .send(validation.error.details.map((detail) => detail.message));

  if (!Number.isInteger(valor))
    return res.status(422).send("O valor deve ser do tipo float!");

  try {
    const session = await db.collection("sessions").findOne({ token: token });
    if (!session) return res.sendStatus(401);

    await db.collection("transacoes").insertOne({
      token: token,
      tipo: tipo,
      descricao: descricao,
      valor: valor,
      data: dayjs().format("DD/MM"),
    });

    res.sendStatus(201);
  } catch (err) {
    res.status(500).send(err.message);
  }
});
const port = process.env.PORT || 5000;
app.listen(port, () => console.log(`Servidor rodando na porta ${port}`));
