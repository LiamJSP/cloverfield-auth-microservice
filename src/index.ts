import express from "express";
import * as speakeasy from "speakeasy";
import * as QRCode from "qrcode";
import { DataSource } from "typeorm";
import * as bcrypt from "bcrypt";
import * as jwt from "jsonwebtoken";
import authy from "authy";
import { User } from "./entities/User";
import { ActiveSession } from "./entities/ActiveSession";

const app = express();
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET;
const TOKEN_EXPIRATION_TIME = process.env.TOKEN_EXPIRATION_TIME || "1h";
const AUTHY_API_KEY = process.env.AUTHY_API_KEY;
const authyClient = authy(AUTHY_API_KEY);

const AppDataSource = new DataSource({
  type: "postgres",
  host: process.env.DB_HOST,
  port: Number(process.env.DB_PORT) || 5432,
  username: process.env.DB_USERNAME,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  entities: [`${__dirname}/entities/*{.ts,.js}`],
  synchronize: true,
});

let initializedAppDataSource: DataSource;

async function initialize(): Promise<DataSource> {
  if (!initializedAppDataSource) {
    await AppDataSource.initialize();
    console.log("Data Source has been initialized!");
    initializedAppDataSource = AppDataSource;
  }
  return initializedAppDataSource;
}

export { AppDataSource, initialize };
