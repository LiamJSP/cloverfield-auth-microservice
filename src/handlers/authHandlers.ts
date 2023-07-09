import {
  APIGatewayProxyEvent,
  APIGatewayProxyResult,
  Context,
} from "aws-lambda";
import { DataSource } from "typeorm";
import * as speakeasy from "speakeasy";
import * as QRCode from "qrcode";
import * as bcrypt from "bcrypt";
import * as jwt from "jsonwebtoken";
import { User } from "../entities/User";
import { ActiveSession } from "../entities/ActiveSession";
import crypto from "crypto";
import { Client } from 'pg';
import net from 'net';
import fs from 'fs';
import path from 'path';

// Function to generate a default key with AES for JWT token generation
// This is used if a key is not manually set
// Generates a 256 bit key using the Node.js crypto library
function generateDefaultKeyWithAES(): Buffer {
  const key: Buffer = crypto.randomBytes(32);
  return key;
}

async function initialize(AppDataSource: DataSource): Promise<DataSource> {
  let initializedAppDataSource: DataSource;
  const dbInitPromise = AppDataSource.initialize();
  const timeoutPromise = new Promise((_, reject) => {
    const id = setTimeout(() => {
      clearTimeout(id);
      reject(new Error("Database connection timeout after 6 seconds"));
    }, 6000);
  });

  try {
    await Promise.race([dbInitPromise, timeoutPromise]);
    console.log("Data Source has been initialized!");
    initializedAppDataSource = AppDataSource;
  } catch (error) {
    console.error("Database connection error:", error);
    throw error;
  }
  return initializedAppDataSource;
}

async function checkHostReachability(host: string, port: number): Promise<void> {
  return new Promise((resolve, reject) => {
    const socket = new net.Socket();

    const onError = (error: Error) => {
      console.log(`Error connecting to host ${host}:${port} - ${error.message}`);
      socket.destroy();
      reject(error);
    };

    socket.setTimeout(5000);
    socket.once('error', onError);
    socket.once('timeout', () => onError(new Error('Timeout in connecting to host')));

    socket.connect(port, host, () => {
      console.log(`Host ${host}:${port} is reachable`);
      socket.end();
      resolve();
    });
  });
}

async function checkPostgresService(host: string, port: number, user: string, password: string, database: string): Promise<void> {
  const client = new Client({
    host,
    port,
    user,
    password,
    database,
  });

  try {
    await client.connect();
    console.log(`Postgres service is running on ${host}:${port}`);
  } catch (error: any) {
    if (error instanceof Error) {
      console.log(`Error connecting to Postgres service on ${host}:${port} - ${error.message}`);
    } else {
      console.log(`Error connecting to Postgres service on ${host}:${port}`);
    }
    throw error;
  } finally {
    await client.end();
  }
}


async function safeInitialize(AppDataSource: DataSource): Promise<APIGatewayProxyResult | DataSource> {
  try {
    await checkHostReachability(process.env.DB_HOST!, Number(process.env.DB_PORT));
    await checkPostgresService(process.env.DB_HOST!, Number(process.env.DB_PORT), process.env.DB_USERNAME!, process.env.DB_PASSWORD!, process.env.DB_NAME!);
    const initializedDataSource = await initialize(AppDataSource);
    return initializedDataSource;
  } catch (error) {
    let errorMessage = "An unknown error occurred.";
    if (error instanceof Error) {
      errorMessage = error.message;
      console.error(errorMessage);
    }
    return createApiResponse(500, { error: errorMessage });
  }
}

// Helper function to create an API Gateway response
export function createApiResponse(
  statusCode: number,
  body: any
): APIGatewayProxyResult {
  return {
    statusCode,
    body: JSON.stringify(body),
  };
}

function isApiGatewayResponse(object: any): object is APIGatewayProxyResult {
  return "statusCode" in object;
}


// Function to register a new user
export async function register(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  console.log("Register fired, pre DB");

  const AppDataSource = new DataSource({
    type: "postgres",
    host: process.env.DB_HOST,
    port: Number(process.env.DB_PORT) || 5432,
    username: process.env.DB_USERNAME,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    entities: [`${__dirname}/../entities/*{.ts,.js}`],
    synchronize: true,
    ssl: {
      ca: fs.readFileSync(path.join(__dirname, '../certs/rds-ca-bundle.pem')).toString()
    },
    extra: {
        ssl: {
            // Disregard mismatch between localhost and rds.amazonaws.com
            rejectUnauthorized: false 
        }
    } 
  });

  const initializedDataSourceOrError = await safeInitialize(AppDataSource);
  if (isApiGatewayResponse(initializedDataSourceOrError)) {
    return initializedDataSourceOrError;
  }

  console.log("DB initialized successfully.");
  const JWT_SECRET: string = process.env.JWT_SECRET || generateDefaultKeyWithAES().toString("base64");

  const body = JSON.parse(event.body || "{}");
  const { username, password, email } = body;

  if (!username || !password || !email) {
    return createApiResponse(400, { error: "Missing required fields" });
  }

  const userRepository = AppDataSource.manager.getRepository(User);
  const existingUser = await userRepository.findOne({ where: { username } });

  if (existingUser) {
    return createApiResponse(409, { error: "Username already exists" });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  const secret = speakeasy.generateSecret({ length: 20 });

  const newUser = userRepository.create({
    username,
    password_hash: hashedPassword,
    secret: secret.base32,
  });

  try {
    await userRepository.save(newUser);

    console.log(`Successfully saved user: ${username}`);
  } catch (error) {
    console.error("Error saving user to database:", error);
    return createApiResponse(500, { error: "Error saving user to database" });
  }

  const otpUrl = `otpauth://totp/${encodeURIComponent(newUser.username)}?secret=${encodeURIComponent(secret.base32)}&issuer=RCS_Auth_Microservice`;

  let qrDataUrl;
  try {
    qrDataUrl = await QRCode.toDataURL(otpUrl);
  } catch (qrErr) {
    return createApiResponse(500, { error: "Error generating QR code for 2FA" });
  }

  return createApiResponse(201, { message: "User registered successfully", qr_code_url: qrDataUrl });
}

export async function login(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  console.log("Login fired, pre DB");

  const AppDataSource = new DataSource({
    type: "postgres",
    host: process.env.DB_HOST,
    port: Number(process.env.DB_PORT) || 5432,
    username: process.env.DB_USERNAME,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    entities: [`${__dirname}/../entities/*{.ts,.js}`],
    synchronize: true,
    ssl: {
      ca: fs.readFileSync(path.join(__dirname, '../certs/rds-ca-bundle.pem')).toString()
    },
    extra: {
        ssl: {
            // Disregard mismatch between localhost and rds.amazonaws.com
            rejectUnauthorized: false 
        }
    } 
  });

  const initializedDataSourceOrError = await safeInitialize(AppDataSource);
  if (isApiGatewayResponse(initializedDataSourceOrError)) {
    return initializedDataSourceOrError;
  }

  console.log("DB initialized successfully.");

  const JWT_SECRET: string = process.env.JWT_SECRET || generateDefaultKeyWithAES().toString("base64");
  const TOKEN_EXPIRATION_TIME: string = process.env.TOKEN_EXPIRATION_TIME || "1h";

  const body = JSON.parse(event.body || "{}");
  const { username, password, otp_token } = body;

  if (!username || !password || !otp_token) {
    return createApiResponse(400, { error: "Missing required fields" });
  }

  const userRepository = AppDataSource.manager.getRepository(User);
  const user = await userRepository.findOne({ where: { username } });

  if (!user) {
    return createApiResponse(404, { error: "User not found" });
  }

  const passwordMatch = await bcrypt.compare(password, user.password_hash);

  if (!passwordMatch) {
    return createApiResponse(401, { error: "Invalid password" });
  }

  const verified = speakeasy.totp.verify({
    secret: user.secret,
    encoding: "base32",
    token: otp_token,
    window: 2,
  });

  if (!verified) {
    return createApiResponse(401, { error: "Invalid OTP token" });
  }

  const token = jwt.sign({ userId: user.id }, JWT_SECRET, {
    expiresIn: TOKEN_EXPIRATION_TIME,
  });

  const activeSessionRepository = AppDataSource.manager.getRepository(ActiveSession);
  const expirationDate = new Date();
  expirationDate.setHours(expirationDate.getHours() + 1);

  const newSession = activeSessionRepository.create({
    user,
    jwt_token: token,
    expiration: expirationDate,
  });

  await activeSessionRepository.save(newSession);

  return createApiResponse(200, { token });
}

export async function isTokenValid(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  console.log("Token validation fired, pre DB");

  const AppDataSource = new DataSource({
    type: "postgres",
    host: process.env.DB_HOST,
    port: Number(process.env.DB_PORT) || 5432,
    username: process.env.DB_USERNAME,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    entities: [`${__dirname}/../entities/*{.ts,.js}`],
    synchronize: true,
    ssl: {
      ca: fs.readFileSync(path.join(__dirname, '../certs/rds-ca-bundle.pem')).toString()
    },
    extra: {
        ssl: {
            // Disregard mismatch between localhost and rds.amazonaws.com
            rejectUnauthorized: false 
        }
    } 
  });

  const initializedDataSourceOrError = await safeInitialize(AppDataSource);
  if (isApiGatewayResponse(initializedDataSourceOrError)) {
    return initializedDataSourceOrError;
  }

  console.log("DB initialized successfully.");

  const JWT_SECRET: string = process.env.JWT_SECRET || generateDefaultKeyWithAES().toString("base64");

  const token = event.headers.authorization?.split(" ")[1];
  console.log("token: " + token + " event header: " + event.headers.authorization);
  if (!token) {
    return createApiResponse(401, { error: "No token provided" });
  }

  try {
    jwt.verify(token, JWT_SECRET);
    return createApiResponse(200, { isValid: true });
  } catch (error) {
    return createApiResponse(401, { error: "Invalid token", isValid: false });
  }
}