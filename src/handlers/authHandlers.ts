import {
  APIGatewayProxyEvent,
  APIGatewayProxyResult,
  Context,
} from "aws-lambda";
import * as speakeasy from "speakeasy";
import * as QRCode from "qrcode";
import { AppDataSource } from "../index";
import * as bcrypt from "bcrypt";
import * as jwt from "jsonwebtoken";
import authy from "authy";
import { User } from "../entities/User";
import { ActiveSession } from "../entities/ActiveSession";
import crypto from 'crypto';

//Used if a key is not manually set. You are intended to set a key manually - this is a failover in case the user does not.
function generateDefaultKeyWithAES(): Buffer {
  // Generate 32 random bytes (256 bits)
  const key: Buffer = crypto.randomBytes(32);
  return key;
}

const JWT_SECRET: string = process.env.JWT_SECRET || generateDefaultKeyWithAES().toString('base64');
const TOKEN_EXPIRATION_TIME:string = process.env.TOKEN_EXPIRATION_TIME || "1h";
const AUTHY_API_KEY:string =
  process.env.AUTHY_API_KEY || "no_key_in_env";
const authyClient = authy(AUTHY_API_KEY);

export function createApiResponse(
  statusCode: number,
  body: any
): APIGatewayProxyResult {
  return {
    statusCode,
    body: JSON.stringify(body),
  };
}

export async function register(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const body = JSON.parse(event.body || "{}");
  const { username, password, email, phone_number, country_code } = body;

  if (!username || !password || !email || !phone_number || !country_code) {
    return createApiResponse(400, { error: "Missing required fields" });
  }

  const userRepository = AppDataSource.manager.getRepository(User);
  const existingUser = await userRepository.findOne({ where: { username } });

  if (existingUser) {
    return createApiResponse(409, { error: "Username already exists" });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  const registerUserResponse = await new Promise<APIGatewayProxyResult>(
    (resolve) => {
      authyClient.register_user(
        email,
        phone_number,
        country_code,
        async (err, regRes) => {
          if (err) {
            console.error("Authy registration error:", err);
            resolve(
              createApiResponse(500, {
                error: "Error registering user with Authy",
              })
            );
          } else {
            // Generate a base32-encoded secret
            const secret = speakeasy.generateSecret({ length: 20 });

            const newUser = userRepository.create({
              username,
              password_hash: hashedPassword,
              authy_id: regRes.user.id,
              secret: secret.base32,
            });

            await userRepository.save(newUser);

            // Generate the QR code for the Authy app
            const otpUrl = `otpauth://totp/${encodeURIComponent(
              newUser.username
            )}?secret=${encodeURIComponent(
              secret.base32
            )}&issuer=RCS_Auth_Microservice`;
            QRCode.toDataURL(otpUrl, (qrErr, qrDataUrl) => {
              if (qrErr) {
                resolve(
                  createApiResponse(500, {
                    error: "Error generating QR code for 2FA",
                  })
                );
              } else {
                resolve(
                  createApiResponse(201, {
                    message: "User registered successfully",
                    qr_code_url: qrDataUrl,
                  })
                );
              }
            });
          }
        }
      );
    }
  );

  return registerUserResponse;
}

export async function login(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const body = JSON.parse(event.body || "{}");
  const { username, password, authy_code } = body;

  if (!username || !password || !authy_code) {
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

  // Use speakeasy to verify the token locally
  const verified = speakeasy.totp.verify({
    secret: user.secret,
    encoding: "base32",
    token: authy_code,
    window: 2, // Allow a window of +/- 2 time steps to account for time drift
  });

  if (!verified) {
    return createApiResponse(401, { error: "Invalid Authy code" });
  }

  const token = jwt.sign({ userId: user.id }, JWT_SECRET, {
    expiresIn: TOKEN_EXPIRATION_TIME,
  });

  const activeSessionRepository =
    AppDataSource.manager.getRepository(ActiveSession);
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

export async function isTokenValid(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const token = event.headers.authorization?.split(" ")[1];

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

