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

// Function to generate a default key with AES for JWT token generation
// This is used if a key is not manually set
// Generates a 256 bit key using the Node.js crypto library
function generateDefaultKeyWithAES(): Buffer {
  const key: Buffer = crypto.randomBytes(32);
  return key;
}

// Configuration variables for JWT, token expiration time, and Authy
const JWT_SECRET: string = process.env.JWT_SECRET || generateDefaultKeyWithAES().toString('base64');
const TOKEN_EXPIRATION_TIME:string = process.env.TOKEN_EXPIRATION_TIME || "1h";
const AUTHY_API_KEY:string = process.env.AUTHY_API_KEY || "no_key_in_env";
const authyClient = authy(AUTHY_API_KEY);

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

// Function to register a new user
export async function register(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  // Parses the request body
  const body = JSON.parse(event.body || "{}");
  const { username, password, email, phone_number, country_code } = body;

  // Validates if all fields are provided
  if (!username || !password || !email || !phone_number || !country_code) {
    return createApiResponse(400, { error: "Missing required fields" });
  }

  // Checks for existing user
  const userRepository = AppDataSource.manager.getRepository(User);
  const existingUser = await userRepository.findOne({ where: { username } });

  if (existingUser) {
    return createApiResponse(409, { error: "Username already exists" });
  }

  // Hashes the user password
  const hashedPassword = await bcrypt.hash(password, 10);

  // Registers the user in Authy, generates a secret, and saves the user in the database
  const registerUserResponse = await new Promise<APIGatewayProxyResult>(
    (resolve) => {
      console.log("Beginning Register Logic");
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
            const secret = speakeasy.generateSecret({ length: 20 });

            const newUser = userRepository.create({
              username,
              password_hash: hashedPassword,
              authy_id: regRes.user.id,
              secret: secret.base32,
            });

            try {
              await userRepository.save(newUser);

              // Log successful user save
              console.log(`Successfully saved user: ${username}`);
            } catch (error) {
              console.error('Error saving user to database:', error);
              resolve(createApiResponse(500, { error: 'Error saving user to database' }));
              return;
            }

            // Generates the OTP registration URL, encoded into a QR code for the Authy app
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
  // Parses the request body
  const body = JSON.parse(event.body || "{}");
  const { username, password, authy_code } = body;

  // Validates if all fields are provided
  if (!username || !password || !authy_code) {
    return createApiResponse(400, { error: "Missing required fields" });
  }

  // Checks if the user exists
  const userRepository = AppDataSource.manager.getRepository(User);
  const user = await userRepository.findOne({ where: { username } });

  if (!user) {
    return createApiResponse(404, { error: "User not found" });
  }

  // Verifies the user password
  const passwordMatch = await bcrypt.compare(password, user.password_hash);

  if (!passwordMatch) {
    return createApiResponse(401, { error: "Invalid password" });
  }

  // Verifies the Authy token
  const verified = speakeasy.totp.verify({
    secret: user.secret,
    encoding: "base32",
    token: authy_code,
    window: 2,
  });

  if (!verified) {
    return createApiResponse(401, { error: "Invalid Authy code" });
  }

  // Signs the JWT and sets the token expiration time
  const token = jwt.sign({ userId: user.id }, JWT_SECRET, {
    expiresIn: TOKEN_EXPIRATION_TIME,
  });

  // Creates a new active session for the user, and set the auto-logout expiration date
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

  // Returns the JWT in the response
  return createApiResponse(200, { token });
}

// Function to check if a JWT token is valid
export async function isTokenValid(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  // Retrieves the token from the authorization header
  const token = event.headers.authorization?.split(" ")[1];

  if (!token) {
    return createApiResponse(401, { error: "No token provided" });
  }

  // Verifies the JWT
  try {
    jwt.verify(token, JWT_SECRET);
    return createApiResponse(200, { isValid: true });
  } catch (error) {
    return createApiResponse(401, { error: "Invalid token", isValid: false });
  }
}
