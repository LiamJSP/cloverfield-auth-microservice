import {
  APIGatewayProxyEvent,
  APIGatewayProxyResult,
  Context,
} from "aws-lambda";
import * as authHandlers from "../handlers/authHandlers";
import { initialize } from "../index";

// The main function is the entry point for the AWS Lambda function
// This function will be called every time the API receives a request
export async function main(
  event: APIGatewayProxyEvent,
  context: Context
): Promise<APIGatewayProxyResult> {
  // Initialize the application (connect to database, etc.) before handling the request
  await initialize();

  // The 'path' property of 'event' tells us which endpoint the client hit
  const path = event.path;
  console.log("Request received: ", event);

  // We call different handlers based on the path
  // This is the main router/dispatcher for incoming requests
  if (path === "/register") {
    // If the request was to /register, call the register handler
    return authHandlers.register(event);
  } else if (path === "/login") {
    // If the request was to /login, call the login handler
    return authHandlers.login(event);
  } else if (path === "/isTokenValid") {
    // If the request was to /isTokenValid, call the isTokenValid handler
    return authHandlers.isTokenValid(event);
  } else {
    // If none of the above paths match, return a 404 not found error
    return authHandlers.createApiResponse(404, { error: "Path not found" });
  }
}
