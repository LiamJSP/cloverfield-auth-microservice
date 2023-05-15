import {
  APIGatewayProxyEvent,
  APIGatewayProxyResult,
  Context,
} from "aws-lambda";
import * as authHandlers from "../handlers/authHandlers";
import { initialize } from "../index";

export async function main(
  event: APIGatewayProxyEvent,
  context: Context
): Promise<APIGatewayProxyResult> {
  // Call the initialize function before processing the request
  await initialize();

  const path = event.path;

  if (path === "/register") {
    return authHandlers.register(event);
  } else if (path === "/login") {
    return authHandlers.login(event);
  } else if (path === "/isTokenValid") {
    return authHandlers.isTokenValid(event);
  } else {
    return authHandlers.createApiResponse(404, { error: "Path not found" });
  }
}
