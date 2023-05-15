
# Cloverfield - Auth Microservice

This Typescript NodeJS microservice handles registration, authentication, and token validation for the Cloverfield SaaS APIs and services. It uses TypeORM and Postgres for storage.

This repo is ts: 'strict'.

Process Flow is as follows:

1. If user doesn't exist, user registers by sending a request to the "/registration-request" endpoint. This request includes registration of an OTP token with their app of choice by QR code scanning. User registration is approved by an OTP sent to the admin's phone by SMS.
2. User confirms registration by sending the code provided by the admin to the "/confirm-registration" endpoint.
3. User logs in by sending a request containing their username, password, and their own OTP, to the "/login" endpoint. The microservice is restricted to using a special postgres function, instead of raw SQL queries. The actual SQL query is embedded in the postgres database inside the function. This ensures the the microservice cannot retrieve the contents of the database tables if compromised.
4. If authentication is successful, a JWT (token) is returned. This token is valid for X minutes. The token is used to interact with internal services and APIs.

## Roadmap

- Currently a Proof-of-Concept. Significant security enhancement still required. It's almost certainly better to use AWS Secrets Manager than RDS both for security and costs, but I wanted to start with a more agnostic PoC.

- Consider posssible Denial-of-Service vulnerabilities and apply rate-limiting logic.

- Tests

- Documentation

