const fs = require('fs');

module.exports = {
  type: "postgres",
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  username: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  synchronize: true,
  logging: true,
  entities: ["src/entities/**/*.ts"],
  migrations: ["src/migrations/**/*.ts"],
  subscribers: ["src/subscribers/**/*.ts"],
  cli: {
    entitiesDir: "src/entities",
    migrationsDir: "src/migrations",
    subscribersDir: "src/subscribers",
  },
  ssl: {
    rejectUnauthorized: true,
    ca: fs.readFileSync('./certs/rds-ca-bundle.pem').toString(),
  },
  extra: {
      ssl: {
          // Disregard mismatch between localhost and rds.amazonaws.com
          rejectUnauthorized: false 
      }
  },
  options: {trustServerCertificate: true}
};
