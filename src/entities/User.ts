import { Entity, PrimaryGeneratedColumn, Column, OneToMany } from "typeorm";
// Importing the ActiveSession model for associating User with their active sessions
import { ActiveSession } from "./ActiveSession";

// @Entity decorator marks the class as a TypeORM entity to be stored into the 'user' table in the database
@Entity()
export class User {
  // This field will be automatically generated and incremented in the database whenever a new user is created
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  username: string;

  @Column()
  password_hash: string;

  // The 'secret' column stores a secret for each user, used for verifying OTP
  @Column()
  secret: string;

  // The 'authy_id' is the user's identifier in the Authy system, which is used to manage OTP
  @Column()
  authy_id: string;

  // OneToMany relationship, a user can have multiple active sessions by design - TODO: add privilege scope to tokens
  // The 'activeSession' function returns the associated active sessions for a given user
  @OneToMany(() => ActiveSession, (activeSession) => activeSession.user)
  activeSessions: ActiveSession[];
}
