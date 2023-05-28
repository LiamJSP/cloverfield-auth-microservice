import { Entity, PrimaryGeneratedColumn, Column, ManyToOne } from "typeorm";
// Importing the User model to associate an ActiveSession with a User
import { User } from "./User";

// @Entity decorator marks the class as a TypeORM entity to be stored in the 'activeSession' table in the database
@Entity()
export class ActiveSession {
  // This field will be automatically generated and incremented in the database whenever a new session is created
  @PrimaryGeneratedColumn()
  id: number;

  // ManyToOne relationship with User. This is the User associated with this session.
  // If the user is deleted, this active session will also be deleted due to the 'CASCADE' option
  @ManyToOne(() => User, (user) => user.activeSessions, { onDelete: "CASCADE" })
  user: User;

  // The 'jwt_token' column stores the JSON Web Token associated with this active session
  @Column()
  jwt_token: string;

  // The 'expiration' column stores the date and time when this active session will expire
  @Column()
  expiration: Date;
}
