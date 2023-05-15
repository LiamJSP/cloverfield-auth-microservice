import { Entity, PrimaryGeneratedColumn, Column, ManyToOne } from "typeorm";
import { User } from "./User";

@Entity()
export class ActiveSession {
  @PrimaryGeneratedColumn()
  id: number;

  @ManyToOne(() => User, (user) => user.activeSessions, { onDelete: "CASCADE" })
  user: User;

  @Column()
  jwt_token: string;

  @Column()
  expiration: Date;
}
