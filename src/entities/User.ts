import { Entity, PrimaryGeneratedColumn, Column, OneToMany } from "typeorm";
import { ActiveSession } from "./ActiveSession";

@Entity()
export class User {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  username: string;

  @Column()
  password_hash: string;

  @Column()
  secret: string;

  @Column()
  authy_id: string;

  @OneToMany(() => ActiveSession, (activeSession) => activeSession.user)
  activeSessions: ActiveSession[];
}
