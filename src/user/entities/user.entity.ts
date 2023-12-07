import { Exclude } from 'class-transformer';

export class UserEntity {
  email: string;
  password: string;
  fullName: string;
  @Exclude()
  confirmPasword: string;

  constructor(partial: Partial<UserEntity>) {
    Object.assign(this, partial);
  }
}
