import { Field, InputType } from '@nestjs/graphql';
import {
  IsEmail,
  IsNotEmpty,
  IsString,
  IsStrongPassword,
  MinLength,
} from 'class-validator';
@InputType()
export class CreateUserDto {
  @Field()
  @IsNotEmpty({ message: 'Full name is required' })
  @IsString()
  fullname: string;

  @Field()
  @IsNotEmpty({ message: 'Password is required' })
  @MinLength(8, { message: 'Password has to be at least 8 characters' })
  @IsStrongPassword()
  password: string;

  @Field()
  @IsNotEmpty({ message: 'Confirm Password is required' })
  confirmPassword: string;

  @Field()
  @IsNotEmpty({ message: 'Email is required' })
  @IsEmail({}, { message: 'Please enter a valid email' })
  email: string;
}
