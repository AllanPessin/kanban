import { IsString, IsInt, IsEmail, IsStrongPassword } from 'class-validator';

export class CreateUserDTO {
  @IsEmail()
  @IsString()
  email: string;

  @IsStrongPassword({
    minLength: 8,
    minLowercase: 1,
    minUppercase: 1,
    minNumbers: 1,
    minSymbols: 1,
  })
  password: string;
}
