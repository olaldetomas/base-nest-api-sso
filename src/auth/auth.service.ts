import { JwtPayload } from 'src/auth/interfaces/jwt-payload-interface';
import { User } from 'src/users/entities/user.entity';
import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UsersService } from '../users/users.service';

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService
  ) {}

  async loginFromGoogle(email: string) {
    const user = await this.usersService.getByEmail(email);
    if (user) {
      return await this.generateToken(user);
    }
    const createdUser = await this.usersService.save({ email });
    return await this.generateToken(createdUser);
  }

  async generateToken(user: User) {
    const payload: JwtPayload = { email: user.email, userId: user.id };
    return {
      token: this.jwtService.sign(payload),
    };
  }
}
