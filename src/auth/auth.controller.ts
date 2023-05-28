import { OAuth2Client } from 'google-auth-library';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { UsersService } from 'src/users/users.service';
import {
  Body,
  Controller,
  Get,
  Post,
  Req,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';

@Controller('auth')
export class AuthController {
  constructor(
    private authService: AuthService,
    private userService: UsersService
  ) {}

  @Post('/google/login')
  async googleLogin(@Body('token') token: string) {
    try {
      const client = new OAuth2Client(
        process.env.GOOGLE_CLIENT_ID,
        process.env.GOOGLE_CLIENT_SECRET
      );

      const ticket = await client.verifyIdToken({
        idToken: token,
        audience: process.env.GOOGLE_CLIENT_ID,
      });

      const { email } = ticket.getPayload();
      return await this.authService.loginFromGoogle(email);
    } catch (error) {
      throw new UnauthorizedException('Unauthorized');
    }
  }

  @Get('/me')
  @UseGuards(JwtAuthGuard)
  async me(@Req() req) {
    const user = await this.userService.getUserById(req.user.id);
    if (!user) throw new UnauthorizedException('Unauthorized');
    return user;
  }
}
