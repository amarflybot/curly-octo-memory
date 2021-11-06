import {ExecutionContext, Module} from '@nestjs/common';
import * as casbin from 'casbin';

import {AppController} from './controllers/app.controller';
import {UserController} from './controllers/user.controller';
import {RoleController} from './controllers/role.controller';
import {AuthController} from './controllers/auth.controller';
import {UserPermissionController} from './controllers/user-permission.controller';
import {UserRoleController} from './controllers/user-role.controller';

import {PassportModule} from '@nestjs/passport';
import {JwtModule} from '@nestjs/jwt';
import {ConfigModule} from './config.module';

import {AuthService, ConfigService, JwtStrategy, RoleService, UserService,} from './services';
import {AUTHZ_ENFORCER, AuthZModule} from 'nest-authz';
import TypeORMAdapter from 'typeorm-adapter';

@Module({
  imports: [
    ConfigModule,
    PassportModule.register({
      defaultStrategy: 'jwt',
    }),
    JwtModule.register({
      secret: 'secretKey',
    }),
    /*AuthZModule.register({
      imports: [ConfigModule],
      enforcerProvider: {
        provide: AUTHZ_ENFORCER,
        useFactory: async (configSrv: ConfigService) => {
          const config = await configSrv.getAuthConfig();
          return casbin.newEnforcer(config.model, config.policy);
        },
        inject: [ConfigService],
      },
      usernameFromContext: (ctx: ExecutionContext) => {
        const request = ctx.switchToHttp().getRequest();
        return request.user && request.user.username;
      },
    }),*/
    AuthZModule.register({
      model: 'model.conf',
      policy: TypeORMAdapter.newAdapter({
        name: 'casbin',
        type: 'postgres',
        host: 'localhost',
        port: 5432,
        username: 'postgres',
        password: 'changeme',
        database: 'postgres',
        logging: 'all',
        schema: 'casbin_domain'
      }),
      usernameFromContext: (ctx) => {
        const request = ctx.switchToHttp().getRequest();
        return request.user && request.user.username;
      },
    }),
  ],
  controllers: [
    AppController,
    AuthController,
    UserController,
    RoleController,
    UserRoleController,
    UserPermissionController,
  ],
  providers: [AuthService, UserService, JwtStrategy, RoleService],
})
export class AppModule {}
