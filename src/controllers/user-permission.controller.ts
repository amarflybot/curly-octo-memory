import {
  Controller,
  Get,
  UseGuards,
  Param,
  Post,
  Body,
  NotFoundException,
  Delete,
  Req,
} from '@nestjs/common';
import { UserService } from '../services';
import {
  AuthActionVerb,
  AuthPossession,
  UsePermissions,
} from 'nest-authz';

import { AuthGuard } from '@nestjs/passport';
import { ApiTags, ApiBearerAuth, ApiOperation } from '@nestjs/swagger';

import { Resource } from '../resources';
import {AddRolePermissionInput} from '../dto/add-role-permission.input';

@ApiTags('UserPermission')
@ApiBearerAuth()
@Controller()
export class UserPermissionController {
  constructor(private readonly usersSrv: UserService) {}

  @ApiOperation({
    summary: 'Get all permissions owned by the given user',
  })
  @Get('/users/:id/permissions')
  @UseGuards(AuthGuard())
  @UsePermissions({
    action: AuthActionVerb.READ,
    resource: Resource.USER_ROLES,
    possession: AuthPossession.OWN_ANY,
    isOwn: (ctx: any): boolean => {
      const request = ctx.getRequest();
      return request.user.id === request.params.id;
    },
  })
  async findUserPermissions(@Req() req, @Param('id') id: string) {
    const user = await this.usersSrv.findById(id);

    if (!user) {
      throw new NotFoundException('The user not found');
    }

    if (user.username === 'root') {
      // built-in superuser with all permissions
      return ['*'];
    }

    return this.usersSrv.userPermissions(user.username);
  }

  @ApiOperation({
    summary: 'Add permissions owned by the given user',
  })
  @Post('/users/:id/permissions')
  @UseGuards(AuthGuard(),)
  @UsePermissions({
    action: AuthActionVerb.CREATE,
    resource: Resource.USER_ROLES,
    possession: AuthPossession.OWN_ANY,
    isOwn: (ctx: any): boolean => {
      const request = ctx.getRequest();
      return request.user.id === request.params.id;
    },
  })
  async addUserPermissions(@Param('id') id: string,
                           @Body() addPermissionDto: AddRolePermissionInput,) {
    const user = await this.usersSrv.findById(id);

    if (!user) {
      throw new NotFoundException('The user not found');
    }

    if (user.username === 'root') {
      // built-in superuser with all permissions
      return ['*'];
    }

    return this.usersSrv.grantPermission(user.username, addPermissionDto.domain, addPermissionDto.operation, addPermissionDto.resource);
  }

  @ApiOperation({
    summary: 'Has permissions owned by the given user?',
  })
  @Post('/users/:id/hasPermission')
  @UseGuards(AuthGuard())
  @UsePermissions({
    action: AuthActionVerb.READ,
    resource: Resource.USER_ROLES,
    possession: AuthPossession.OWN_ANY,
    isOwn: (ctx: any): boolean => {
      const request = ctx.getRequest();
      return request.user.id === request.params.id;
    },
  })
  async hasUserPermissions(@Param('id') id: string,
                           @Body() addPermissionDto: AddRolePermissionInput,) {
    const user = await this.usersSrv.findById(id);

    if (!user) {
      throw new NotFoundException('The user not found');
    }

    if (user.username === 'root') {
      // built-in superuser with all permissions
      return ['*'];
    }

    return this.usersSrv.hasPermission(user.username, addPermissionDto.domain, addPermissionDto.operation, addPermissionDto.resource);
  }
}
