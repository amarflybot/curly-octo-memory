import {
  Controller,
  Get,
  UseGuards,
  Req, Post, Param, Body, NotFoundException,
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

import { Request } from 'express';
import {AddRolePermissionInput} from "../dto/add-role-permission.input";

@ApiTags('User')
@ApiBearerAuth()
@Controller('users')
export class UserController {
  constructor(private readonly usersSrv: UserService) {}

  @ApiOperation({
    summary: 'Find all users',
  })
  @Get()
  @UseGuards(AuthGuard(),)
  @UsePermissions({
    action: AuthActionVerb.READ,
    resource: Resource.USERS_LIST,
    possession: AuthPossession.ANY,
  })
  async findUsers() {
    return await this.usersSrv.findAll();
  }

  @ApiOperation({
    summary: 'Get own info',
  })
  @Get('me')
  @UseGuards(AuthGuard())
  async printCurrentUser(@Req() request: Request) {
    return request.user;
  }


  @ApiOperation({
    summary: 'get Resources related to the given user?',
  })
  @Post('/users/:id/resources')
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
  async getResourcesRelated(@Param('id') id: string,
                           @Body() addPermissionDto: AddRolePermissionInput,) {
    const user = await this.usersSrv.findById(id);

    if (!user) {
      throw new NotFoundException('The user not found');
    }

    return this.usersSrv.getResourceListForUserWithActions(user.username, addPermissionDto.domain, addPermissionDto.operation);
  }
}
