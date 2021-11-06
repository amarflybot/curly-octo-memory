import {AuthAction, CustomAuthActionVerb} from 'nest-authz';
import { Resource, ResourceGroup } from '../resources';
import { ApiProperty } from '@nestjs/swagger';

export class AddRolePermissionInput {
  @ApiProperty()
  operation: AuthAction| CustomAuthActionVerb;

  @ApiProperty()
  resource: Resource | ResourceGroup | CustomAuthActionVerb;

  @ApiProperty()
  domain: string;
}
