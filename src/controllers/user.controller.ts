import {AuthenticationBindings, TokenService} from '@loopback/authentication';
import {
  Credentials,
  MyUserService,
  TokenServiceBindings,
  UserServiceBindings,
} from '@loopback/authentication-jwt';
import {inject} from '@loopback/core';
import {model, property, repository} from '@loopback/repository';
import {
  get,
  HttpErrors,
  post,
  Request,
  requestBody,
  RestBindings,
  SchemaObject,
} from '@loopback/rest';
import {SecurityBindings, securityId, UserProfile} from '@loopback/security';
import {genSalt, hash} from 'bcryptjs';
import {promisify} from 'util';
import {secured} from '../authentication/jwt';
import {User} from '../models';
import {UserRepository} from '../repositories';
const {sign} = require('jsonwebtoken');
const signAsync = promisify(sign);

@model()
export class NewUserRequest extends User {
  @property({
    type: 'string',
    required: true,
  })
  password: string;
}

const CredentialsSchema: SchemaObject = {
  type: 'object',
  required: ['email', 'password'],
  properties: {
    email: {
      type: 'string',
      format: 'email',
    },
    password: {
      type: 'string',
      minLength: 8,
    },
  },
};

export const CredentialsRequestBody = {
  description: 'The input of login function',
  required: true,
  content: {
    'application/json': {schema: CredentialsSchema},
  },
};

export class UserController {
  constructor(
    @inject(RestBindings.Http.REQUEST) private request: Request,
    @inject(TokenServiceBindings.TOKEN_SERVICE)
    public jwtService: TokenService,
    @inject(UserServiceBindings.USER_SERVICE)
    public userService: MyUserService,
    @inject(SecurityBindings.USER, {optional: true})
    public user: UserProfile,
    @repository(UserRepository) protected userRepository: UserRepository,
  ) {}

  @post('/users/login', {
    responses: {
      '200': {
        description: 'Token',
        content: {
          'application/json': {
            schema: {
              type: 'object',
              properties: {
                token: {
                  type: 'string',
                },
              },
            },
          },
        },
      },
    },
  })
  async login(@requestBody() credentials: Credentials) {
    if (!credentials.email || !credentials.password)
      throw new HttpErrors.BadRequest('Missing Email or Password');
    const user = await this.userRepository.findOne({
      where: {email: credentials.email},
    });
    if (!user) throw new HttpErrors.Unauthorized('Invalid credentials');

    var bcrypt = require('bcryptjs');
    const isPasswordMatched = await bcrypt.compare(
      credentials.password,
      user.password,
    );

    if (!isPasswordMatched)
      throw new HttpErrors.Unauthorized('Invalid credentials');

    const tokenObject = {email: credentials.email};

    // const token = await this.jwtService.generateToken(tokenObject);
    const token = await signAsync(tokenObject, 'testjwt', {expiresIn: 60 * 60}); //token expire in one hour
    return token;
  }

  @secured()
  @get('/whoAmI', {
    responses: {
      '200': {
        description: 'Return current user',
        content: {
          'application/json': {
            schema: {
              type: 'string',
            },
          },
        },
      },
    },
  })
  async whoAmI(
    @inject(AuthenticationBindings.CURRENT_USER)
    currentUserProfile: UserProfile,
  ): Promise<any> {
    return currentUserProfile[securityId];
  }

  @post('/signup', {
    responses: {
      '200': {
        description: 'User',
        content: {
          'application/json': {
            schema: {
              'x-ts-type': User,
            },
          },
        },
      },
    },
  })
  async createUser(@requestBody() user: User): Promise<any> {
    //check if email already exist
    const findUser = this.userRepository.find({where: {email: user.email}});

    //if email exist return message
    if ((await findUser).length >= 1) {
      throw new HttpErrors.BadRequest('Email already exist.');
    }

    if (!user['password'])
      throw new HttpErrors.BadRequest('User Must Have Password.');
    //if not lets create hashed password
    const password = await hash(user.password, await genSalt());
    user['password'] = password;

    let userData = await this.userRepository.create(user);
    return userData;
  }
}
