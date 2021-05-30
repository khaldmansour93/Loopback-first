import {
  repository,
} from '@loopback/repository';
import {
  param,
  get,
  getModelSchemaRef,
} from '@loopback/rest';
import {
  Product,
  User,
} from '../models';
import {ProductRepository} from '../repositories';

export class ProductUserController {
  constructor(
    @repository(ProductRepository)
    public productRepository: ProductRepository,
  ) { }

  @get('/products/{id}/user', {
    responses: {
      '200': {
        description: 'User belonging to Product',
        content: {
          'application/json': {
            schema: {type: 'array', items: getModelSchemaRef(User)},
          },
        },
      },
    },
  })
  async getUser(
    @param.path.number('id') id: typeof Product.prototype.id,
  ): Promise<User> {
    return this.productRepository.user(id);
  }
}
