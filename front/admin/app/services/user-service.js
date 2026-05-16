import { createCrudService } from '../utils/http-utils.js';
export const users = createCrudService('users');
export const { list: listUsers, get: getUser, create: createUser, update: updateUser, delete: deleteUser } = users;
