import bcrypt from 'bcryptjs';
import Joi from 'joi';
import mongoSanitize from 'express-mongo-sanitize';
import { Instructor } from '../models/Instructor.js';

const DIRECTORY_FIELDS = '_id name department role';

const loginSchema = Joi.object({
  username: Joi.string().required(),
  password: Joi.string().max(72, 'utf8').required()
}).required().strict();

const searchSchema = Joi.object({
  name: Joi.string().max(120).pattern(/^[^\0]*$/).allow(''),
  department: Joi.string().max(120),
  role: Joi.string().max(120)
}).required().strict();

function validateInput(schema, input) {
  const { error, value } = schema.validate(input);
  return error || mongoSanitize.has(input) ? null : value;
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

export async function loginInstructor(req, res, next) {
  try {
    const credentials = validateInput(loginSchema, req.body);
    if (!credentials) {
      return res.status(400).json({ message: 'Invalid login input' });
    }

    const { username, password } = credentials;
    const instructor = await Instructor.findOne({ username })
        .select('_id name username department role password')
        .lean();

    if (!instructor?.password || !(await bcrypt.compare(password, instructor.password))) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    return res.json({
      instructor: {
        id: instructor._id.toString(),
        name: instructor.name,
        username: instructor.username,
        department: instructor.department,
        role: instructor.role
      }
    });
  } catch (err) {
    next(err);
  }
}

export async function getDirectory(req, res, next) {
  try {
    const instructors = await Instructor.find()
        .select(DIRECTORY_FIELDS)
        .sort({ name: 1 })
        .lean();

    return res.json({ instructors });
  } catch (err) {
    next(err);
  }
}

export async function searchInstructors(req, res, next) {
  try {
    const search = validateInput(searchSchema, req.query);
    if (!search) {
      return res.status(400).json({ message: 'Invalid search filters' });
    }

    const { name, department, role } = search;
    const filter = {};

    if (name !== undefined) {
      const term = name.trim();
      filter.name = term ? new RegExp(escapeRegExp(term), 'i') : '';
    }
    if (department !== undefined) filter.department = department;
    if (role !== undefined) filter.role = role;

    const instructors = await Instructor.find(filter)
        .select(DIRECTORY_FIELDS)
        .sort({ name: 1 })
        .lean();

    return res.json({ count: instructors.length, instructors });
  } catch (err) {
    next(err);
  }
}