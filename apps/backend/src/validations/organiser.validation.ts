import {z} from 'zod'
import { Prisma, OrganizerType } from '@prisma/client'; 

const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)+$/;
const passwordRegex = /^(?=\S{8,128}$)(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).*$/;

const usernameRegex = /^[a-z0-9](?:[a-z0-9_]{1,28}[a-z0-9])?$/;
const phoneRegex = /^\+?[1-9]\d{7,14}$/;

const signupSchema = z.object({
  name: z
    .string()
    .trim()
    .min(2, 'Name must contain at least 2 characters')
    .max(100, 'Name must not exceed 100 characters')
    .regex(/^[\p{L}\p{M} .'-]+$/u, 'Name contains invalid characters'),

  username: z
    .string()
    .trim()
    .toLowerCase()
    .min(3, 'Username must contain at least 3 characters')
    .max(30, 'Username must not exceed 30 characters')
    .regex(
      usernameRegex,
      'Username must use lowercase letters, numbers, or underscores; it cannot start or end with an underscore',
    ),

  email: z
    .string()
    .trim()
    .toLowerCase()
    .max(254, 'Email is too long')
    .regex(emailRegex, 'Enter a valid email address'),

  password: z
    .string()
    .min(8, 'Password must contain at least 8 characters')
    .max(128, 'Password must not exceed 128 characters')
    .regex(
      passwordRegex,
      'Password must contain uppercase and lowercase letters, a number, and a special character, with no spaces',
    ),

  organizationName: z
    .string()
    .trim()
    .min(2, 'Organization name must contain at least 2 characters')
    .max(150, 'Organization name must not exceed 150 characters'),

  type: z.nativeEnum(OrganizerType),

  description: z
    .string()
    .trim()
    .max(1000, 'Description must not exceed 1000 characters')
    .optional(),

  website: z
    .string()
    .trim()
    .max(2048, 'Website URL is too long')
    .refine(
      (value) => value === '' || z.string().url().safeParse(value).success,
      'Enter a valid website URL',
    )
    .optional(),

  phoneNumber: z
    .string()
    .trim()
    .regex(phoneRegex, 'Enter a valid international phone number, e.g. +919876543210')
    .optional(),

  city: z.string().trim().max(100).optional(),

  country: z.string().trim().max(100).optional(),
});

const signinSchema = z.object({
  email: z.string().trim().email().transform((v) => v.toLowerCase()),
  password: z.string().min(1).max(128),
})

export {signinSchema, signupSchema}