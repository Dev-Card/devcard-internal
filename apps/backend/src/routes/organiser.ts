import type { FastifyInstance, FastifyReply } from 'fastify';
import { signinSchema, signupSchema } from '../validations/organiser.validation';
import bcrypt from "bcryptjs"
import { handleDbError } from '../utils/error.util';

const cookieOptions = {
  path: '/',
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'none' as const,
  maxAge: 60 * 60 * 24, // 1 day
};

function setAuthCookie(reply: FastifyReply, token: string) {
  return reply.setCookie('accessToken', token, cookieOptions);
}

export async function organizerAuthRoutes(
  app: FastifyInstance,
): Promise<void> {
  // POST /organizers/signup
  app.post('/signup', async (request, reply) => {
    const parsed = signupSchema.safeParse(request.body);

    if (!parsed.success) {
      return reply.status(400).send({
        error: 'Validation failed',
        details: parsed.error.flatten(),
      });
    }

    const data = parsed.data;

    try {
      const passwordHash = await bcrypt.hash(data.password, 12);

      const organizer = await app.prisma.organizerProfile.create({
        data: {
          name: data.name,
          username: data.username,
          email: data.email,
          passwordHash,
          organizationName: data.organizationName,
          type: data.type,
          description: data.description || null,
          website: data.website || null,
          phoneNumber: data.phoneNumber || null,
          city: data.city || null,
          country: data.country || null,
          // status defaults to PENDING in Prisma
        },
        select: {
          id: true,
          name: true,
          username: true,
          email: true,
          organizationName: true,
          type: true,
          status: true,
          createdAt: true,
        },
      });

      const token = await reply.jwtSign(
        {
          id: organizer.id,
          sub: organizer.id,
          accountType: 'ORGANIZER',
        },
        { expiresIn: '1d' },
      );

      setAuthCookie(reply, token);

      return reply.status(201).send({
        message: 'Organizer account created',
        organizer,
      });
    } catch (err: unknown) {
      handleDbError(err , request, reply)
    }
  });

  // POST /organizers/signin
  app.post('/signin', async (request, reply) => {
    const parsed = signinSchema.safeParse(request.body);

    if (!parsed.success) {
      return reply.status(400).send({
        error: 'Invalid email or password format',
      });
    }

    const { email, password } = parsed.data;

    try {
      const organizer = await app.prisma.organizerProfile.findUnique({
        where: { email },
      });

      if (
        !organizer ||
        !(await bcrypt.compare(password, organizer.passwordHash))
      ) {
        return reply.status(401).send({
          error: 'Invalid email or password',
        });
      }

      const token = await reply.jwtSign(
        {
          id: organizer.id,
          sub: organizer.id,
          accountType: 'ORGANIZER',
        },
        { expiresIn: '1d' },
      );

      setAuthCookie(reply, token);

      return reply.send({
        message: 'Signed in successfully',
        organizer: {
          id: organizer.id,
          name: organizer.name,
          username: organizer.username,
          email: organizer.email,
          organizationName: organizer.organizationName,
          type: organizer.type,
          status: organizer.status,
        },
      });
    } catch (err: unknown) {
      request.log.error({ err }, 'Organizer signin failed');

      return reply.status(500).send({
        error: 'Internal server error',
      });
    }
  });

  // POST /organizers/logout
  app.post('/logout', async (_request, reply) => {
    return reply
      .clearCookie('accessToken', { path: '/' })
      .send({ message: 'Signed out successfully' });
  });

  // GET /organizers/me
  app.get('/me', async (request, reply) => {
    try {
      const token = request.cookies.accessToken;

      if (!token) {
        return reply.status(401).send({
          error: 'Authentication required',
        });
      }

      const decoded = await app.jwt.verify<{
        id: string;
        sub: string;
        accountType: string;
      }>(token);

      if (decoded.accountType !== 'ORGANIZER') {
        return reply.status(403).send({
          error: 'Organizer access required',
        });
      }

      const organizer = await app.prisma.organizerProfile.findUnique({
        where: { id: decoded.id },
        select: {
          id: true,
          name: true,
          username: true,
          email: true,
          organizationName: true,
          type: true,
          description: true,
          website: true,
          logoUrl: true,
          phoneNumber: true,
          city: true,
          country: true,
          status: true,
          createdAt: true,
        },
      });

      if (!organizer) {
        return reply.status(404).send({
          error: 'Organizer not found',
        });
      }

      return reply.send({ organizer });
    } catch (err: unknown) {
      request.log.error({ err }, 'Organizer authentication failed');

      return reply.status(401).send({
        error: 'Invalid or expired authentication token',
      });
    }
  });
}