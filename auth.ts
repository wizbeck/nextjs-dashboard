import NextAuth from "next-auth";
import { authConfig } from "./auth.config";
import Credentials from 'next-auth/providers/credentials';
import { z } from "zod";
import { sql } from "@vercel/postgres";
import type { User } from "@/app/lib/definitions";
import bcrypt from 'bcrypt';

// typescript, when definining functions we can specify the type input
//  and the return output type to make sure the function returns what we expected
async function getUser(email: string): Promise<User | undefined> {
  try {
    // getting user from database by email
    const user = await sql<User>`SELECT * FROM USERS WHERE email=${email};`;
    return user.rows[0];
  } catch(error) {
    console.error("Failed to fetch user", error);
    throw new Error("Failed to fetch user.");
  }
}

export const { auth, signIn, signOut } = NextAuth({
  ...authConfig,
  providers: [
    Credentials({
      async authorize(credentials) {
        const parsedCredentials = z
          .object({ email: z.string(), password: z.string().min(6) })
          .safeParse(credentials);
        
        if (parsedCredentials.success) {
          const { email, password } = parsedCredentials.data;
          const user = await getUser(email);
          if (!user) return null;

          const passwordsMatch = await bcrypt.compare(password, user.password);
          if (passwordsMatch) return user;
        }

        console.log('Invalid Credentials');
        return null;
      },
    }),
  ],
})
