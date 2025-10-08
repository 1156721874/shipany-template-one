import CredentialsProvider from "next-auth/providers/credentials";
import GitHubProvider from "next-auth/providers/github";
import GoogleProvider from "next-auth/providers/google";
import { NextAuthConfig } from "next-auth";
import { Provider } from "next-auth/providers/index";
import { User } from "@/types/user";
import { getClientIp } from "@/lib/ip";
import { getIsoTimestr } from "@/lib/time";
import { getUuid } from "@/lib/hash";
import { saveUser } from "@/services/user";

let providers: Provider[] = [];

// Google One Tap Auth
if (
  process.env.NEXT_PUBLIC_AUTH_GOOGLE_ONE_TAP_ENABLED === "true" &&
  process.env.NEXT_PUBLIC_AUTH_GOOGLE_ID
) {
  providers.push(
    CredentialsProvider({
      id: "google-one-tap",
      name: "google-one-tap",

      credentials: {
        credential: { type: "text" },
      },

      async authorize(credentials, req) {
        const googleClientId = process.env.NEXT_PUBLIC_AUTH_GOOGLE_ID;
        if (!googleClientId) {
          console.log("invalid google auth config");
          return null;
        }

        const token = credentials!.credential;

        const response = await fetch(
          "https://oauth2.googleapis.com/tokeninfo?id_token=" + token
        );
        if (!response.ok) {
          console.log("Failed to verify token");
          return null;
        }

        const payload = await response.json();
        if (!payload) {
          console.log("invalid payload from token");
          return null;
        }

        const {
          email,
          sub,
          given_name,
          family_name,
          email_verified,
          picture: image,
        } = payload;
        if (!email) {
          console.log("invalid email in payload");
          return null;
        }

        const user = {
          id: sub,
          name: [given_name, family_name].join(" "),
          email,
          image,
          emailVerified: email_verified ? new Date() : null,
        };

        return user;
      },
    })
  );
}

// Google Auth
if (
  process.env.NEXT_PUBLIC_AUTH_GOOGLE_ENABLED === "true" &&
  process.env.AUTH_GOOGLE_ID &&
  process.env.AUTH_GOOGLE_SECRET
) {
  providers.push(
    GoogleProvider({
      clientId: process.env.AUTH_GOOGLE_ID,
      clientSecret: process.env.AUTH_GOOGLE_SECRET,
    })
  );
}

// Github Auth
if (
  process.env.NEXT_PUBLIC_AUTH_GITHUB_ENABLED === "true" &&
  process.env.AUTH_GITHUB_ID &&
  process.env.AUTH_GITHUB_SECRET
) {
  providers.push(
    GitHubProvider({
      clientId: process.env.AUTH_GITHUB_ID,
      clientSecret: process.env.AUTH_GITHUB_SECRET,
    })
  );
}

export const providerMap = providers
  .map((provider) => {
    if (typeof provider === "function") {
      const providerData = provider();
      return { id: providerData.id, name: providerData.name };
    } else {
      return { id: provider.id, name: provider.name };
    }
  })
  .filter((provider) => provider.id !== "google-one-tap");

export const authOptions: NextAuthConfig = {
  providers,
    /**
     * 指定 NextAuth 内置页面的自定义路径，覆盖默认的 /api/auth/signin 等页面。
     *
     * 🔍 默认行为：
     * 如果不设置 pages，NextAuth 会使用内置的登录页面，路径是：
     *
     * /api/auth/signin → 显示所有 provider 的登录按钮
     * /api/auth/signup → 注册页（如果有）
     * /api/auth/error → 错误页
     */
  pages: {
    signIn: "/auth/signin",
  },
  callbacks: {
      /**
       * user	用户信息（来自 OAuth 提供商或 authorize）
       * account	账户信息（如 type: "oauth", provider: "google"）
       * profile	原始 OAuth 响应数据（如 Google 返回的 JSON）
       * email	邮箱相关（主要用于邮件验证）
       * credentials	仅用于 credentials 提供商，如用户名密码
       */
    async signIn({ user, account, profile, email, credentials }) {
      const isAllowedToSignIn = true;
      if (isAllowedToSignIn) {
        return true;
      } else {
        // Return false to display a default error message
        return false;
        // Or you can return a URL to redirect to:
        // return '/unauthorized'
      }
    },
    async redirect({ url, baseUrl }) {
      // Allows relative callback URLs
      if (url.startsWith("/")) return `${baseUrl}${url}`;
      // Allows callback URLs on the same origin
      else if (new URL(url).origin === baseUrl) return url;
      return baseUrl;
    },
      /**
       * 定制客户端可用的会话（session）对象。这是前端 useSession() 拿到的数据来源。
       *
       * 🔁 执行时机：
       * 每次前端调用 getSession() 或 useSession() 时触发。
       *
       * 🧩 参数说明：
       * 参数	说明
       * session	即将返回给客户端的会话对象
       * token	JWT 令牌内容（包含你在 jwt 回调中添加的数据）
       * user	用户信息（仅在首次登录时存在）
       */
    async session({ session, token, user }) {
      if (token && token.user && token.user) {
        session.user = token.user;
      }
      return session;
    },
      /**
       * 生成或更新 JWT 令牌。这是整个认证流程中最关键的“数据中枢”。
       *
       * 🔁 执行时机：
       * 用户首次登录成功后
       * 每次会话更新时（如刷新）
       * 每次调用 getToken() 时
       * 🧩 参数说明：
       * 参数	说明
       * token	JWT 令牌对象（持久化存储在客户端 cookie 中）
       * user	用户信息（仅首次登录时存在）
       * account	账户信息（仅首次登录时存在）
       */
    async jwt({ token, user, account }) {
      // Persist the OAuth access_token and or the user id to the token right after signin
      try {
        if (user && user.email && account) {
          const dbUser: User = {
            uuid: getUuid(),
            email: user.email,
            nickname: user.name || "",
            avatar_url: user.image || "",
            signin_type: account.type,
            signin_provider: account.provider,
            signin_openid: account.providerAccountId,
            created_at: getIsoTimestr(),
            signin_ip: await getClientIp(),
          };

          try {
            const savedUser = await saveUser(dbUser);

            token.user = {
              uuid: savedUser.uuid,
              email: savedUser.email,
              nickname: savedUser.nickname,
              avatar_url: savedUser.avatar_url,
              created_at: savedUser.created_at,
            };
          } catch (e) {
            console.error("save user failed:", e);
          }
        }
        return token;
      } catch (e) {
        console.error("jwt callback error:", e);
        return token;
      }
    },
  },
};
