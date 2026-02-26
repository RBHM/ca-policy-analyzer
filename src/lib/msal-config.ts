/**
 * MSAL Authentication Configuration
 *
 * Configures Microsoft Authentication Library for reading
 * Conditional Access policies from any Entra ID tenant.
 */

import { Configuration, LogLevel, PopupRequest } from "@azure/msal-browser";

// The client ID for a multi-tenant SPA (register in Entra ID → App registrations)
// Users MUST set this via environment variable or .env.local
const CLIENT_ID = process.env.NEXT_PUBLIC_MSAL_CLIENT_ID ?? "";
const REDIRECT_URI =
  process.env.NEXT_PUBLIC_MSAL_REDIRECT_URI ?? "http://localhost:3000";

export const msalConfig: Configuration = {
  auth: {
    clientId: CLIENT_ID,
    authority: "https://login.microsoftonline.com/common",
    redirectUri: REDIRECT_URI,
  },
  cache: {
    cacheLocation: "sessionStorage",
  },
  system: {
    loggerOptions: {
      loggerCallback: (level, message, containsPii) => {
        if (containsPii) return;
        switch (level) {
          case LogLevel.Error:
            console.error(message);
            break;
          case LogLevel.Warning:
            console.warn(message);
            break;
          case LogLevel.Info:
            // console.info(message);
            break;
          case LogLevel.Verbose:
            // console.debug(message);
            break;
        }
      },
      logLevel: LogLevel.Warning,
    },
  },
};

// ─── Graph Permission Scopes ─────────────────────────────────────────────────
// These are the delegated permissions needed to read CA policies and resolve
// the service principals / named locations they reference.

export const graphScopes = {
  /** Read Conditional Access policies */
  policyRead: "Policy.Read.All",
  /** Read service principal metadata (to describe excluded apps) */
  applicationRead: "Application.Read.All",
  /** Read directory objects (groups, roles, users referenced in policies) */
  directoryRead: "Directory.Read.All",
};

export const loginRequest: PopupRequest = {
  scopes: [
    graphScopes.policyRead,
    graphScopes.applicationRead,
    graphScopes.directoryRead,
  ],
};

export const graphTokenRequest = {
  scopes: ["https://graph.microsoft.com/.default"],
};
