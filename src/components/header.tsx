"use client";

import { useMsal, useIsAuthenticated } from "@azure/msal-react";
import { loginRequest } from "@/lib/msal-config";
import { LogIn, LogOut, Shield, User } from "lucide-react";
import { cn } from "@/lib/utils";

export default function Header() {
  const { instance, accounts } = useMsal();
  const isAuthenticated = useIsAuthenticated();

  const handleLogin = () => {
    instance.loginRedirect(loginRequest).catch((e) => {
      console.error("Login failed:", e);
    });
  };

  const handleLogout = () => {
    instance.logoutRedirect({ postLogoutRedirectUri: "/" });
  };

  const account = accounts[0];

  return (
    <header className="sticky top-0 z-50 border-b border-gray-800 bg-gray-950/80 backdrop-blur-md">
      <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-4 sm:px-6 lg:px-8">
        {/* Logo / Title */}
        <div className="flex items-center gap-3">
          <Shield className="h-7 w-7 text-blue-500" />
          <div>
            <h1 className="text-lg font-semibold text-white">
              CA Policy Analyzer
            </h1>
            <p className="text-xs text-gray-500">
              Conditional Access Best-Practice Scanner
            </p>
          </div>
        </div>

        {/* Auth section */}
        <div className="flex items-center gap-4">
          {isAuthenticated && account ? (
            <div className="flex items-center gap-3">
              <div className="hidden text-right sm:block">
                <p className="text-sm font-medium text-gray-200">
                  {account.name ?? account.username}
                </p>
                <p className="text-xs text-gray-500">
                  {account.tenantId?.slice(0, 8)}…
                </p>
              </div>
              <div className="flex h-8 w-8 items-center justify-center rounded-full bg-blue-600 text-xs font-bold text-white">
                {(account.name ?? account.username)?.[0]?.toUpperCase() ?? (
                  <User className="h-4 w-4" />
                )}
              </div>
              <button
                onClick={handleLogout}
                className={cn(
                  "flex items-center gap-2 rounded-lg px-3 py-2 text-sm font-medium",
                  "text-gray-400 hover:bg-gray-800 hover:text-white transition-colors"
                )}
              >
                <LogOut className="h-4 w-4" />
                <span className="hidden sm:inline">Disconnect</span>
              </button>
            </div>
          ) : (
            <button
              onClick={handleLogin}
              className={cn(
                "flex items-center gap-2 rounded-lg px-4 py-2 text-sm font-medium",
                "bg-blue-600 text-white hover:bg-blue-500 transition-colors"
              )}
            >
              <LogIn className="h-4 w-4" />
              Connect Tenant
            </button>
          )}
        </div>
      </div>
    </header>
  );
}
