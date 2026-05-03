// React hook that reads /api/auth/me and exposes a logout() helper.
//
// Generic over the user shape so each app can keep its own User type
// (including app-specific fields like credit balance, team label, etc.)
// without forking the hook.

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiRequest } from "./api-request";

export interface BaseAuthUser {
  id: string;
  email: string;
  role: "admin" | "user";
  emailVerifiedAt?: string | null;
}

export interface UseAuthOptions {
  // Where the UI should land after logout. Defaults to "/login".
  logoutRedirectUrl?: string;
  // Override the /api/auth/me endpoint. Defaults to "/api/auth/me".
  meEndpoint?: string;
  // Override the /api/auth/logout endpoint.
  logoutEndpoint?: string;
}

export interface UseAuthResult<U extends BaseAuthUser = BaseAuthUser> {
  user: U | null;
  isLoading: boolean;
  isAuthenticated: boolean;
  isAdmin: boolean;
  logout: () => void;
  isLoggingOut: boolean;
  refetch: () => void;
}

export function useAuth<U extends BaseAuthUser = BaseAuthUser>(
  opts: UseAuthOptions = {},
): UseAuthResult<U> {
  const meEndpoint = opts.meEndpoint ?? "/api/auth/me";
  const logoutEndpoint = opts.logoutEndpoint ?? "/api/auth/logout";
  const logoutRedirect = opts.logoutRedirectUrl ?? "/login";

  const queryClient = useQueryClient();
  const { data, isLoading, refetch } = useQuery<{ user: U }>({
    queryKey: [meEndpoint],
    retry: false,
    staleTime: 1000 * 60 * 5,
  });

  const logoutMutation = useMutation({
    mutationFn: async () => {
      await apiRequest("POST", logoutEndpoint);
    },
    onSuccess: () => {
      queryClient.clear();
      if (typeof window !== "undefined") {
        window.location.href = logoutRedirect;
      }
    },
  });

  const user = (data?.user ?? null) as U | null;
  return {
    user,
    isLoading,
    isAuthenticated: !!user,
    isAdmin: user?.role === "admin",
    logout: () => logoutMutation.mutate(),
    isLoggingOut: logoutMutation.isPending,
    refetch,
  };
}
