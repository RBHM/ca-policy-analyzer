/**
 * Role Name Resolver
 *
 * Converts Azure AD role template GUIDs to human-readable names.
 * Used across the UI, exports, and template matcher.
 */

import { ADMIN_ROLE_IDS } from "@/data/policy-templates";

// ─── Role Name Lookup ────────────────────────────────────────────────────────

/** Reverse map: role GUID (lowercase) → human-friendly name */
export const ROLE_NAME_MAP: Record<string, string> = Object.fromEntries(
  Object.entries(ADMIN_ROLE_IDS).map(([key, id]) => [
    id.toLowerCase(),
    key
      .replace(/([A-Z])/g, " $1")
      .replace(/^./, (c) => c.toUpperCase())
      .trim(),
  ]),
);

/**
 * Resolve a role template GUID to its friendly name.
 * Falls back to the raw GUID if unrecognised.
 */
export function resolveRoleName(guid: string): string {
  return ROLE_NAME_MAP[guid.toLowerCase()] ?? guid;
}

/**
 * Resolve an array of role GUIDs to a comma-separated string of names.
 * Returns "—" if the array is empty or undefined.
 */
export function resolveRoleList(guids: string[] | undefined): string {
  if (!guids || guids.length === 0) return "—";
  return guids.map(resolveRoleName).join(", ");
}
