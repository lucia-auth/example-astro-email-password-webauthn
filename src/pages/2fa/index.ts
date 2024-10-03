import { getPasswordReset2FARedirect } from "@lib/server/2fa";
import { validatePasswordResetSessionRequest } from "@lib/server/password-reset";

import type { APIContext } from "astro";

export function GET(context: APIContext): Response {
	const { session, user } = validatePasswordResetSessionRequest(context);
	if (session === null) {
		return context.redirect("/login");
	}
	if (!user.registered2FA || session.twoFactorVerified) {
		return context.redirect("/");
	}
	return context.redirect(getPasswordReset2FARedirect(user));
}
