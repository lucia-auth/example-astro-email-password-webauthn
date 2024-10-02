import { invalidateSession, deleteSessionTokenCookie } from "@lib/server/session";

import type { APIContext } from "astro";

export async function DELETE(context: APIContext): Promise<Response> {
	if (context.locals.session === null) {
		return new Response("Not authenticated", {
			status: 401
		});
	}
	invalidateSession(context.locals.session.id);
	deleteSessionTokenCookie(context);
	return new Response(null, { status: 204 });
}
