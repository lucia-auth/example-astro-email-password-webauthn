import { createWebAuthnChallenge } from "@lib/server/webauthn";
import { encodeBase64 } from "@oslojs/encoding";
import { RefillingTokenBucket } from "@lib/server/rate-limit";

import type { APIContext } from "astro";

const webauthnChallengeRateLimitBucket = new RefillingTokenBucket<string>(30, 10);

export async function POST(context: APIContext): Promise<Response> {
	// TODO: Assumes X-Forwarded-For is always included.
	const clientIP = context.request.headers.get("X-Forwarded-For");
	if (clientIP !== null && !webauthnChallengeRateLimitBucket.consume(clientIP, 1)) {
		return new Response(null, {
			status: 429
		});
	}
	const challenge = createWebAuthnChallenge();
	return new Response(JSON.stringify({ challenge: encodeBase64(challenge) }));
}
