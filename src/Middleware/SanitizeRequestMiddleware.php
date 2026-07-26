<?php

declare(strict_types=1);

namespace PiiProtect\Laravel\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Arr;
use PiiProtect\Laravel\PiiProtectClient;
use Symfony\Component\HttpFoundation\Response;

/**
 * Anonymizes string values in incoming request inputs before they reach controllers.
 *
 * This middleware is always synchronous regardless of pii-protect.driver: the
 * controller must receive clean data before it runs, so async dispatch is not
 * applicable here.
 *
 * Usage in routes:
 *
 *   Route::post('/register', RegisterController::class)
 *       ->middleware('pii.sanitize');
 *
 *   Route::post('/login', LoginController::class)
 *       ->middleware('pii.sanitize:secret_answer,pin');
 */
class SanitizeRequestMiddleware
{
    public function __construct(
        private readonly PiiProtectClient $client,
    ) {}

    /**
     * Handle an incoming request.
     *
     * @param  Request  $request
     * @param  Closure  $next
     * @param  string   ...$skipFields  Additional fields to skip (per-route).
     * @return Response
     */
    public function handle(Request $request, Closure $next, string ...$skipFields): Response
    {
        // Merge global + per-route skip lists
        $globalSkip = config('pii-protect.skip_fields', []);
        $skip       = array_unique(array_merge((array) $globalSkip, $skipFields));

        $input = $request->all();

        if (!empty($input)) {
            $sanitized = $this->anonymizeInput($input, $skip);

            // Replace all inputs on the request so controllers see clean data
            $request->replace($sanitized);
        }

        return $next($request);
    }

    /**
     * Recursively anonymize string leaf values, skipping protected keys.
     *
     * Uses the batch endpoint when possible to minimise API round-trips.
     */
    private function anonymizeInput(array $input, array $skip): array
    {
        return $this->client->anonymizeArray($input, $skip);
    }
}
