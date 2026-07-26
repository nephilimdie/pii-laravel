<?php

declare(strict_types=1);

namespace PiiProtect\Laravel\Middleware;

use Closure;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use PiiProtect\Laravel\Events\ResponseBodyAnonymized;
use PiiProtect\Laravel\Jobs\AnonymizeResponseBodyJob;
use PiiProtect\Laravel\PiiProtectClient;
use Symfony\Component\HttpFoundation\Response;

/**
 * Anonymizes string values in JSON responses.
 *
 * Driver behaviour (pii-protect.driver):
 *
 *   sync (default)   — anonymize inline; client receives clean data.
 *
 *   after_response   — send the original response to the client immediately,
 *                      then anonymize in Laravel's terminating() hook and fire
 *                      ResponseBodyAnonymized. Use for audit/compliance logging
 *                      when latency matters more than client-side masking.
 *
 *   queue            — same semantics as after_response but runs in a queue
 *                      worker (pii-protect.queue). Useful when the anonymization
 *                      workload is heavy or you want retry support.
 *
 * Note: in after_response and queue modes the client receives the original
 * (un-anonymized) data. Only use these modes for trusted internal consumers
 * or when the goal is an anonymized audit trail, not client-facing protection.
 */
class SanitizeResponseMiddleware
{
    public function __construct(
        private readonly PiiProtectClient $client,
    ) {}

    public function handle(Request $request, Closure $next, string ...$skipKeys): Response
    {
        /** @var Response $response */
        $response = $next($request);

        if (!str_contains($response->headers->get('Content-Type', ''), 'application/json')) {
            return $response;
        }

        $body = $response->getContent();
        if ($body === false || $body === '' || $body === 'null') {
            return $response;
        }

        $decoded = json_decode($body, true, 512);
        if (!is_array($decoded)) {
            return $response;
        }

        $globalSkip = config('pii-protect.skip_fields', []);
        $skip       = array_unique(array_merge((array) $globalSkip, $skipKeys));
        $driver     = config('pii-protect.driver', 'sync');

        if ($driver === 'after_response') {
            $client = $this->client;
            app()->terminating(static function () use ($client, $decoded, $skip): void {
                $sanitized = $client->anonymizeArray($decoded, $skip);
                event(new ResponseBodyAnonymized($sanitized));
            });
            return $response;
        }

        if ($driver === 'queue') {
            AnonymizeResponseBodyJob::dispatch($decoded, $skip)
                ->onQueue(config('pii-protect.queue', 'default'));
            return $response;
        }

        // sync — anonymize before sending to client
        $sanitized     = $this->client->anonymizeArray($decoded, $skip);
        $sanitizedJson = json_encode($sanitized, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);

        if ($response instanceof JsonResponse) {
            $response->setJson($sanitizedJson);
        } else {
            $response->setContent($sanitizedJson);
            $response->headers->set('Content-Type', 'application/json');
        }

        return $response;
    }
}
