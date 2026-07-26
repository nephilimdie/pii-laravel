<?php

declare(strict_types=1);

namespace PiiProtect\Laravel\Tests;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Queue;
use Orchestra\Testbench\TestCase;
use PiiProtect\Laravel\Events\ResponseBodyAnonymized;
use PiiProtect\Laravel\Jobs\AnonymizeResponseBodyJob;
use PiiProtect\Laravel\Middleware\SanitizeRequestMiddleware;
use PiiProtect\Laravel\Middleware\SanitizeResponseMiddleware;
use PiiProtect\Laravel\PiiProtectClient;
use PiiProtect\Laravel\PiiProtectServiceProvider;

class SanitizeMiddlewareTest extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [PiiProtectServiceProvider::class];
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    private function makeClient(array $anonymized): PiiProtectClient
    {
        $mock = $this->createMock(PiiProtectClient::class);
        $mock->method('anonymize')->willReturnCallback(fn($t) => $anonymized[$t] ?? $t);
        $mock->method('anonymizeBatch')->willReturnCallback(
            fn(array $texts) => array_map(fn($t) => $anonymized[$t] ?? $t, $texts)
        );
        $mock->method('anonymizeArray')->willReturnCallback(function (array $data) use ($anonymized): array {
            array_walk_recursive($data, function (&$v) use ($anonymized) {
                if (is_string($v)) {
                    $v = $anonymized[$v] ?? $v;
                }
            });
            return $data;
        });
        return $mock;
    }

    private function jsonRequest(string $method, array $body): Request
    {
        $req = Request::create('/test', $method, [], [], [], [], json_encode($body));
        $req->headers->set('Content-Type', 'application/json');
        $req->merge($body);
        return $req;
    }

    private function jsonResponse(array $body): JsonResponse
    {
        return new JsonResponse($body);
    }

    // ── SanitizeRequestMiddleware ──────────────────────────────────────────────

    public function testRequestMiddlewareAnonymizesInputSync(): void
    {
        $client = $this->makeClient(['mario@example.com' => '[EMAIL_1]', 'Mario Rossi' => '[PERSON_1]']);
        $mw     = new SanitizeRequestMiddleware($client);
        $req    = $this->jsonRequest('POST', ['name' => 'Mario Rossi', 'email' => 'mario@example.com']);

        $seen = null;
        $mw->handle($req, function ($r) use (&$seen) {
            $seen = $r->all();
            return response()->json([]);
        });

        $this->assertSame('[PERSON_1]', $seen['name']);
        $this->assertSame('[EMAIL_1]', $seen['email']);
    }

    public function testRequestMiddlewareSkipsConfiguredFields(): void
    {
        $client = $this->makeClient([]);
        $mw     = new SanitizeRequestMiddleware($client);
        $req    = $this->jsonRequest('POST', ['email' => 'mario@example.com', 'password' => 'secret123']);

        config(['pii-protect.skip_fields' => ['password']]);

        $seen = null;
        $mw->handle($req, function ($r) use (&$seen) {
            $seen = $r->all();
            return response()->json([]);
        });

        $this->assertSame('secret123', $seen['password']);
    }

    public function testRequestMiddlewareAlwaysSyncRegardlessOfDriver(): void
    {
        // Even with driver=queue, request middleware must call anonymizeArray inline
        config(['pii-protect.driver' => 'queue']);
        Queue::fake();

        $called = false;
        $client = $this->createMock(PiiProtectClient::class);
        $client->method('anonymizeArray')->willReturnCallback(function ($d) use (&$called) {
            $called = true;
            return $d;
        });

        $mw  = new SanitizeRequestMiddleware($client);
        $req = $this->jsonRequest('POST', ['field' => 'value']);
        $mw->handle($req, fn($r) => response()->json([]));

        $this->assertTrue($called, 'Request middleware must call anonymizeArray synchronously');
        Queue::assertNothingPushed();
    }

    // ── SanitizeResponseMiddleware — sync ──────────────────────────────────────

    public function testResponseMiddlewareSyncAnonymizesBeforeSend(): void
    {
        config(['pii-protect.driver' => 'sync']);
        $client = $this->makeClient(['mario@example.com' => '[EMAIL_1]']);
        $mw     = new SanitizeResponseMiddleware($client);
        $req    = Request::create('/test', 'GET');

        $resp = $mw->handle($req, fn() => $this->jsonResponse(['email' => 'mario@example.com']));

        $this->assertSame(['email' => '[EMAIL_1]'], json_decode($resp->getContent(), true));
    }

    public function testResponseMiddlewareSyncPassesThroughNonJson(): void
    {
        config(['pii-protect.driver' => 'sync']);
        $client = $this->createMock(PiiProtectClient::class);
        $client->expects($this->never())->method('anonymizeArray');
        $mw  = new SanitizeResponseMiddleware($client);
        $req = Request::create('/test', 'GET');

        $resp = $mw->handle($req, fn() => response('<html>ok</html>', 200, ['Content-Type' => 'text/html']));

        $this->assertStringContainsString('<html>', $resp->getContent());
    }

    // ── SanitizeResponseMiddleware — after_response ────────────────────────────

    public function testResponseMiddlewareAfterResponseSendsOriginalImmediately(): void
    {
        config(['pii-protect.driver' => 'after_response']);
        $client = $this->makeClient(['mario@example.com' => '[EMAIL_1]']);
        $mw     = new SanitizeResponseMiddleware($client);
        $req    = Request::create('/test', 'GET');

        $resp = $mw->handle($req, fn() => $this->jsonResponse(['email' => 'mario@example.com']));

        // Client receives ORIGINAL data
        $this->assertSame(['email' => 'mario@example.com'], json_decode($resp->getContent(), true));
    }

    public function testResponseMiddlewareAfterResponseFiresEventInTerminatingHook(): void
    {
        config(['pii-protect.driver' => 'after_response']);
        Event::fake([ResponseBodyAnonymized::class]);
        $client = $this->makeClient(['mario@example.com' => '[EMAIL_1]']);
        $mw     = new SanitizeResponseMiddleware($client);
        $req    = Request::create('/test', 'GET');

        $mw->handle($req, fn() => $this->jsonResponse(['email' => 'mario@example.com']));

        // Simulate Laravel terminating phase
        $this->app->terminate();

        Event::assertDispatched(ResponseBodyAnonymized::class, function ($e) {
            return $e->data === ['email' => '[EMAIL_1]'];
        });
    }

    // ── SanitizeResponseMiddleware — queue ─────────────────────────────────────

    public function testResponseMiddlewareQueueSendsOriginalImmediately(): void
    {
        config(['pii-protect.driver' => 'queue']);
        Queue::fake();
        $client = $this->makeClient([]);
        $mw     = new SanitizeResponseMiddleware($client);
        $req    = Request::create('/test', 'GET');

        $resp = $mw->handle($req, fn() => $this->jsonResponse(['email' => 'mario@example.com']));

        $this->assertSame(['email' => 'mario@example.com'], json_decode($resp->getContent(), true));
    }

    public function testResponseMiddlewareQueueDispatchesJob(): void
    {
        config(['pii-protect.driver' => 'queue', 'pii-protect.queue' => 'pii']);
        Queue::fake();
        $client = $this->makeClient([]);
        $mw     = new SanitizeResponseMiddleware($client);
        $req    = Request::create('/test', 'GET');

        $mw->handle($req, fn() => $this->jsonResponse(['email' => 'mario@example.com']));

        Queue::assertPushedOn('pii', AnonymizeResponseBodyJob::class);
    }

    public function testAnonymizeResponseBodyJobFiresEvent(): void
    {
        Event::fake([ResponseBodyAnonymized::class]);
        $client = $this->makeClient(['mario@example.com' => '[EMAIL_1]']);
        $this->app->instance(PiiProtectClient::class, $client);

        $job = new AnonymizeResponseBodyJob(['email' => 'mario@example.com'], []);
        $job->handle($client);

        Event::assertDispatched(ResponseBodyAnonymized::class, function ($e) {
            return $e->data === ['email' => '[EMAIL_1]'];
        });
    }
}
