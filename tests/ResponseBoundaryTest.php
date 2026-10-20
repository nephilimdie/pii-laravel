<?php

declare(strict_types=1);

namespace PiiProtect\Laravel\Tests;

use Illuminate\Http\Request;
use Orchestra\Testbench\TestCase;
use PiiProtect\Laravel\Middleware\SanitizeResponseMiddleware;
use PiiProtect\Laravel\PiiProtectClient;

class ResponseBoundaryTest extends TestCase
{
    public function testScalarJsonIsProtectedAndStaleHeadersAreRemoved(): void
    {
        $client = $this->createMock(PiiProtectClient::class);
        $client->expects($this->once())->method('anonymize')->with('private')->willReturn('[PERSON_1]');
        $middleware = new SanitizeResponseMiddleware($client);
        $response = $middleware->handle(Request::create('/test'), fn () => response('"private"', 200, [
            'Content-Type' => 'application/problem+json', 'Content-Length' => '9', 'ETag' => 'original',
        ]));
        $this->assertSame('"[PERSON_1]"', $response->getContent());
        $this->assertFalse($response->headers->has('Content-Length'));
        $this->assertFalse($response->headers->has('ETag'));
    }

    public function testMalformedJsonDoesNotPassThrough(): void
    {
        $middleware = new SanitizeResponseMiddleware($this->createStub(PiiProtectClient::class));
        $this->expectException(\JsonException::class);
        $middleware->handle(Request::create('/test'), fn () => response('{"private":', 200, [
            'Content-Type' => 'application/json',
        ]));
    }

    public function testFailureDoesNotReturnScalarOriginal(): void
    {
        $client = $this->createMock(PiiProtectClient::class);
        $client->expects($this->once())->method('anonymize')->willThrowException(new \RuntimeException('Protection failed'));
        $this->expectException(\RuntimeException::class);
        (new SanitizeResponseMiddleware($client))->handle(Request::create('/test'), fn () => response('"private"', 200, [
            'Content-Type' => 'application/json',
        ]));
    }
}
