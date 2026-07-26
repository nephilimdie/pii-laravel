<?php

declare(strict_types=1);

namespace PiiProtect\Laravel;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\ServiceProvider;
use PiiProtect\Laravel\Middleware\SanitizeRequestMiddleware;
use PiiProtect\Laravel\Middleware\SanitizeResponseMiddleware;

class PiiProtectServiceProvider extends ServiceProvider
{
    /**
     * Register services.
     */
    public function register(): void
    {
        // Merge default config so the application config is always complete
        $this->mergeConfigFrom(
            __DIR__ . '/../config/pii-protect.php',
            'pii-protect',
        );

        // Register PiiProtectClient as a singleton so we share the Guzzle
        // HTTP client (and its connection pool) across the whole request.
        $this->app->singleton(PiiProtectClient::class, function (Application $app): PiiProtectClient {
            $cfg = $app['config']['pii-protect'];

            return new PiiProtectClient(
                engineUrl: $cfg['engine_url'],
                apiKey:    $cfg['api_key'] ?? '',
                timeoutMs: (int) ($cfg['timeout_ms'] ?? 500),
            );
        });

        // Convenient alias so users can type-hint the interface name too
        $this->app->alias(PiiProtectClient::class, 'pii-protect');
    }

    /**
     * Bootstrap services.
     */
    public function boot(): void
    {
        // Publish the config file
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__ . '/../config/pii-protect.php' => config_path('pii-protect.php'),
            ], 'pii-protect-config');
        }

        // Register named middleware aliases
        $this->registerMiddlewareAliases();
    }

    /**
     * Register middleware aliases so they can be used in route definitions.
     */
    private function registerMiddlewareAliases(): void
    {
        /** @var \Illuminate\Routing\Router $router */
        $router = $this->app['router'];

        $router->aliasMiddleware('pii.sanitize',          SanitizeRequestMiddleware::class);
        $router->aliasMiddleware('pii.sanitize.response', SanitizeResponseMiddleware::class);
    }

    /**
     * {@inheritdoc}
     */
    public function provides(): array
    {
        return [
            PiiProtectClient::class,
            'pii-protect',
        ];
    }
}
