# pii-protect/laravel

Laravel service provider that runs PII Protect anonymization over the
request/response lifecycle. Point it at a PII Protect engine (self-hosted or
Pseudora Cloud) and personal data is stripped before it reaches your logs,
your database, or a third-party API.

## Install

```bash
composer require pii-protect/laravel
```

The provider and the `PiiProtect` facade are auto-discovered. Publish the config
if you want to edit it in your app:

```bash
php artisan vendor:publish --tag=pii-protect-config
```

## Configure

```dotenv
PII_PROTECT_ENGINE_URL=https://pseudora.cloud
PII_PROTECT_API_KEY=your-api-key
PII_PROTECT_TIMEOUT_MS=500
PII_DRIVER=sync
```

`timeout_ms` is a hard deadline: if the engine does not answer in time the
original text is returned unchanged, so anonymization never takes your
application down.

## Middleware

Two aliases are registered:

| Alias | Effect |
|---|---|
| `pii.sanitize` | Anonymizes the incoming request input before your controller sees it |
| `pii.sanitize.response` | Anonymizes the outgoing JSON response body |

```php
Route::post('/tickets', [TicketController::class, 'store'])
    ->middleware('pii.sanitize');
```

Keys listed under `skip_fields` (passwords, tokens, `api_key`, `secret`, …) are
never sent to the engine.

## Response drivers

`PII_DRIVER` controls how `pii.sanitize.response` dispatches its work:

| Driver | Behaviour |
|---|---|
| `sync` | Inline. The client receives the anonymized body. Default. |
| `after_response` | The original body ships first; anonymization runs in the `terminating()` hook and fires `ResponseBodyAnonymized` for audit. |
| `queue` | Same as `after_response` but through a queue worker, so it retries. Set `PII_QUEUE` to target a specific queue. |

`pii.sanitize` is always synchronous — the request cannot proceed on
un-anonymized input.

## Direct use

```php
use PiiProtect\Laravel\Facades\PiiProtect;

$clean  = PiiProtect::anonymize('Mario Rossi, CF RSSMRA80A01H501U');
$many   = PiiProtect::anonymizeBatch(['first text', 'second text']);
$record = PiiProtect::anonymizeArray($request->all(), skipKeys: ['password']);
```

Or inject `PiiProtect\Laravel\PiiProtectClient` — it is bound as a singleton so
the Guzzle connection pool is shared for the whole request.

## Tests

```bash
composer install
composer test
```

## Requirements

PHP 8.1+, Laravel 10/11/12/13.

## License

MIT.
