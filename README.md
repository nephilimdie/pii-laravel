# pii-protect/laravel

Laravel service provider that runs PII Protect anonymization over the
request/response lifecycle. Point it at a PII Protect engine (self-hosted or
Pseudora Cloud). Only configured request and JSON response fields are covered;
this is not a filter for every log, database write or outbound API call.

## Install

Not yet published on Packagist. The command below applies after publication;
until then, use a Composer path repository for local evaluation only.

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
PII_PROTECT_TIMEOUT_MS=30000
PII_DRIVER=sync
```

The timeout applies to each API request. Errors, malformed responses and any
result without an explicit `safe: true` throw a generic exception. Never catch
that exception by returning the original input. HTTPS is required except for
loopback development URLs; redirects are disabled. Batch calls currently run
sequentially and return no partial results if an item fails.

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
never sent to the engine and remain unchanged in the request. Do not forward
these excluded credentials to logs or external recipients.

## Response drivers

`PII_DRIVER` controls how `pii.sanitize.response` dispatches its work:

| Driver | Behaviour |
|---|---|
| `sync` | Inline. The client receives the anonymized body. Default. |
| `after_response` | The original body ships first; anonymization runs in the `terminating()` hook and fires `ResponseBodyAnonymized` for audit. |
| `queue` | Same as `after_response` but through a queue worker, so it retries. Set `PII_QUEUE` to target a specific queue. |

`after_response` and `queue` are audit modes, not privacy boundaries: both
release original data, and the queue also stores it. Use `sync` for response
protection. Non-JSON responses are outside this middleware's scope.

`pii.sanitize` is always synchronous and blocks on protection errors for
processed fields. Field names, numeric values and excluded fields are unchanged.

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
