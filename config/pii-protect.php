<?php

return [

    /*
    |--------------------------------------------------------------------------
    | PII Protect Engine URL
    |--------------------------------------------------------------------------
    |
    | The base URL of the PII Protect engine instance.  No trailing slash.
    |
    */
    'engine_url' => env('PII_PROTECT_ENGINE_URL', 'http://localhost:8000'),

    /*
    |--------------------------------------------------------------------------
    | API Key
    |--------------------------------------------------------------------------
    |
    | The API key used to authenticate requests to the engine.
    |
    */
    'api_key' => env('PII_PROTECT_API_KEY'),

    /*
    |--------------------------------------------------------------------------
    | Request Timeout (milliseconds)
    |--------------------------------------------------------------------------
    |
    | Maximum time (in milliseconds) to wait for a response from the engine.
    | On timeout the original text is returned — the application never breaks.
    |
    */
    'timeout_ms' => env('PII_PROTECT_TIMEOUT_MS', 500),

    /*
    |--------------------------------------------------------------------------
    | Skip Fields
    |--------------------------------------------------------------------------
    |
    | Input / JSON keys that must NEVER be sent to the anonymization engine.
    | Passwords, tokens, and other secrets belong here.
    |
    */
    /*
    |--------------------------------------------------------------------------
    | Response Anonymization Driver
    |--------------------------------------------------------------------------
    |
    | Controls how SanitizeResponseMiddleware dispatches the anonymization call.
    |
    |   sync           — inline, client receives anonymized data (default).
    |   after_response — send original response first, anonymize in terminating()
    |                    hook, fire ResponseBodyAnonymized event for audit/logging.
    |   queue          — same as after_response but via a queue worker; supports
    |                    retries. Set pii_queue to target a specific queue name.
    |
    | Note: SanitizeRequestMiddleware is always sync regardless of this setting.
    |
    */
    'driver' => env('PII_DRIVER', 'sync'),
    'queue'  => env('PII_QUEUE', 'default'),

    'skip_fields' => [
        'password',
        'password_confirmation',
        'current_password',
        '_token',
        'token',
        'api_key',
        'secret',
    ],

];
