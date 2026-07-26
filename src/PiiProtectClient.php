<?php

declare(strict_types=1);

namespace PiiProtect\Laravel;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\RequestOptions;

/**
 * HTTP client for the PII Protect engine API.
 *
 * All methods are intentionally non-throwing: on any network or API error
 * the original text is returned so the application never breaks.
 */
class PiiProtectClient
{
    private Client $httpClient;
    private string $engineUrl;
    private string $apiKey;

    public function __construct(
        string $engineUrl,
        string $apiKey,
        int $timeoutMs = 500,
    ) {
        $this->engineUrl = rtrim($engineUrl, '/');
        $this->apiKey    = $apiKey;

        $this->httpClient = new Client([
            'base_uri'              => $this->engineUrl,
            RequestOptions::TIMEOUT => $timeoutMs / 1000.0,
            RequestOptions::HEADERS => [
                'X-API-Key'    => $this->apiKey,
                'Content-Type' => 'application/json',
                'Accept'       => 'application/json',
            ],
        ]);
    }

    /**
     * Anonymize a single text string.
     *
     * @param  string $text Raw text that may contain PII.
     * @return string       Anonymized text, or the original text on error.
     */
    public function anonymize(string $text): string
    {
        if (trim($text) === '') {
            return $text;
        }

        try {
            $response = $this->httpClient->post('/v1/anonymize', [
                RequestOptions::JSON => [
                    'text'         => $text,
                    'context_id'   => uniqid('laravel_', true),
                    'context_type' => 'generic',
                ],
            ]);

            $body = json_decode((string) $response->getBody(), true, 512, JSON_THROW_ON_ERROR);

            return $body['anonymized_text'] ?? $text;
        } catch (\Throwable $e) {
            $this->logError('anonymize', $e);
            return $text;
        }
    }

    /**
     * Anonymize multiple texts in a single batch request.
     *
     * @param  array<string> $texts Raw texts.
     * @return array<string>        Anonymized texts in the same order.
     */
    public function anonymizeBatch(array $texts): array
    {
        if (empty($texts)) {
            return $texts;
        }

        $indexedTexts = [];
        foreach ($texts as $idx => $text) {
            if (trim((string) $text) !== '') {
                $indexedTexts[$idx] = $text;
            }
        }

        if (empty($indexedTexts)) {
            return $texts;
        }

        try {
            $items = [];
            foreach ($indexedTexts as $idx => $text) {
                $items[] = ['id' => (string) $idx, 'text' => $text];
            }

            $response = $this->httpClient->post('/v1/anonymize/batch', [
                RequestOptions::JSON => [
                    'items'        => $items,
                    'context_type' => 'generic',
                ],
            ]);

            $body = json_decode((string) $response->getBody(), true, 512, JSON_THROW_ON_ERROR);

            $anonymizedById = [];
            foreach ($body['items'] ?? [] as $item) {
                if (isset($item['id'], $item['output']) && $item['error_code'] === null) {
                    $anonymizedById[$item['id']] = $item['output'];
                }
            }

            $result = $texts;
            foreach ($indexedTexts as $idx => $text) {
                $id = (string) $idx;
                if (isset($anonymizedById[$id])) {
                    $result[$idx] = $anonymizedById[$id];
                }
            }

            return $result;
        } catch (\Throwable $e) {
            $this->logError('anonymizeBatch', $e);
            return $texts;
        }
    }

    /**
     * Recursively walk an array and anonymize all string leaf values,
     * skipping any keys present in $skipKeys.
     *
     * @param  array    $data      The data array to sanitize.
     * @param  string[] $skipKeys  Keys to leave untouched.
     * @return array               The sanitized data array.
     */
    public function anonymizeArray(array $data, array $skipKeys = []): array
    {
        // Gather all leaf strings with their dot-notation paths
        $strings  = [];
        $paths    = [];
        $this->flattenStrings($data, $skipKeys, '', $strings, $paths);

        if (empty($strings)) {
            return $data;
        }

        $anonymized = $this->anonymizeBatch(array_values($strings));

        // Re-map by path
        $pathToAnon = array_combine(array_values($paths), $anonymized);

        return $this->rebuildArray($data, $skipKeys, '', $pathToAnon);
    }

    // ------------------------------------------------------------------
    // Internals
    // ------------------------------------------------------------------

    private function flattenStrings(
        array $data,
        array $skipKeys,
        string $prefix,
        array &$strings,
        array &$paths,
    ): void {
        foreach ($data as $key => $value) {
            $path = $prefix === '' ? (string) $key : $prefix . '.' . $key;

            if (in_array($key, $skipKeys, true)) {
                continue;
            }

            if (is_string($value) && trim($value) !== '') {
                $strings[] = $value;
                $paths[]   = $path;
            } elseif (is_array($value)) {
                $this->flattenStrings($value, $skipKeys, $path, $strings, $paths);
            }
        }
    }

    private function rebuildArray(
        array $data,
        array $skipKeys,
        string $prefix,
        array $pathToAnon,
    ): array {
        foreach ($data as $key => &$value) {
            $path = $prefix === '' ? (string) $key : $prefix . '.' . $key;

            if (in_array($key, $skipKeys, true)) {
                continue;
            }

            if (is_string($value) && isset($pathToAnon[$path])) {
                $value = $pathToAnon[$path];
            } elseif (is_array($value)) {
                $value = $this->rebuildArray($value, $skipKeys, $path, $pathToAnon);
            }
        }
        unset($value);

        return $data;
    }

    private function logError(string $method, \Throwable $e): void
    {
        $msg = sprintf(
            '[PiiProtect] %s() failed: %s (%s:%d)' . PHP_EOL,
            $method,
            $e->getMessage(),
            $e->getFile(),
            $e->getLine(),
        );
        fwrite(STDERR, $msg);
    }
}
