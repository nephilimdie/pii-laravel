<?php

declare(strict_types=1);

namespace PiiProtect\Laravel\Facades;

use Illuminate\Support\Facades\Facade;
use PiiProtect\Laravel\PiiProtectClient;

/**
 * Facade for the PiiProtectClient singleton.
 *
 * @method static string   anonymize(string $text)
 * @method static array    anonymizeBatch(array $texts)
 * @method static array    anonymizeArray(array $data, array $skipKeys = [])
 *
 * @see \PiiProtect\Laravel\PiiProtectClient
 */
class PiiProtect extends Facade
{
    /**
     * {@inheritdoc}
     */
    protected static function getFacadeAccessor(): string
    {
        return PiiProtectClient::class;
    }
}
