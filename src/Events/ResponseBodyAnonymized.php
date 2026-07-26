<?php

declare(strict_types=1);

namespace PiiProtect\Laravel\Events;

class ResponseBodyAnonymized
{
    public function __construct(
        public readonly array $data,
    ) {}
}
