<?php

declare(strict_types=1);

/**
 * This file is part of mfuns/hyperf-auth.
 *
 * @link     https://www.mfuns.cn
 * @author   ChenDoXiu<chendoxiu@gmail.com>,LixWorth<lixworth@outlook.com>
 * @license  https://github.com/mfuns-cn/hyperf-auth/blob/master/LICENSE
 */

namespace Mfuns\HyperfAuth;

use Hyperf\Context\Context;
use Hyperf\Contract\ConfigInterface;
use InvalidArgumentException;
use Mfuns\HyperfAuth\Contracts\AuthManagerInterface;
use Mfuns\HyperfAuth\Contracts\GuardInterface;
use Mfuns\HyperfAuth\Contracts\TokenProviderInterface;
use Psr\Container\ContainerInterface;

class AuthManager implements AuthManagerInterface
{
    protected ContainerInterface $container;

    protected ConfigInterface $config;

    public function __construct(ContainerInterface $container)
    {
        $this->container = $container;
        $this->config = $container->get(ConfigInterface::class);
    }

    public function getDefaultDriver(): string
    {
        return $this->config->get('auth.defaults.guard', '');
    }

    public function getTokenProvider(string $name): TokenProviderInterface
    {
        $config = $this->config->get('auth.token_provider.' . $name);
        if ($config == null) {
            throw new InvalidArgumentException("Auth token provider [{$name}] is not defined.");
        }

        if (empty($config['driver'])) {
            throw new InvalidArgumentException("Auth token provider [{$name}] driver is not defined.");
        }

        $options = $config['options'] ?? [];
        return Context::getOrSet(
            static::class . '.token_provider.' . $name,
            make($config['driver'], compact('options'))
        );
    }

    public function guard(string $name = null): GuardInterface
    {
        if ($name == null) {
            $name = $this->getDefaultDriver();
        }
        return Context::getOrSet(static::class . '.guards.' . $name, $this->resolve($name)); // todo context
    }

    public function resolve(string $guardName): GuardInterface
    {
        $config = $this->config->get('auth.guards.' . $guardName);
        if (empty($config)) {
            throw new InvalidArgumentException("Auth guard [{$guardName}] is not defined.");
        }

        if (empty($config['driver'])) {
            throw new InvalidArgumentException("Auth guard [{$guardName}] driver is not defined.");
        }

        if (empty($config['token_provider'])) {
            throw new InvalidArgumentException("Auth guard [{$guardName}] token_provider is not defined.");
        }

        if (empty($config['model'])) {
            throw new InvalidArgumentException("Auth guard [{$guardName}] token_provider is not defined.");
        }

        $tokenProvider = $this->getTokenProvider($config['token_provider']);
        $model = $config['model'];
        $options = $config['options'] ?? [];
        return make($config['driver'], compact('guardName', 'tokenProvider', 'model', 'options'));
    }
}
