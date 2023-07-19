<?php

declare(strict_types=1);

/**
 * This file is part of mfuns/hyperf-auth.
 *
 * @link     https://www.mfuns.cn
 * @author   ChenDoXiu<chendoxiu@gmail.com>,LixWorth<lixworth@outlook.com>
 * @license  https://github.com/mfuns-cn/hyperf-auth/blob/master/LICENSE
 */

namespace Mfuns\HyperfAuth\Middlewares;

use Hyperf\HttpServer\Contract\ResponseInterface;
use Mfuns\HyperfAuth\AuthManager;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseInterface as PsrResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

abstract class AbstractAuthMiddleware implements MiddlewareInterface
{
    /**
     * @param ContainerInterface $container
     * @param ResponseInterface $response
     * @param AuthManager $authManager
     * @param null|string $guard_name
     */
    public function __construct(
        protected ContainerInterface $container,
        protected ResponseInterface $response,
        protected AuthManager $authManager,
        protected ?string $guard_name = null
    ) {
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): PsrResponseInterface
    {
        $guard = $this->authManager->guard($this->guard_name);
        if ($guard->check()) {
            return $handler->handle($request);
        }
        return $this->fail();
    }

    protected function fail(string $reason = 'unauthorized'): PsrResponseInterface
    {
        return $this->response->json([
            'code' => 401,
            'msg' => $reason,
        ])->withStatus(401);
    }
}
