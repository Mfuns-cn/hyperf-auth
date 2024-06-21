<?php

declare(strict_types=1);

/**
 * This file is part of mfuns/hyperf-auth.
 *
 * @link     https://www.mfuns.cn
 * @author   ChenDoXiu<chendoxiu@gmail.com>,LixWorth<lixworth@outlook.com>
 * @license  https://github.com/mfuns-cn/hyperf-auth/blob/master/LICENSE
 */

namespace Mfuns\HyperfAuth\Guards;

use Exception;
use Hyperf\Contract\SessionInterface;
use Hyperf\Database\Model\Model;
use Hyperf\Redis\Redis;
use Hyperf\Redis\RedisFactory;
use Hyperf\Redis\RedisProxy;
use Mfuns\HyperfAuth\Contracts\AuthenticatableInterface;
use Mfuns\HyperfAuth\Contracts\Guard\UserSessionData;
use Mfuns\HyperfAuth\Contracts\GuardInterface;
use Mfuns\HyperfAuth\Contracts\HashTokenData;
use Mfuns\HyperfAuth\Contracts\IdentifierInfo;
use Mfuns\HyperfAuth\Contracts\TokenProviderInterface;
use Mfuns\HyperfAuth\Exceptions\UnauthorizedException;
use Mfuns\HyperfAuth\Exceptions\UserSessionDataCreateException;
use Mfuns\HyperfAuth\Traits\ModelQueryTrait;
use Mfuns\HyperfAuth\Utils;
use Psr\Container\ContainerExceptionInterface;
use Psr\Container\ContainerInterface;
use Psr\Container\NotFoundExceptionInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Http\Message\ServerRequestInterface;
use RedisException;

/**
 * 几个基础概念
 * provider: 处理 token 的格式
 * token data: 存储在 token 里的数据
 * user session data: 存储在 redis 中的单个会话数据
 * identifier info: 存储 用户表示符 name=uid value=1 即 uid=1.
 *
 * provider 对 token 进行解密 校验自身的同时 获取到 token data
 * token data 中存储 session id(会话id), guard name, identifier info
 * 验证过程中以 identifier info 识别用户标识 并与 session id 查询 hash table 获得 session info , 验证真假后
 * 对 session info 进行更新 活跃时间、ip、extra 等。
 */
class StatefulGuard implements GuardInterface
{
    use ModelQueryTrait;

    public const SESSION_INFO_V1 = 001;

    /**
     * 用户是否已登出.
     * @var bool
     */
    protected bool $isLogin = false;

    /**
     * Redis connection pool.
     * @var Redis|RedisProxy
     */
    protected Redis|RedisProxy $redis;

    protected null|AuthenticatableInterface|Model $userModel = null;

    protected ?string $origin_token = null;

    protected int $ttl;

    protected bool $use_model_cache;

    private ?HashTokenData $hashTokenData = null;

    private ?UserSessionData $userSessionData = null;

    private bool $init = false;

    /**
     * @throws NotFoundExceptionInterface
     * @throws ContainerExceptionInterface
     */
    public function __construct(
        protected ContainerInterface $container,
        protected ServerRequestInterface $request,
        protected EventDispatcherInterface $eventDispatcher,
        protected string $guardName,
        protected TokenProviderInterface $tokenProvider,
        protected string $model,
        protected array $options,
    ) {
        $redis_conn_name = $this->options['redis_conn_name'] ?? 'default'; // redis 链接池
        $this->redis = $this->container->get(RedisFactory::class)->get($redis_conn_name);
        $this->ttl = (int) $this->options['ttl'] ?? 3600;
        $this->use_model_cache = $this->options['model_cache'] ?? false;
    }

    public function user(): ?AuthenticatableInterface
    {
        if ($this->userModel !== null) {
            return $this->userModel;
        }
        if (! $this->check()) {
            return null;
        }
        return $this->userModel;
    }

    /**
     * @return bool
     */
    public function check(): bool
    {
        try {
            $this->init();
        } catch (Exception $e) {
            return false;
        }
        if (! $this->isLogin || ! $this->userModel) {
            return false;
        }
        return true;
    }

    /**
     * 返回原始 token.
     * @throws UnauthorizedException
     */
    public function getOriginToken(): string
    {
        if ($this->origin_token === null) {
            $auth_methods = $this->options['auth_methods'] ?? ['header', 'query'];
            if (in_array('header', $auth_methods)) {
                if (isset($this->request->getHeader('Authorization')[0])) {
                    $this->origin_token = $this->request->getHeader('authorization')[0];
                }
            }
            if ($this->origin_token === null && in_array('query', $auth_methods) && $this->request->getQueryParams()['token']) {
                $this->origin_token = $this->request->getQueryParams()['token'];
            }
            if ($this->origin_token === null && in_array('cookie', $auth_methods)) {
                $cookie_name = $this->options['cookie_name'] ?? 'AuthToken';
                if (isset($this->request->getCookieParams()[$cookie_name])) {
                    $this->origin_token = $this->request->getCookieParams()[$cookie_name];
                }
            }
            if ($this->origin_token === null && in_array('session', $auth_methods)) {
                $session_key = $this->options['session_key'] ?? 'auth_guard_session';
                $this->origin_token = $this->container->get(SessionInterface::class)->get($session_key);
            }
            if ($this->origin_token === null) {
                throw new UnauthorizedException();
            }
        }
        return $this->origin_token;
    }

    /**
     * 删除一个会话.
     * @param HashTokenData $tokenData
     * @return bool
     */
    public function deleteSession(HashTokenData $tokenData): bool
    {
        try {
            $this->redis->hDel($this->getUserSessionsHashKey($tokenData->getIdentifierInfo()), $tokenData->getSessionId());
        } catch (RedisException) {
            return true;
        }
        return true;
    }

    public function setUserModel($user): null|AuthenticatableInterface|Model
    {
        $this->userModel = $user;
        return $this->userModel;
    }

    public function id(): ?int
    {
        if (! $this->check()) {
            return null;
        }
        return $this->userModel->toArray()[$this->userModel->getAuthIdentifierName()] ?? null;
    }

    public function validate(array $credentials = []): bool
    {
        return false;
    }

    /**
     * 获取用户所有的有效会话.
     * @param null|AuthenticatableInterface $user
     * @return array
     * @throws UnauthorizedException
     * @throws RedisException
     */
    public function getValidSessionDataList(?AuthenticatableInterface $user = null): array
    {
        if (! $this->check()) {
            return throw new UnauthorizedException('login first');
        }
        $res = [];
        if ($user) {
            // 指定用户
            $key = $this->getUserSessionsHashKeyByUser($user);
        } else {
            $key = $this->getUserSessionsHashKey($this->hashTokenData->getIdentifierInfo());
        }
        $array = $this->redis->hGetAll($key);
        foreach ($array as $session_id => $token_info) {
            try {
                $userSessionData = UserSessionData::factory($token_info);
                // 判断是否过期
                if ($userSessionData->getExpireTime() <= time()) {
                    $this->deleteSession($userSessionData->getHashToken());
                } else {
                    $res[] = $userSessionData->toArray();
                }
            } catch (UserSessionDataCreateException $e) {
                $this->redis->hDel($key, $session_id);
            }
        }
        return $res;
    }

    /**
     * 获取用户当前使用的会话.
     * @throws UnauthorizedException
     */
    public function getCurrentSessionData(): UserSessionData
    {
        if (! $this->check()) {
            throw new UnauthorizedException('login first');
        }
        return $this->userSessionData;
    }

    public function updateCurrentTokenData(): void
    {
        // TODO: Implement updateCurrentTokenData() method.
    }

    /**
     * @throws RedisException
     * @throws Exception
     */
    public function login(AuthenticatableInterface $user, bool $remember = false, array $extra = []): string
    {
        $id = new IdentifierInfo($user->getAuthIdentifierName(), $user->{$user->getAuthIdentifierName()});

        $session_id = base64_encode(random_bytes(9));

        $hashTokenData = new HashTokenData($id->toArray(), $session_id);
        /** @var Model $user */
        $token = $this->tokenProvider->encode($hashTokenData);
        $hash_key = $this->getUserSessionsHashKey($id);
        if ($this->redis->hExists($hash_key, $session_id)) {
            throw new Exception('exists');
        }
        $this->redis->hSet($hash_key, $session_id, json_encode($this->genSessionInfo($hashTokenData, $extra)->toArray()));
        $this->redis->expire($hash_key, $this->ttl);

        if ($this->options['auth_methods'] === ['session']) {
            $this->setLoginSession($token);
        }

        $this->setUserModel($user);
        return $token;
    }

    /**
     * 生成一个新的 session info.
     * @param HashTokenData $hashTokenData
     * @param array $extra
     * @return UserSessionData
     */
    public function genSessionInfo(HashTokenData $hashTokenData, array $extra = []): UserSessionData
    {
        return new UserSessionData(
            $hashTokenData,
            time() + $this->ttl,
            Utils::ip($this->request),
            time(),
            time(),
            array_merge($extra, [
                'ua' => Utils::getUserAgent($this->request),
                'system' => Utils::equipmentSystem($this->request),
            ])
        );
    }

    public function logout(?HashTokenData $hashTokenData): void
    {
        if ($this->check()) {
            if ($hashTokenData) {
                $this->deleteSession($hashTokenData);
            } elseif ($this->hashTokenData) {
                $this->deleteSession($this->hashTokenData);
            }
        }
        $this->isLogin = false;

        if ($this->options['auth_methods'] === ['session']) {
            $this->delLoginSession();
        }
    }

    /**
     * 清理当前用户的过期Token.
     * @throws RedisException
     */
    public function clearExpiredToken(): void
    {
        if (! $this->check()) {
            return;
        }
        $key = $this->getUserSessionsHashKey($this->hashTokenData->getIdentifierInfo());
        $array = $this->redis->hGetAll($key);
        foreach ($array as $session_id => $token_info) {
            try {
                $userSessionData = UserSessionData::factory($token_info);
                // 判断是否过期
                if ($userSessionData->getExpireTime() <= time()) {
                    $this->deleteSession($userSessionData->getHashToken());
                }
            } catch (UserSessionDataCreateException $e) {
                $this->redis->hDel($key, $session_id);
            }
        }
    }

    public function getGuardName(): string
    {
        return $this->guardName;
    }

    public function getOptions(): array
    {
        return $this->options;
    }

    /**
     * @return TokenProviderInterface
     */
    public function getTokenProvider(): TokenProviderInterface
    {
        return $this->tokenProvider;
    }

    public function logoutAll(?AuthenticatableInterface $user = null): void
    {
        if ($user) {
            // 登出指定用户
            $key = $this->getUserSessionsHashKeyByUser($user);
            $this->redis->del($key);
        } else {
            // 登出当前用户
            if ($this->check() && $this->userSessionData) {
                $key = $this->getUserSessionsHashKey($this->userSessionData->getHashToken()->getIdentifierInfo());
                $this->redis->del($key);
            }
        }
    }

    public function setLoginSession(string $token): bool
    {
        $session_key = $this->options['session_key'] ?? 'auth_guard_session';
        $this->container->get(SessionInterface::class)->set($session_key, $token);
        return true;
    }

    public function delLoginSession(): bool
    {
        $session_key = $this->options['session_key'] ?? 'auth_guard_session';
        $this->container->get(SessionInterface::class)->remove($session_key);
        return true;
    }

    /**
     * 查询用户模型.
     * @param IdentifierInfo $identifierInfo
     * @return AuthenticatableInterface|Model
     */
    protected function queryUserModel(IdentifierInfo $identifierInfo): AuthenticatableInterface|Model
    {
        $model = $this->createModel();
        if ($this->use_model_cache) {
            return $model->getUserModelFormCache($identifierInfo);
        }
        return $model->getUserModel($identifierInfo);
    }

    /**
     * @throws RedisException
     * @throws UnauthorizedException
     */
    private function init()
    {
        if ($this->init) {
            return;
        }
        $this->init = true;
        $this->decodeToken();
        $hashTokenData = $this->hashTokenData;
        if (! $hashTokenData) {
            return;
        }
        $hash_key = $this->getUserSessionsHashKey($hashTokenData->getIdentifierInfo());
        // 获取并膨胀存储在redis的登录信息
        $token_info = $this->redis->hGet($hash_key, $hashTokenData->getSessionId());
        if (! $token_info) {
            return;
        }
        try {
            $userSessionData = UserSessionData::factory($token_info);
            // 判断是否过期
            if ($userSessionData->getExpireTime() <= time()) {
                $this->deleteSession($hashTokenData);
            }
            // 如果 Token 的寿命小于ttl的一半了  给 Token 续命
            if (($userSessionData->getExpireTime() - time()) < $this->ttl / 2) {
                $userSessionData->updateExpireTime(time() + $this->ttl);
            }
            // 刷新 Token 活跃时间
            $userSessionData->updateActiveTime();
            // 刷新IP地址
            $userSessionData->updateActiveIP(Utils::ip($this->request));
            $this->userSessionData = $userSessionData;
            $this->redis->hSet($hash_key, $hashTokenData->getSessionId(), json_encode($userSessionData->toArray()));
            // 给 Token 列表续命
            $this->redis->expire($hash_key, $this->ttl);

            // 获取用户模型
            $this->setUserModel($this->queryUserModel($userSessionData->getHashToken()->getIdentifierInfo()));
            $this->isLogin = true;
            return;
        } catch (UserSessionDataCreateException $e) {
            // 出现异常删除session
            $this->deleteSession($hashTokenData);
        }
        $this->isLogin = false;
    }

    /**
     * 解密token.
     * @throws UnauthorizedException
     */
    private function decodeToken(): void
    {
        // 解密token
        $token = $this->tokenProvider->decode($this->getOriginToken());
        if (! $token) {
            $this->isLogin = false;
            return;
        }
        $this->hashTokenData = $token;
    }

    /**
     * 获取存储用户会话的哈希表名称.
     * @param IdentifierInfo $identifierInfo
     * @return string
     */
    private function getUserSessionsHashKey(IdentifierInfo $identifierInfo): string
    {
        return 'login:auth:' . $this->guardName . ':' . $identifierInfo->getValue();
    }

    /**
     * 根据用户模型获取会话的哈希表名称.
     * @param AuthenticatableInterface $user
     * @return string
     */
    private function getUserSessionsHashKeyByUser(AuthenticatableInterface $user): string
    {
        return 'login:auth:' . $this->guardName . ':' . $user[$user->getAuthIdentifierName()];
    }
}
