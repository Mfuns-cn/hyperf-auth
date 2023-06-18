# mfuns-cn/hyperf-auth

Hyperf Auth Guard Component.

### 安装
```shell
composer require mfuns-cn/hyperf-auth dev-master
```

### 发布配置
```shell
php bin/hyperf.php vendor:publish mfuns-cn/hyperf-auth
```

### 实例
用户模型
````php
<?php

declare(strict_types=1);

namespace App\Model;

use Hyperf\DbConnection\Model\Model;
use Hyperf\ModelCache\Cacheable;
use Hyperf\Tappable\HigherOrderTapProxy;
use Mfuns\HyperfAuth\Contracts\AuthenticatableInterface;
use Mfuns\HyperfAuth\Contracts\IdentifierInfo;

class UserModel extends Model implements AuthenticatableInterface
{
    use Cacheable;

    protected ?string $table = 'users';
    
    protected array $fillable = [];
    protected array $casts = [];

    protected array $hidden = ['password'];

    public function getUserModel(IdentifierInfo $identifierInfo): \Hyperf\Database\Model\Model|AuthenticatableInterface
    {
        if ($identifierInfo->getName() === $this->getAuthIdentifierName()) {
            return self::find($identifierInfo->getValue());
        }
        return self::query()->where($identifierInfo->getName(), $identifierInfo->getValue())->first();
    }

    public function getUserModelFormCache(IdentifierInfo $identifierInfo): \Hyperf\Database\Model\Model|AuthenticatableInterface
    {
        return self::findFromCache($identifierInfo->getValue());
    }

    public function getAuthIdentifierName(): string
    {
        return 'id';
    }
}
````
中间件
```php
<?php

declare(strict_types=1);

namespace App\Middleware;

use Mfuns\HyperfAuth\Middlewares\AbstractAuthMiddleware;
use Psr\Http\Message\ResponseInterface as PsrResponseInterface;
class AuthMiddleware extends AbstractAuthMiddleware
{
    protected ?string $guard_name = 'web';

    protected function fail(string $reason = 'unauthorized'): PsrResponseInterface
    {
        // 自定义返回错误提示
        return $this->response->json([
            'code' => 1,
            'msg' => $reason,
        ])->withStatus(401);
    }
}
```
异常处理
```php
<?php

declare(strict_types=1);

namespace App\Exception\Handler;

use Hyperf\Context\ApplicationContext;
use Hyperf\ExceptionHandler\ExceptionHandler;
use Mfuns\HyperfAuth\Exceptions\TokenDecodeException;
use Mfuns\HyperfAuth\Exceptions\UnauthorizedException;
use Mfuns\HyperfAuth\Exceptions\UserSessionDataCreateException;
use Psr\Http\Message\ResponseInterface;
use Throwable;

class AuthExceptionHandler extends ExceptionHandler
{
    public function handle(Throwable $throwable, ResponseInterface $response): ResponseInterface
    {
        $this->stopPropagation();
        // ep logger ...
        return ApplicationContext::getContainer()->get(\Hyperf\HttpServer\Contract\ResponseInterface::class)->json([
            'code' => 1,
            'message' => $throwable->getMessage(),
            'data' => [],
        ]);
    }

    public function isValid(Throwable $throwable): bool
    {
        return $throwable instanceof TokenDecodeException || $throwable instanceof UnauthorizedException || $throwable instanceof UserSessionDataCreateException;
    }
}
```
身份验证服务
```php
<?php

declare(strict_types=1);

namespace App\Service;

use App\Constant\ServiceResponse;
use App\Model\UserModel;
use Hyperf\Di\Annotation\Inject;
use Mfuns\HyperfAuth\AuthManager;
use Mfuns\HyperfAuth\Contracts\GuardInterface;

class AuthService
{
    #[Inject]
    protected AuthManager $authManager;

    public function getAuthManage(): GuardInterface
    {
        return $this->authManager->guard('web');
    }

    public function userLogin(string $account, string $password): ServiceResponse
    {
        .....
        /** @var UserModel $user */
        $this->getAuthManage()->login($user);
        .....
    }

    public function userRegister(string $phone, string $name, string $password)
    {
        // .....
    }

    public function check(): bool
    {
        return $this->getAuthManage()->check();
    }
}
```
身份守卫接口 `Mfuns\HyperfAuth\Contracts\GuardInterface`
```php
interface GuardInterface
{
    /**
     * 获取 guard name.
     * @return string
     */
    public function getGuardName(): string;

    /**
     * 获取 Options.
     * @return array
     */
    public function getOptions(): array;

    /**
     * 判断是否已登陆.
     * @return bool
     */
    public function check(): bool;

    /**
     * 返回用户模型.
     * @return null|AuthenticatableInterface
     */
    public function user(): ?AuthenticatableInterface;

    /**
     * 返回用户识别ID.
     * @return mixed
     */
    public function id(): mixed;

    /**
     * 验证用户身份.
     * @param array $credentials
     * @return bool
     */
    public function validate(array $credentials = []): bool;

    /**
     * 设置用户.
     * @param $user
     * @return $this
     */
    public function setUserModel($user): AuthenticatableInterface|Model|null;

    /**
     * 获取有效会话数据集合.
     * @param null|AuthenticatableInterface $user 获取指定用户的会话
     * @return array
     */
    public function getValidSessionDataList(?AuthenticatableInterface $user = null): array;

    /**
     * 获取当前会话的信息.
     * @return mixed
     */
    public function getCurrentSessionData(): UserSessionData;

    /**
     * 更新当前回话的信息.
     */
    public function updateCurrentTokenData(): void;

    /**
     * 为用户授权登录.
     * @param AuthenticatableInterface $user
     * @param bool $remember
     * @return mixed
     */
    public function login(AuthenticatableInterface $user, bool $remember = false): mixed;

    /**
     * 登出当前会话.
     */
    public function logout(?HashTokenData $hashTokenData): void;

    /**
     * 登出用户的所有会话.
     * @param null|AuthenticatableInterface $user 登出指定用户的会话
     */
    public function logoutAll(?AuthenticatableInterface $user = null): void;
}
```