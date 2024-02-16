<?php

declare(strict_types=1);

/**
 * This file is part of mfuns/hyperf-auth.
 *
 * @link     https://www.mfuns.cn
 * @author   ChenDoXiu<chendoxiu@gmail.com>,LixWorth<lixworth@outlook.com>
 * @license  https://github.com/mfuns-cn/hyperf-auth/blob/master/LICENSE
 */

namespace Mfuns\HyperfAuth\Contracts;

use Hyperf\Database\Model\Model;
use Mfuns\HyperfAuth\Contracts\Guard\UserSessionData;

/**
 * 身份验证门卫接口.
 */
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
    public function setUserModel($user): null|AuthenticatableInterface|Model;

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

    //    /**
    //     * 用已给凭据尝试登陆.
    //     * @param array $credentials
    //     * @param bool $remember
    //     * @return mixed
    //     */
    //    public function attempt(array $credentials = [], bool $remember = false): mixed;

    /**
     * 为用户授权登录.
     * @param AuthenticatableInterface $user
     * @param bool $remember
     * @return mixed
     */
    public function login(AuthenticatableInterface $user, bool $remember = false): mixed;
    //
    //    /**
    //     * 授权用户ID登录会话.
    //     * @param $id
    //     * @param bool $remember
    //     * @return mixed
    //     */
    //    public function loginUsingId($id, bool $remember = false): mixed;

    //    /**
    //     * 判断用户是否勾选记住我选项.
    //     * @return bool
    //     */
    //    public function viaRemember(): bool;

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
