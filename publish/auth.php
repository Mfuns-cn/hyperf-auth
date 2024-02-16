<?php

declare(strict_types=1);

/**
 * This file is part of mfuns/hyperf-auth.
 *
 * @link     https://www.mfuns.cn
 * @author   ChenDoXiu<chendoxiu@gmail.com>,LixWorth<lixworth@outlook.com>
 * @license  https://github.com/mfuns-cn/hyperf-auth/blob/master/LICENSE
 */

use Mfuns\HyperfAuth\Guards\StatefulGuard;
use Mfuns\HyperfAuth\Handler\HathTokenHandler;
use Mfuns\Test\HyperfAuth\Model\UserModel;

return [
    /*
     * 默认 auth guard.
     * \Mfuns\HyperfAuth\auth(null);
     */

    'defaults' => [
        'guard' => 'api',
    ],

    /*
     * Guard list.
     * 调用方法: \Mfuns\HyperfAuth\auth($name);
     *
     * guard_name => [] guard info.
     * guard info 包含 必填项目 driver,model,provider,options
     * - driver 为 auth 处理驱动
     * - model 为 用户模型 需实现 \Mfuns\HyperfAuth\Contracts\AuthenticatableInterface 接口
     * - token_provider 对应下方 token_provider，负责 token 的验证加密解密
     * - options 配置选项
     *  - redis_conn_name redis线程池名称，若为空则使用 default，根据 driver 的不同可能会使用该 redis 存储一些身份状态信息
     *  - auth_methods 可选参数 cookie header query 数组 影响 guard->check 的处理方式
     *  - ttl 有效期 处理方式由 driver 决定
     *  - model_cache 是否使用模型缓存 默认false (前提是使用 Cacheable trait)
     */

    'guards' => [
        'api' => [
            'driver' => StatefulGuard::class,
            'model' => UserModel::class,
            'token_provider' => 'hash_token',
            'options' => [
                'redis_conn_name' => 'default', // redis pool name
                'auth_methods' => ['cookie', 'header'], // 支持的验证方式
                'cookie_name' => 'AuthToken', // auth cookie name
                'ttl' => \Hyperf\Support\env('TOKEN_TTL', 3600), // token expire
                'model_cache' => true,
            ],
        ],
        'lighting' => [
            'driver' => StatefulGuard::class,
            'model' => UserModel::class,
            'token_provider' => 'hash_token',
            'options' => [
                'redis_conn_name' => 'default', // redis pool name
                'auth_methods' => ['header'], // 支持的验证方式
                'cookie_name' => 'Lighting_Token', // auth cookie name
                'ttl' => \Hyperf\Support\env('TOKEN_TTL', 3600), // token expire
            ],
        ],
        'session_only' => [ // auth_methods 只为 session 的时候 login 和 logout 方法才会托管 set 与 del session 工作
            'driver' => StatefulGuard::class,
            'model' => UserModel::class,
            'token_provider' => 'token2',
            'options' => [
                'redis_conn_name' => 'default', // redis pool name
                'auth_methods' => ['session'], // 支持的验证方式
                'ttl' => \Hyperf\Support\env('TOKEN_TTL', 3600), // token expire
            ],
        ],
    ],

    /*
     * Token 处理形式.
     * 建议保证每个 guard 单独对应一个 handlers，并且其中 secret 不相同，如此可避免生产与开发不同环境中不会出现滥用行为，
     */
    'token_provider' => [
        'hash_token' => [
            'driver' => HathTokenHandler::class,
            'options' => [
                'secret' => \Hyperf\Support\env('APP_GUARD_SECRET', base64_encode(\Hyperf\Support\env('APP_NAME'))), // token secret
            ],
        ],
        'token2' => [
            'driver' => HathTokenHandler::class,
            'options' => [
                'secret' => \Hyperf\Support\env('APP_GUARD_SECRET', base64_encode(md5(\Hyperf\Support\env('APP_NAME')))), // token secret
            ],
        ],
    ],
];
