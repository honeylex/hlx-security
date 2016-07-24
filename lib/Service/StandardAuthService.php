<?php

namespace Hlx\Security\Service;

use Honeybee\Infrastructure\Config\ConfigInterface;
use Honeybee\Infrastructure\DataAccess\Query\AttributeCriteria;
use Honeybee\Infrastructure\DataAccess\Query\Comparison\Equals;
use Honeybee\Infrastructure\DataAccess\Query\CriteriaList;
use Honeybee\Infrastructure\DataAccess\Query\Query;
use Honeybee\Infrastructure\DataAccess\Query\QueryServiceMap;
use Honeybee\Infrastructure\Security\Auth\AuthResponse;
use Honeybee\Infrastructure\Security\Auth\AuthServiceInterface;
use Honeybee\Infrastructure\Security\Auth\CryptedPasswordHandler;

class StandardAuthService implements AuthServiceInterface
{
    const TYPE_KEY = 'hlx.security.standard';

    protected $config;

    protected $query_service_map;

    protected $password_handler;

    public function __construct(
        ConfigInterface $config,
        QueryServiceMap $query_service_map,
        CryptedPasswordHandler $password_handler
    ) {
        $this->config = $config;
        $this->query_service_map = $query_service_map;
        $this->password_handler = $password_handler;
    }

    public function getTypeKey()
    {
        return static::TYPE_KEY;
    }

    public function findByUsername($username)
    {
        $query_result = $this->getProjectionQueryService()->find(
            new Query(
                new CriteriaList,
                new CriteriaList([ new AttributeCriteria('username', new Equals($username)) ]),
                new CriteriaList,
                0,
                1
            )
        );

        $user = null;
        if (1 === $query_result->getTotalCount()) {
            $user = $query_result->getFirstResult();
        }

        return $user;
    }

    // @todo nested query
    public function findByToken($token, $type)
    {
        $query_result = $this->getProjectionQueryService()->find(
            new Query(
                new CriteriaList,
                new CriteriaList([
                    new AttributeCriteria('tokens.token', new Equals($token)),
                ]),
                new CriteriaList,
                0,
                1
            )
        );

        $user = null;
        if (1 === $query_result->getTotalCount()) {
            $user = $query_result->getFirstResult();
        }

        return $user;
    }

    public function authenticate($username, $password, $options = [])
    {
        // not currently implemented since the registered SecurityProvider
        // proxies user look up and password verification through the UserService
    }

    public function verifyPassword($password, $password_hash)
    {
        return $this->password_handler->verify($password, $password_hash);
    }

    public function encodePassword($password)
    {
        return $this->password_handler->hash($password);
    }

    protected function getProjectionQueryService()
    {
        $query_service_key = $this->config->get(
            'query_service',
            'hlx.security.user::projection.standard::query_service'
        );
        return $this->query_service_map->getItem($query_service_key);
    }
}
