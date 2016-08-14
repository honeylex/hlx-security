<?php

namespace Hlx\Security\Service;

use Hlx\Security\User\Projection\Standard\User;
use Honeybee\Infrastructure\Config\ConfigInterface;
use Honeybee\Infrastructure\DataAccess\Finder\FinderMap;
use Honeybee\Infrastructure\DataAccess\Query\AttributeCriteria;
use Honeybee\Infrastructure\DataAccess\Query\Comparison\Equals;
use Honeybee\Infrastructure\DataAccess\Query\CriteriaList;
use Honeybee\Infrastructure\DataAccess\Query\CriteriaQuery;
use Honeybee\Infrastructure\DataAccess\Query\QueryServiceMap;
use Honeybee\Infrastructure\Security\Auth\AuthResponse;
use Honeybee\Infrastructure\Security\Auth\AuthServiceInterface;
use Honeybee\Infrastructure\Security\Auth\CryptedPasswordHandler;

class AuthenticationService implements AuthServiceInterface
{
    const TYPE_KEY = 'hlx.security.standard';

    protected $config;

    protected $queryServiceMap;

    protected $finderMap;

    protected $passwordHandler;

    public function __construct(
        ConfigInterface $config,
        QueryServiceMap $queryServiceMap,
        FinderMap $finderMap,
        CryptedPasswordHandler $passwordHandler
    ) {
        $this->config = $config;
        $this->queryServiceMap = $queryServiceMap;
        $this->finderMap = $finderMap;
        $this->passwordHandler = $passwordHandler;
    }

    public function getTypeKey()
    {
        return static::TYPE_KEY;
    }

    public function findByIdentifier($identifier)
    {
        $results = $this->getFinder()->getByIdentifier($identifier);
        return $results->getFirstResult();
    }

    public function findByUsername($username)
    {
        $queryResult = $this->getProjectionQueryService()->find(
            new CriteriaQuery(
                new CriteriaList,
                new CriteriaList([ new AttributeCriteria('username', new Equals($username)) ]),
                new CriteriaList,
                0,
                1
            )
        );

        $user = null;
        if (1 === $queryResult->getTotalCount()) {
            $user = $queryResult->getFirstResult();
        }

        return $user;
    }

    // @note could match multiple users since type filter is not applied
    public function findByToken($token, $type)
    {
        $queryResult = $this->getProjectionQueryService()->find(
            new CriteriaQuery(
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
        if (1 === $queryResult->getTotalCount()) {
            $user = $queryResult->getFirstResult();
        }

        return $user;
    }

    public function findByEmail($email)
    {
        $queryResult = $this->getProjectionQueryService()->find(
            new CriteriaQuery(
                new CriteriaList,
                new CriteriaList([ new AttributeCriteria('email', new Equals($email)) ]),
                new CriteriaList,
                0,
                1
            )
        );

        $user = null;
        if (1 === $queryResult->getTotalCount()) {
            $user = $queryResult->getFirstResult();
        }

        return $user;
    }

    public function findAllByUsernameOrEmail($username, $email, array $ignoreIds = [])
    {
        $filterCriteriaList = new CriteriaList([
            new CriteriaList(
                [
                    new AttributeCriteria('username', new Equals($username)),
                    new AttributeCriteria('email', new Equals($email))
                ],
                CriteriaList::OP_OR
            )
        ]);

        if (!empty($ignoreIds)) {
            $filterCriteriaList->addItem(new AttributeCriteria('_id', new Equals($ignoreIds, true)));
        }

        return $this->getProjectionQueryService()->find(
            new CriteriaQuery(
                new CriteriaList,
                $filterCriteriaList,
                new CriteriaList,
                0,
                1000
            )
        );
    }

    public function authenticate($username, $password, $options = [])
    {
        // not currently implemented since the registered SecurityProvider
        // proxies user look up and password verification through the UserService
    }

    public function verifyPassword($password, $passwordHash)
    {
        return $this->passwordHandler->verify($password, $passwordHash);
    }

    public function encodePassword($password)
    {
        return $this->passwordHandler->hash($password);
    }

    protected function getFinder()
    {
        $finderKey = $this->config->get(
            'finder',
            'hlx.security.user::projection.standard::view_store::finder'
        );
        return $this->finderMap->getItem($finderKey);
    }

    protected function getProjectionQueryService()
    {
        $queryServiceKey = $this->config->get(
            'query_service',
            'hlx.security.user::projection.standard::query_service'
        );
        return $this->queryServiceMap->getItem($queryServiceKey);
    }
}
